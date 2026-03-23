<?php
declare(strict_types=1);

error_reporting(E_ALL);
set_error_handler(static function (int $errno, string $errstr, string $errfile, int $errline): bool {
    if (error_reporting() & $errno) {
        throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
    }

    return true;
});

function bytesToPhpString(string $bytes): string
{
    $escaped = '';
    $len = strlen($bytes);
    for ($i = 0; $i < $len; $i++) {
        $escaped .= "\\x" . bin2hex($bytes[$i]);
    }

    return '"' . $escaped . '"';
}

function parseCidrPrefix(string $cidr, string $prefixRaw, int $maxBits): int
{
    if ($prefixRaw === '' || preg_match('/^\d+$/', $prefixRaw) !== 1) {
        throw new RuntimeException("Invalid CIDR prefix in {$cidr}");
    }

    $prefix = (int) $prefixRaw;
    if ($prefix < 0 || $prefix > $maxBits) {
        throw new RuntimeException("CIDR prefix out of range in {$cidr}");
    }

    return $prefix;
}

/**
 * @param array<int, string> $cidrs
 * @return array<int, array{start:int,end:int,labels:array<int,string>}>
 */
function buildIpv4Ranges(array $cidrs): array
{
    $ranges = [];
    foreach ($cidrs as $cidr) {
        [$base, $prefixRaw] = explode('/', $cidr, 2);
        $prefix = parseCidrPrefix($cidr, $prefixRaw, 32);
        $packed = inet_pton($base);
        if ($packed === false || strlen($packed) !== 4) {
            throw new RuntimeException("Invalid IPv4 CIDR base: {$cidr}");
        }

        $baseInt = unpack('N', $packed)[1];
        $mask = $prefix === 0 ? 0 : ((~((1 << (32 - $prefix)) - 1)) & 0xFFFFFFFF);
        $start = $baseInt & $mask;
        $end = $start | (~$mask & 0xFFFFFFFF);
        $ranges[] = [
            'start' => $start,
            'end' => $end,
            'labels' => [$cidr],
        ];
    }

    usort($ranges, static fn(array $a, array $b): int => $a['start'] <=> $b['start']);

    $merged = [];
    foreach ($ranges as $range) {
        $start = $range['start'];
        $end = $range['end'];

        if ($merged === []) {
            $merged[] = $range;
            continue;
        }

        $lastIdx = count($merged) - 1;
        $lastEnd = $merged[$lastIdx]['end'];
        if ($start <= ($lastEnd + 1)) {
            if ($end > $lastEnd) {
                $merged[$lastIdx]['end'] = $end;
            }
            $merged[$lastIdx]['labels'] = array_values(
                array_unique(array_merge($merged[$lastIdx]['labels'], $range['labels']))
            );
            continue;
        }

        $merged[] = $range;
    }

    return $merged;
}

/**
 * @param array<int, array{start:int,end:int,labels:array<int,string>}> $ranges
 */
function buildIpv4Condition(array $ranges): string
{
    if ($ranges === []) {
        return 'false';
    }

    $lines = [];
    foreach ($ranges as $idx => $range) {
        $start = $range['start'];
        $end = $range['end'];
        $labels = implode(', ', $range['labels']);
        $op = $idx === 0 ? '' : '|| ';
        $lines[] = "{$op}(\$ipLong >= {$start} && \$ipLong <= {$end}) // {$labels}";
    }

    return implode("\n                ", $lines);
}

/**
 * @param array<int, string> $cidrs
 */
function buildIpv6Condition(array $cidrs): string
{
    if ($cidrs === []) {
        return 'false';
    }

    $checks = [];
    foreach ($cidrs as $idx => $cidr) {
        [$base, $prefixRaw] = explode('/', $cidr, 2);
        $prefix = parseCidrPrefix($cidr, $prefixRaw, 128);
        $packed = inet_pton($base);
        if ($packed === false || strlen($packed) !== 16) {
            throw new RuntimeException("Invalid IPv6 CIDR base: {$cidr}");
        }

        $fullBytes = intdiv($prefix, 8);
        $remainingBits = $prefix % 8;
        $parts = [];

        if ($fullBytes > 0) {
            $parts[] = '\\str_starts_with($packed, ' . bytesToPhpString(substr($packed, 0, $fullBytes)) . ')';
        }

        if ($remainingBits > 0) {
            $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
            $expected = ord($packed[$fullBytes]) & $mask;
            $parts[] = "(\\ord(\$packed[{$fullBytes}]) & {$mask}) === {$expected}";
        }

        $expr = $parts === [] ? 'true' : '(' . implode(' && ', $parts) . ')';
        $op = $idx === 0 ? '' : '|| ';
        $checks[] = "{$op}{$expr} // {$cidr}";
    }

    return implode("\n                ", $checks);
}

$root = dirname(__DIR__);
$target = $root . '/src/CloudflareIpValidator.php';

$raw = file_get_contents('https://api.cloudflare.com/client/v4/ips');
if ($raw === false) {
    throw new RuntimeException('Unable to fetch Cloudflare IP list.');
}

$data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
$ipv4Cidrs = $data['result']['ipv4_cidrs'] ?? null;
$ipv6Cidrs = $data['result']['ipv6_cidrs'] ?? null;
$etag = (string) ($data['result']['etag'] ?? '');

if (!is_array($ipv4Cidrs) || !is_array($ipv6Cidrs)) {
    throw new RuntimeException('Unexpected Cloudflare API response format.');
}

$generatedAt = gmdate('Y-m-d');
$template = <<<PHPFILE
<?php
declare(strict_types=1);

namespace Divinity76\\CloudflareIpValidator;

// Maintainer note: Do not edit this file directly.
// Any manual changes will be overwritten by tools/update-cloudflare-ip-validator.php.
final class CloudflareIpValidator
{
    public const GENERATED_AT_UTC = {{generatedAt}};
    public const CLOUDFLARE_ETAG = {{etag}};

    public static function isCloudflareIp(string \$ip): bool
    {
        \$packed = \\inet_pton(\$ip);
        if (\$packed === false) {
            return false;
        }

        \$packedLen = \\strlen(\$packed);
        if (\$packedLen === 4) {
            \$ipLong = \\unpack('N', \$packed)[1];
            return
                {{IPV4_CONDITION}}
                ;
        }

        if (\$packedLen === 16) {
            return
                {{IPV6_CONDITION}}
                ;
        }

        return false;
    }
}
PHPFILE;

$ipv4Ranges = buildIpv4Ranges($ipv4Cidrs);
$output = strtr($template, [
    '{{IPV4_CONDITION}}' => buildIpv4Condition($ipv4Ranges),
    '{{IPV6_CONDITION}}' => buildIpv6Condition($ipv6Cidrs),
    '{{generatedAt}}' => var_export($generatedAt, true),
    '{{etag}}' => var_export($etag, true),
]);

file_put_contents($target, $output . PHP_EOL);
echo "Updated {$target}\n";
echo "etag={$etag}\n";
