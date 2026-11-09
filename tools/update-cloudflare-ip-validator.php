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

function indentLines(string $text, string $indent): string
{
    return $indent . str_replace("\n", "\n{$indent}", $text);
}

/**
 * @param array<int, string> $conditions
 */
function buildReturn(array $conditions, string $indent): string
{
    $text = 'return ' . $conditions[0];
    for ($i = 1, $n = count($conditions); $i < $n; $i++) {
        $text .= "\n    || " . $conditions[$i];
    }
    // Own line: a trailing "//" comment would swallow an inline semicolon.
    $text .= "\n;";

    return indentLines($text, $indent);
}

/**
 * @param array<int, string> $conditions
 */
function buildIfReturnTrue(array $conditions, string $indent): string
{
    $text = 'if (' . $conditions[0];
    for ($i = 1, $n = count($conditions); $i < $n; $i++) {
        $text .= "\n    || " . $conditions[$i];
    }
    $text .= "\n) {\n    return true;\n}";

    return indentLines($text, $indent);
}

/**
 * Merges overlapping and adjacent CIDRs and buckets the result by first octet,
 * so the generated checks only run for addresses that share a first octet with
 * at least one Cloudflare range.
 *
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
function buildIpv4Condition(array $ranges, string $indent): string
{
    if ($ranges === []) {
        return $indent . 'return false;';
    }

    foreach ($ranges as $range) {
        if ($range['start'] === 0 && $range['end'] === 0xFFFFFFFF) {
            return $indent . 'return true;';
        }
    }

    /** @var array<int, array<int, array{start:int,end:int,labels:array<int,string>}>> $buckets */
    $buckets = [];
    foreach ($ranges as $range) {
        $firstOctet = $range['start'] >> 24;
        $lastOctet = $range['end'] >> 24;
        for ($octet = $firstOctet; $octet <= $lastOctet; $octet++) {
            $buckets[$octet][] = $range;
        }
    }
    ksort($buckets);

    $inner = $indent . '    ';
    $lines = [$indent . 'switch (($ipLong >> 24) & 0xFF) {'];
    foreach ($buckets as $octet => $octetRanges) {
        $lines[] = $inner . 'case ' . $octet . ':';
        $octetStart = $octet << 24;
        $octetEnd = $octetStart | 0xFFFFFF;

        $coversOctet = false;
        foreach ($octetRanges as $range) {
            if ($range['start'] <= $octetStart && $range['end'] >= $octetEnd) {
                $coversOctet = true;
                break;
            }
        }

        if ($coversOctet) {
            $lines[] = $inner . '    return true;';
            continue;
        }

        $conditions = [];
        foreach ($octetRanges as $range) {
            $conditions[] = '($ipLong >= ' . $range['start'] . ' && $ipLong <= ' . $range['end'] . ') // '
                . implode(', ', $range['labels']);
        }
        $lines[] = buildReturn($conditions, $inner . '    ');
    }
    $lines[] = $inner . 'default:';
    $lines[] = $inner . '    return false;';
    $lines[] = $indent . '}';

    return implode("\n", $lines);
}

function buildIpv6Expression(string $packed, int $prefix): string
{
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

    if ($parts === []) {
        return 'true';
    }

    return '(' . implode(' && ', $parts) . ')';
}

/**
 * Buckets IPv6 CIDRs by first byte so addresses that cannot be Cloudflare are
 * rejected without running any prefix checks.
 *
 * @param array<int, string> $cidrs
 */
function buildIpv6Condition(array $cidrs, string $indent): string
{
    if ($cidrs === []) {
        return $indent . 'return false;';
    }

    /** @var array<int, string> $wideChecks prefixes shorter than 8 bits */
    $wideChecks = [];
    /** @var array<string, array<int, string>> $buckets */
    $buckets = [];

    foreach ($cidrs as $cidr) {
        [$base, $prefixRaw] = explode('/', $cidr, 2);
        $prefix = parseCidrPrefix($cidr, $prefixRaw, 128);
        $packed = inet_pton($base);
        if ($packed === false || strlen($packed) !== 16) {
            throw new RuntimeException("Invalid IPv6 CIDR base: {$cidr}");
        }

        if ($prefix === 0) {
            return $indent . 'return true;';
        }

        $expression = buildIpv6Expression($packed, $prefix);

        if ($prefix < 8) {
            $wideChecks[] = $expression . ' // ' . $cidr;
            continue;
        }

        // A /8 covers the whole first-byte bucket it is placed in.
        $buckets[$packed[0]][] = $prefix === 8
            ? 'true // ' . $cidr
            : $expression . ' // ' . $cidr;
    }

    ksort($buckets);

    $inner = $indent . '    ';
    $lines = [];
    if ($wideChecks !== []) {
        $lines[] = buildIfReturnTrue($wideChecks, $indent);
        $lines[] = '';
    }
    $lines[] = $indent . 'switch ($packed[0]) {';
    foreach ($buckets as $firstByte => $checks) {
        $lines[] = $inner . 'case ' . bytesToPhpString($firstByte) . ':';
        $lines[] = buildReturn($checks, $inner . '    ');
    }
    $lines[] = $inner . 'default:';
    $lines[] = $inner . '    return false;';
    $lines[] = $indent . '}';

    return implode("\n", $lines);
}

function main(array $argv): void
{
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

    $force = in_array('--force', $argv ?? [], true);
    $existing = is_file($target) ? (string) file_get_contents($target) : '';
    if (!$force && $etag !== '' && str_contains($existing, 'CLOUDFLARE_ETAG = ' . var_export($etag, true))) {
        echo "No changes: etag={$etag}\n";
        exit(0);
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
            \$ipLong = \\ip2long(\$ip);
            if (\$ipLong !== false) {
    {{IPV4_CONDITION}}
            }

            \$packed = \\inet_pton(\$ip);
            if (\$packed === false || \\strlen(\$packed) !== 16) {
                return false;
            }

    {{IPV6_CONDITION}}
        }
    }
    PHPFILE;

    $ipv4Ranges = buildIpv4Ranges($ipv4Cidrs);
    $output = strtr($template, [
        '{{IPV4_CONDITION}}' => buildIpv4Condition($ipv4Ranges, str_repeat(' ', 12)),
        '{{IPV6_CONDITION}}' => buildIpv6Condition($ipv6Cidrs, str_repeat(' ', 8)),
        '{{generatedAt}}' => var_export($generatedAt, true),
        '{{etag}}' => var_export($etag, true),
    ]);

    file_put_contents($target, $output . PHP_EOL);
    echo "Updated {$target}\n";
    echo "etag={$etag}\n";
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    main($argv);
}
