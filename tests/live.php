<?php
declare(strict_types=1);

require __DIR__ . '/../src/CloudflareIpValidator.php';

use Divinity76\CloudflareIpValidator\CloudflareIpValidator;

function fail(string $message): void
{
    fwrite(STDERR, "Live range check failed: {$message}\n");
    exit(1);
}

/**
 * @return array{0:string,1:string} packed first and last address of the CIDR
 */
function cidrBounds(string $cidr): array
{
    [$base, $prefixRaw] = explode('/', $cidr, 2);
    $prefix = (int) $prefixRaw;
    $packed = inet_pton($base);
    if ($packed === false) {
        fail("invalid CIDR base: {$cidr}");
    }

    $start = $packed;
    $end = $packed;
    for ($i = 0, $len = strlen($packed); $i < $len; $i++) {
        $bits = max(0, min(8, $prefix - $i * 8));
        $mask = $bits === 0 ? 0 : ((0xFF << (8 - $bits)) & 0xFF);
        $start[$i] = chr(ord($start[$i]) & $mask);
        $end[$i] = chr(ord($end[$i]) | (~$mask & 0xFF));
    }

    return [$start, $end];
}

/**
 * Adds -1 or +1 to a big-endian packed address, null on overflow/underflow.
 */
function shiftPacked(string $packed, int $delta): ?string
{
    for ($i = strlen($packed) - 1; $i >= 0; $i--) {
        $byte = ord($packed[$i]);
        if ($delta === 1) {
            if ($byte !== 0xFF) {
                $packed[$i] = chr($byte + 1);
                return $packed;
            }
            $packed[$i] = "\x00";
        } else {
            if ($byte !== 0x00) {
                $packed[$i] = chr($byte - 1);
                return $packed;
            }
            $packed[$i] = "\xFF";
        }
    }

    return null;
}

/**
 * Independent reference matcher.
 *
 * @param array<int, string> $cidrs
 */
function matchesCidrs(string $packed, array $cidrs): bool
{
    foreach ($cidrs as $cidr) {
        [$base, $prefixRaw] = explode('/', $cidr, 2);
        $prefix = (int) $prefixRaw;
        $basePacked = inet_pton($base);
        $ok = true;
        for ($i = 0, $len = strlen($packed); $i < $len; $i++) {
            $bits = $prefix - $i * 8;
            if ($bits <= 0) {
                break;
            }
            $bits = min(8, $bits);
            $mask = (0xFF << (8 - $bits)) & 0xFF;
            if ((ord($packed[$i]) & $mask) !== (ord($basePacked[$i]) & $mask)) {
                $ok = false;
                break;
            }
        }
        if ($ok) {
            return true;
        }
    }

    return false;
}

$raw = file_get_contents('https://api.cloudflare.com/client/v4/ips');
if ($raw === false) {
    fail('unable to fetch Cloudflare IP list');
}

$data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
$ipv4 = $data['result']['ipv4_cidrs'] ?? null;
$ipv6 = $data['result']['ipv6_cidrs'] ?? null;
if (!is_array($ipv4) || !is_array($ipv6)) {
    fail('unexpected Cloudflare API response');
}

$etag = (string) ($data['result']['etag'] ?? '');
if ($etag !== '' && CloudflareIpValidator::CLOUDFLARE_ETAG !== $etag) {
    fail('ETag mismatch: class=' . CloudflareIpValidator::CLOUDFLARE_ETAG . " api={$etag}");
}

foreach (['not-an-ip', '', '999.1.1.1'] as $invalid) {
    if (CloudflareIpValidator::isCloudflareIp($invalid) !== false) {
        fail('invalid input accepted: ' . var_export($invalid, true));
    }
}

$candidates = [];
foreach (array_merge($ipv4, $ipv6) as $cidr) {
    [$start, $end] = cidrBounds($cidr);
    $candidates[] = $start;
    $candidates[] = $end;

    $below = shiftPacked($start, -1);
    if ($below !== null) {
        $candidates[] = $below;
    }
    $above = shiftPacked($end, 1);
    if ($above !== null) {
        $candidates[] = $above;
    }
}

$checked = 0;
foreach ($candidates as $packed) {
    $ip = inet_ntop($packed);
    $want = matchesCidrs($packed, strlen($packed) === 4 ? $ipv4 : $ipv6);
    $got = CloudflareIpValidator::isCloudflareIp($ip);
    if ($got !== $want) {
        fail("{$ip}: expected " . var_export($want, true) . ', got ' . var_export($got, true));
    }
    $checked++;
}

printf(
    "Live range check passed: %d IPv4 / %d IPv6 CIDRs, %d boundary addresses.\n",
    count($ipv4),
    count($ipv6),
    $checked
);
