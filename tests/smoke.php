<?php
declare(strict_types=1);

require __DIR__ . '/../src/CloudflareIpValidator.php';

use Divinity76\CloudflareIpValidator\CloudflareIpValidator;

/**
 * @param mixed $expected
 * @param mixed $actual
 */
function assertSame($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(
            STDERR,
            "Assertion failed: {$message}\nExpected: " . var_export($expected, true)
            . "\nActual: " . var_export($actual, true) . "\n"
        );
        exit(1);
    }
}

assertSame(true, CloudflareIpValidator::isCloudflareIp('173.245.48.1'), 'Known Cloudflare IPv4 should pass');
assertSame(false, CloudflareIpValidator::isCloudflareIp('8.8.8.8'), 'Non-Cloudflare IPv4 should fail');
assertSame(true, CloudflareIpValidator::isCloudflareIp('2606:4700::1111'), 'Known Cloudflare IPv6 should pass');
assertSame(false, CloudflareIpValidator::isCloudflareIp('2001:4860:4860::8888'), 'Non-Cloudflare IPv6 should fail');
assertSame(false, CloudflareIpValidator::isCloudflareIp('not-an-ip'), 'Invalid input should fail');

fwrite(STDOUT, "All smoke tests passed.\n");
