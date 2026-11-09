# Maintainers

## Updating Cloudflare Ranges

```bash
php tools/update-cloudflare-ip-validator.php
```

This regenerates `src/CloudflareIpValidator.php` from Cloudflare's official IP API.
It exits without writing when the API ETag matches the checked-in `CLOUDFLARE_ETAG`;
pass `--force` to regenerate anyway.

The generated checks switch on the first IPv4 octet / first IPv6 byte, so the hot
path rejects addresses outside Cloudflare's blocks with a single lookup.

The generator requires 64-bit PHP. The generated class uses a slower byte-wise
fallback on 32-bit builds, where `ip2long()` returns signed values.

## Automatic Updates

`.github/workflows/update-cloudflare-ips.yml` runs the generator on the 1st of each
month and commits `src/CloudflareIpValidator.php` when Cloudflare's ETag changed.
It can also be run manually via `workflow_dispatch`. GitHub disables scheduled
workflows after 60 days without repository activity; re-enable it from the Actions
tab if that happens.
