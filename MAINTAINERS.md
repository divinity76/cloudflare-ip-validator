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
