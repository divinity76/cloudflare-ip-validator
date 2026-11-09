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
month. When Cloudflare's ETag changed it commits `src/CloudflareIpValidator.php` and
publishes the next patch release (`vX.Y.Z+1`), so Composer users get the new ranges
without manual tagging. It can also be run manually via `workflow_dispatch`. GitHub
disables scheduled workflows after 60 days without repository activity; re-enable it
from the Actions tab if that happens.

If the commit succeeds but the release step fails, create the release manually from
that commit; a later run sees no file changes and will not retry. The release step
aborts if no reachable version tag exists, a tag is malformed, or the next tag is
already present, rather than guessing a version.
