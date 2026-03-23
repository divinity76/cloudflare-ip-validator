# cloudflare-ip-validator

Fast PHP validation of whether an IP belongs to Cloudflare.
This library is heavily optimized: [`src/CloudflareIpValidator.php`](src/CloudflareIpValidator.php), I believe the implementation is about as fast as userland PHP can get. To go faster, you would likely need a C-php-extension.

## Install

```bash
composer require divinity76/cloudflare-ip-validator
```

## Public API

- `Divinity76\CloudflareIpValidator\CloudflareIpValidator`
  - `isCloudflareIp(string $ip): bool` (static)

## Usage

```php
<?php
use Divinity76\CloudflareIpValidator\CloudflareIpValidator;

CloudflareIpValidator::isCloudflareIp('173.245.48.1'); // true
CloudflareIpValidator::isCloudflareIp('1.1.1.1'); // false
```
Alternatively:
```php
<?php

\Divinity76\CloudflareIpValidator\CloudflareIpValidator::isCloudflareIp('173.245.48.1'); // true
\Divinity76\CloudflareIpValidator\CloudflareIpValidator::isCloudflareIp('1.1.1.1'); // false
```
