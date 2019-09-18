# Altis Browser Security

Improve the browser security of your WordPress site.

Built for, and included with, [Altis, the WordPress Digital Experience Platform for Enterprise](https://www.altis-dxp.com/).


## Installation

You can use this plugin either directly as a submodule or as a Composer dependency.

```sh
# For submodule usage:
git submodule add https://github.com/humanmade/altis-browser-security.git wp-content/plugins/altis-browser-security

# For Composer usage:
composer require altis/browser-security
```


## Configuration

If you are using this as part of the [Altis DXP](https://www.altis-dxp.com/), configuration is handled via the configuration framework. Consult the [Altis security module documentation](https://www.altis-dxp.com/resources/docs/security/browser/).

As a standalone plugin, you can use the following constants to change the behaviour of this module:

* `ABS_AUTOMATIC_INTEGRITY` (`bool`): True to enable automatic generation of integrity hashes, false to disable. (True by default.)
* `ABS_NOSNIFF_HEADER` (`bool`): True to send `X-Content-Type-Options: nosniff`, false to disable. (True by default.)
* `ABS_FRAME_OPTIONS_HEADER` (`bool`): True to send `X-Frame-Options: SAMEORIGIN`, false to disable. (True by default.)


## Features

### Subresource Integrity

This plugin automatically adds [subresource integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) hashes where possible. These will be generated for any files on the same server; i.e. any plugin or theme assets.

These hashes will be automatically cached in the object cache, linked to the filename and version of the script or stylesheet.

For external assets, you can manually set the integrity hash. After enqueuing (or registering) your asset, use the `set_hash_for_script()` or `set_hash_for_style()` helpers:

```php
// Setting hashes for scripts.
use function Altis\Security\Browser\set_hash_for_script;
wp_enqueue_script( 'my-handle', 'https://...' );
set_hash_for_script( 'my-handle', 'sha384-...' );

// Setting hashes for styles.
use function Altis\Security\Browser\set_hash_for_style;
wp_enqueue_style( 'my-handle', 'https://...' );
set_hash_for_style( 'my-handle', 'sha384-...' );
```


### Security Headers

This plugin automatically adds various security headers by default. These follow best-practices for web security and aim to provide a sensible, secure default.

In some cases, you may want to adjust or disable these headers depending on the use cases of your site.


#### X-Content-Type-Options

By default, Altis adds a [`X-Content-Type-Options` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) with the value set to `nosniff`. This prevents browsers from attempting to guess the content type based on the content, and instead forces them to follow the type set in the `Content-Type` header.

This should generally always be sent, and your content type should always be set explicitly. If you need to disable it, set the `ABS_NOSNIFF_HEADER` constant:

```php
define( 'ABS_NOSNIFF_HEADER', false );
```


#### X-Frame-Options

By default, Altis adds a [`X-Frame-Options` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) with the value set to `sameorigin`. This prevents your site from being iframed into another site, which can prevent [clickjacking attacks](https://en.wikipedia.org/wiki/Clickjacking).

This should generally always be sent, but in some cases, you may want to allow specific sites to iframe your site, or allow any sites. To disable the automatic header, set the `ABS_FRAME_OPTIONS_HEADER` constant:

```php
define( 'ABS_FRAME_OPTIONS_HEADER', false );
```

You can then send your own headers as needed. We recommend hooking into the `template_redirect` hook to send these headers.


## License

Altis Browser Security is licensed under the GPLv2 or later. Copyright 2019 Human Made and contributors.
