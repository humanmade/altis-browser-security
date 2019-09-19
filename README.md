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


## License

Altis Browser Security is licensed under the GPLv2 or later. Copyright 2019 Human Made and contributors.
