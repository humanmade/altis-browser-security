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
* `ABS_XSS_PROTECTION_HEADER` (`bool`): True to send `X-XSS-Protection: 1; mode=block`, false to disable. (True by default.)


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


### Content-Security-Policy

This plugin can gather and send [Content-Security-Policy policies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) for you automatically.

**Out of the box, no policies are sent.** CSP policies tend to be specific to sites, so no assumptions are made about what you may want.

Add a filter to `altis.security.browser.content_security_policies` to set policies. This filter receives an array, where the keys are the policy directive names. Each item can either be a string or a list of directive value strings:

```php
add_filter( 'altis.security.browser.content_security_policies', function ( array $policies ) : array {
	// Policies can be set as strings.
	$policies['object-src'] = 'none';
	$policies['base-uri'] = 'self';

	// Policies can also be set as arrays.
	$policies['font-src'] = [
		'https://fonts.gstatic.com',
		'https://cdnjs.cloudflare.com',
	];

	// Special directives (such as `unsafe-inline`) are handled for you.
	$policies['script-src'] = [
		'https:',
		'unsafe-inline',
	];

	return $policies;
} );
```

Special directives (`'self'`, `'unsafe-inline'`, `'unsafe-eval'`, `'none'`, `'strict-dynamic'`) do not need to be double-quoted.

You can also modify individual directives if desired:

```php
// You can filter specific keys via the filter name.
add_filter( 'altis.security.browser.filter_policy_value.font-src', function ( array $values ) : array {
	$values[] = 'https://fonts.gstatic.com';
	return $values;
} );

// A filter is also available with the directive name in a parameter.
add_filter( 'altis.security.browser.filter_policy_value', function ( array $values, string $name ) : array {
	if ( $name === 'font-src' ) {
		$values[] = 'https://cdnjs.cloudflare.com';
	}

	return $values;
} );
```

To build Content-Security-Policy policies, we recommend using the [Laboratory CSP toolkit extension](https://addons.mozilla.org/en-US/firefox/addon/laboratory-by-mozilla/) for Firefox, and the [CSP Evaluator tool](https://csp-evaluator.withgoogle.com/).

#### Report-Only Policies

To send a [Content-Security-Policy-Report-Only header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only), use the exact same process described above for the ordinary CSP policies with the alternative filter `altis.security.browser.report_only_content_security_policies`.

An external service must be used to ingest the reports from Report-Only policies. The external service will provide you with a reporting URL which you can use by adding a `report-uri` directive with the appropriate URL for processing reports.

As an example, you can add a reporting directive to your Report-Only policies by filtering the policies array:

```php
add_filter( 'altis.security.browser.report_only_content_security_policies', function ( array $policies ) : array {
	$policies['report-uri'] = 'https://example.uriports.com/reports';
	return $policies;
} );
```

You can also modify individual directives for use in report-only policies in the same manner described above using the filters,

- `altis.security.browser.filter_report_only_policy_value.{ directive name }`
- `altis.security.browser.filter_report_only_policy_value`

Both normal and report-only policies may be used simultaneously.


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


#### X-XSS-Protection

By default, Altis adds a [`X-XSS-Protection` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection?) with the value set to `1; mode=block`. This prevents browsers from loading if they detect [cross-site scripting (XSS) attacks](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)).

This should generally always be sent. If you need to disable it, set the `ABS_XSS_PROTECTION_HEADER` header:

```php
define( 'ABS_XSS_PROTECTION_HEADER', false );
```


## License

Altis Browser Security is licensed under the GPLv2 or later. Copyright 2019 Human Made and contributors.
