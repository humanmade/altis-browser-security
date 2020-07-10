<?php

namespace Altis\Security\Browser;

use Altis;
use WP_Dependencies;
use WP_Error;

const INTEGRITY_DATA_KEY = 'altis_integrity_hash';
const INTEGRITY_HASH_ALGO = 'sha384';
const INTEGRITY_CACHE_GROUP = 'altis_integrity';

/**
 * Bootstrap.
 *
 * @param array $config {
 *   @var bool $automatic-integrity True to enable automatic generation of integrity hashes, false to disable. (True by default.)
 * }
 */
function bootstrap( array $config ) {
	if ( $config['automatic-integrity'] ?? true ) {
		add_filter( 'script_loader_tag', __NAMESPACE__ . '\\generate_hash_for_script', 0, 3 );
		add_filter( 'style_loader_tag', __NAMESPACE__ . '\\generate_hash_for_style', 0, 3 );
	}

	if ( $config['nosniff-header'] ?? true ) {
		add_action( 'template_redirect', 'send_nosniff_header' );
	}

	if ( $config['frame-options-header'] ?? true ) {
		add_action( 'template_redirect', 'send_frame_options_header' );
	}

	if ( $config['xss-protection-header'] ?? true ) {
		add_action( 'template_redirect', __NAMESPACE__ . '\\send_xss_header' );
	}

	if ( $config['content-security-policy'] ?? null ) {
		add_filter( 'altis.security.browser.content_security_policies', function ( $policies ) use ( $config ) {
			return array_merge( $policies, $config['content-security-policy'] );
		}, 0 );
	}

	if ( $config['report-only-content-security-policy'] ?? null ) {
		add_filter( 'altis.security.browser.report_only_content_security_policies', function ( $policies ) use ( $config ) {
			return array_merge( $policies, $config['report-only-content-security-policy'] );
		}, 0 );
	}

	add_filter( 'script_loader_tag', __NAMESPACE__ . '\\output_integrity_for_script', 0, 2 );
	add_filter( 'style_loader_tag', __NAMESPACE__ . '\\output_integrity_for_style', 0, 3 );
	add_action( 'template_redirect', __NAMESPACE__ . '\\send_normal_csp_header' );
	add_action( 'template_redirect', __NAMESPACE__ . '\\send_report_only_csp_header' );

	// Register cache group as global (as it's path-based rather than data-based).
	wp_cache_add_global_groups( INTEGRITY_CACHE_GROUP );
}

/**
 * Generate an integrity hash for a given path.
 *
 * Provides the `altis.security.browser.pre_generate_hash_for_path` filter to
 * allow shortcircuiting hash generation if using external build tools
 * or caching.
 *
 * @param string $path Absolute path to a file to get the hash for.
 * @param string $version Version of the hash, used as part of the cache key.
 * @return string|null Integrity hash (in format "<algo>-<hash>") if available, or null if it could not be generated.
 */
function generate_hash_for_path( string $path, ?string $version = null ) : ?string {
	$hash = apply_filters( 'altis.security.browser.pre_generate_hash_for_path', null, $path, $version );
	if ( ! empty( $hash ) ) {
		return $hash;
	}

	// Load from cache if possible.
	$cache_key = sha1( sprintf( '%s?%s', $path, $version ) );
	$cached = wp_cache_get( $cache_key, INTEGRITY_CACHE_GROUP );
	if ( ! empty( $cached ) ) {
		return $cached;
	}

	$data = file_get_contents( $path );
	$hash = hash( INTEGRITY_HASH_ALGO, $data, true );
	$value = INTEGRITY_HASH_ALGO . '-' . base64_encode( $hash );
	$value = apply_filters( 'altis.security.browser.generate_hash_for_path', $value, $path, $version );

	// Cache.
	wp_cache_set( $cache_key, $value, INTEGRITY_CACHE_GROUP, time() + YEAR_IN_SECONDS );

	return $value;
}

/**
 * Automatically generate hash for a stylesheet.
 *
 * Hooked into `style_loader_tag` to automatically generate hashes for
 * stylesheets on the filesystem.
 *
 * @param string $html Stylesheet HTML tag.
 * @param string $handle Unique handle for the stylesheet.
 * @param string $href URL for the stylesheet.
 * @return string Unaltered stylesheet HTML tag.
 */
function generate_hash_for_style( string $html, string $handle, string $href ) : string {
	global $wp_styles;

	$err = generate_hash_for_asset( $wp_styles, $handle, $href );
	if ( is_wp_error( $err ) ) {
		trigger_error( sprintf( 'Style %s error [%s]: %s', $handle, $err->get_error_code(), $err->get_error_message() ), E_USER_NOTICE );
	}

	return $html;
}

/**
 * Automatically generate hash for a script.
 *
 * Hooked into `script_loader_tag` to automatically generate hashes for
 * scripts on the filesystem.
 *
 * @param string $html Stylesheet HTML tag.
 * @param string $handle Unique handle for the stylesheet.
 * @param string $href URL for the stylesheet.
 * @return string Unaltered stylesheet HTML tag.
 */
function generate_hash_for_script( string $tag, string $handle, string $src ) : string {
	global $wp_scripts;

	$err = generate_hash_for_asset( $wp_scripts, $handle, $src );
	if ( is_wp_error( $err ) ) {
		trigger_error( sprintf( 'Script %s error [%s]: %s', $handle, $err->get_error_code(), $err->get_error_message() ), E_USER_NOTICE );
	}

	return $tag;
}

/**
 * Automatically generate hash for an asset.
 *
 * @param WP_Dependencies $dependencies
 * @param string $handle
 * @return WP_Error|null Error if one occurred, or null if successful.
 */
function generate_hash_for_asset( WP_Dependencies $dependencies, string $handle ) : ?WP_Error {
	$asset = $dependencies->query( $handle );
	if ( ! $asset ) {
		return new WP_Error(
			'altis.security.browser.invalid_asset_handle',
			sprintf(
				'Invalid asset handle %s',
				$handle
			)
		);
	}

	// Translate the script back to a path if possible.
	$src = $asset->src;
	$site_url = trailingslashit( site_url() );
	if ( substr( $src, 0, strlen( $site_url ) ) !== $site_url ) {
		// Not a local asset, skip.
		return null;
	}

	$rel_path = substr( $src, strlen( $site_url ) );
	$query = '';
	if ( strpos( $rel_path, '?' ) !== false ) {
		list( $rel_path, $query ) = explode( '?', $rel_path, 2 );
	}

	if ( path_is_absolute( $rel_path ) || strpos( $rel_path, '../' ) !== false ) {
		// Invalid relative path.
		return new WP_Error(
			'altis.security.browser.invalid_path',
			sprintf(
				'Path "%s" for %s is invalid',
				$src,
				$handle
			),
			compact( 'handle', 'src' )
		);
	}

	// Determine root directory.
	if ( defined( 'Altis\\ROOT_DIR' ) ) {
		$root = Altis\ROOT_DIR;
	} else {
		// Either ABSPATH or directory above.
		if ( file_exists( ABSPATH . '/wp-config.php' ) ) {
			$root = ABSPATH;
		} else {
			$root = dirname( ABSPATH );
		}
	}

	if ( $root !== ABSPATH && substr( $rel_path, 0, 3 ) === 'wp-' ) {
		// Core asset, use ABSPATH instead.
		$root = ABSPATH;
	}

	$actual_path = path_join( $root, $rel_path );
	if ( ! file_exists( $actual_path ) ) {
		// Invalid path.
		return new WP_Error(
			'altis.security.browser.file_not_exists',
			sprintf( 'File for %s does not exist', $handle )
		);
	}

	// Generate the hash.
	$hash = generate_hash_for_path( $actual_path, $asset->ver );
	if ( empty( $hash ) ) {
		// Couldn't generate a hash.
		return new WP_Error(
			'altis.security.browser.could_not_generate_hash',
			sprintf( 'Could not generate hash for %s', $handle )
		);
	}

	$did_set = set_hash_for_asset( $dependencies, $handle, $hash );
	if ( ! $did_set ) {
		// Couldn't set the hash.
		return new WP_Error(
			'altis.security.browser.could_not_set_hash',
			sprintf( 'Could not set hash for %s', $handle )
		);
	}

	return null;
}

/**
 * Get the integrity hash for a script.
 *
 * Use `set_hash_for_script()` to set the integrity hash for a script.
 *
 * @param string $handle Unique script handle.
 * @return string|null Integrity hash if set, null otherwise.
 */
function get_hash_for_script( string $handle ) : ?string {
	global $wp_scripts;
	return get_hash_for_asset( $wp_scripts, $handle );
}

/**
 * Get the integrity hash for a style.
 *
 * Use `set_hash_for_style()` to set the integrity hash for a style.
 *
 * @param string $handle Unique style handle.
 * @return string|null Integrity hash if set, null otherwise.
 */
function get_hash_for_style( string $handle ) : ?string {
	global $wp_styles;
	return get_hash_for_asset( $wp_styles, $handle );
}

/**
 * Get the integrity hash for an asset.
 *
 * Use `set_hash_for_asset()` to set the integrity hash for an asset.
 *
 * @param WP_Dependencies $dependencies Dependency registry to use.
 * @param string $handle Unique asset handle.
 * @return string|null Integrity hash if set, null otherwise.
 */
function get_hash_for_asset( WP_Dependencies $dependencies, string $handle ) : ?string {
	return $dependencies->get_data( $handle, INTEGRITY_DATA_KEY ) ?? null;
}

/**
 * Set the integrity hash for a script.
 *
 * @param string $handle Unique script handle.
 * @param string $hash Integrity hash (in format "<algo>-<hash>").
 * @return boolean True if the hash was set correctly, false otherwise.
 */
function set_hash_for_script( string $handle, string $hash ) : bool {
	global $wp_scripts;
	return set_hash_for_asset( $wp_scripts, $handle, $hash );
}

/**
 * Set the integrity hash for a stylesheet.
 *
 * @param string $handle Unique style handle.
 * @param string $hash Integrity hash (in format "<algo>-<hash>").
 * @return boolean True if the hash was set correctly, false otherwise.
 */
function set_hash_for_style( string $handle, string $hash ) : bool {
	global $wp_styles;
	return set_hash_for_asset( $wp_styles, $handle, $hash );
}

/**
 * Set the integrity hash for an asset.
 *
 * @param WP_Dependencies $dependencies Dependency registry to use.
 * @param string $handle Unique asset handle.
 * @param string $hash Integrity hash (in format "<algo>-<hash>").
 * @return boolean True if the hash was set correctly, false otherwise.
 */
function set_hash_for_asset( WP_Dependencies $dependencies, string $handle, string $hash ) : bool {
	return $dependencies->add_data( $handle, INTEGRITY_DATA_KEY, $hash );
}

/**
 * Output the integrity hash for a script.
 *
 * This is automatically added to the `script_loader_tag` filter. Use
 * `set_hash_for_script()` to set the integrity hash for a script.
 *
 * @param string $tag Script HTML tag.
 * @param string $handle Unique script handle.
 * @return string Script tag with `integrity` attribute set if available.
 */
function output_integrity_for_script( string $tag, string $handle ) : string {
	$hash = get_hash_for_script( $handle );
	if ( empty( $hash ) ) {
		return $tag;
	}

	// Insert the attribute.
	$tag = str_replace(
		"type='text/javascript' src='",
		sprintf(
			"type='text/javascript' integrity='%s' src='",
			esc_attr( $hash )
		),
		$tag
	);
	return $tag;
}

/**
 * Output the integrity hash for a stylesheet.
 *
 * This is automatically added to the `style_loader_tag` filter. Use
 * `set_hash_for_style()` to set the integrity hash for a stylesheet.
 *
 * @param string $html Stylesheet HTML tag.
 * @param string $handle Unique style handle.
 * @return string Stylesheet tag with `integrity` attribute set if available.
 */
function output_integrity_for_style( string $html, string $handle ) : string {
	$hash = get_hash_for_style( $handle );
	if ( empty( $hash ) ) {
		return $html;
	}

	// Insert the attribute.
	$html = str_replace(
		" type='text/css'",
		sprintf(
			" type='text/css' integrity='%s'",
			esc_attr( $hash )
		),
		$html
	);
	return $html;
}

/**
 * Send XSS protection header for legacy browsers.
 *
 * This is deprecated, but some browsers still want it. Additionally, this is
 * often tested in automated security checks.
 *
 * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
 */
function send_xss_header() {
	header( 'X-XSS-Protection: 1; mode=block' );
}

/**
 * Filter an individual policy value.
 *
 * @param string       $name        Directive name.
 * @param string|array $value       Directive value.
 * @param bool         $report_only Whether the directive is being filtered for
 *                                  use in a Report-Only policy. (False by default.)
 * @return string[] List of directive values.
 */
function filter_policy_value( string $name, $value, bool $report_only = false ) : array {
	$value = (array) $value;

	$needs_quotes = [
		'self',
		'unsafe-inline',
		'unsafe-eval',
		'none',
		'strict-dynamic',
	];

	// Normalize directive values.
	foreach ( $value as &$item ) {
		if ( in_array( $item, $needs_quotes, true ) || strpos( $item, 'nonce-' ) === 0 ) {
			// Add missing quotes if the value was erroneously added
			// without them.
			$item = sprintf( "'%s'", $item );
		}
	}

	if ( $report_only ) {
		/**
		 * Filter value for a given report-only policy directive.
		 *
		 * `$name` is the directive name.
		 *
		 * @param array $value List of directive values.
		 */
		$value = apply_filters( "altis.security.browser.filter_report_only_policy_value.$name", $value );
	
		/**
		 * Filter value for a given report-only policy directive.
		 *
		 * @param array $value List of directive values.
		 * @param string $name Directive name.
		 */
		return apply_filters( 'altis.security.browser.filter_report_only_policy_value', $value, $name );
	}

	/**
	 * Filter value for a given policy directive.
	 *
	 * `$name` is the directive name.
	 *
	 * @param array $value List of directive values.
	 */
	$value = apply_filters( "altis.security.browser.filter_policy_value.$name", $value );

	/**
	 * Filter value for a given policy directive.
	 *
	 * @param array $value List of directive values.
	 * @param string $name Directive name.
	 */
	return apply_filters( 'altis.security.browser.filter_policy_value', $value, $name );
}

/**
 * Send the Content-Security-Policy header.
 *
 * The header is only sent if policies have been specified. See
 * get_content_security_policies() for setting the policies.
 */
function send_normal_csp_header() {
	// Gather and filter the policy parts.
	$policies = get_content_security_policies();
	send_csp_header( 'Content-Security-Policy', $policies );
}

/**
 * Send the Content-Security-Policy-Report-Only header.
 *
 * The header is only sent if policies have been specified. See
 * get_report_only_content_security_policies() for setting the policies.
 */
function send_report_only_csp_header() {
	// Gather and filter the report-only policy parts.
	$policies = get_report_only_content_security_policies();
	send_csp_header( 'Content-Security-Policy-Report-Only', $policies );
}

/**
 * Send the Content-Security-Policy or Content-Security-Policy-Report-Only headers.
 *
 * The header is only sent if policies have been specified. See
 * get_content_security_policies() and get_report_only_content_security_policies()
 * for setting the policies.
 *
 * @param string[] $policies The policies to apply for the specified header.
 * @param string   $header   One of 'Content-Security-Policy' or
 *                           'Content-Security-Policy-Report-Only'.
 * @return void Sends CSP header and exits.
 */
function send_csp_header( string $header, array $policies ) {
	$report_only = $header === 'Content-Security-Policy-Report-Only';
	$policy_parts = [];
	foreach ( $policies as $key => $value ) {
		$value = filter_policy_value( $key, $value, $report_only );
		if ( empty( $value ) ) {
			continue;
		}
		$policy_parts[] = sprintf( '%s %s', $key, implode( ' ', $value ) );
	}
	if ( empty( $policy_parts ) ) {
		return;
	}

	header( $header . ': ' . implode( '; ', $policy_parts ) );
}

/**
 * Return an array of CSP directives for use in CSP and CSP-Report-Only headers.
 *
 * @return array Map of directive names to empty arrays.
 */
function get_content_security_policy_directives() : array {
	return [
		'child-src' => [],
		'font-src' => [],
		'frame-src' => [],
		'img-src' => [],
		'media-src' => [],
		'object-src' => [],
		'script-src' => [],
		'style-src' => [],
	];
}

/**
 * Get the content security policies for the current page.
 *
 * @return array Map from directive name to value or list of values.
 */
function get_content_security_policies() : array {
	$policies = get_content_security_policy_directives();

	/**
	 * Filter the security policies for the current page.
	 *
	 * The filtered value is a map from directive name (e.g. `base-uri`,
	 * `default-src`) to directive value. Each directive value can be a string
	 * or list of strings.
	 *
	 * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
	 *
	 * @param string[] $policies Map from directive name to value or list of values.
	 */
	return apply_filters( 'altis.security.browser.content_security_policies', $policies );
}

/**
 * Get the content security policies for the current page.
 *
 * @return array Map from directive name to value or list of values.
 */
function get_report_only_content_security_policies() : array {
	$policies = get_content_security_policy_directives();

	/**
	 * Filter the report-only security policies for the current page.
	 *
	 * The filtered value is a map from directive name (e.g. `base-uri`,
	 * `default-src`) to directive value. Each directive value can be a
	 * string or array of strings.
	 *
	 * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
	 *
	 * @param string[] $policies Map from directive name to value or list of values.
	 */
	return apply_filters( 'altis.security.browser.report_only_content_security_policies', $policies );
}
