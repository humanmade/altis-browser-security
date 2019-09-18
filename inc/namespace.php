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

	add_filter( 'script_loader_tag', __NAMESPACE__ . '\\output_integrity_for_script', 0, 2 );
	add_filter( 'style_loader_tag', __NAMESPACE__ . '\\output_integrity_for_style', 0, 3 );

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
