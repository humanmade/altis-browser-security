<?php
/**
 * Plugin Name: Altis Browser Security
 * Description: Browser security utilities for WordPress/Altis
 * Author: Human Made
 * Author URI: https://humanmade.com/
 */

namespace Altis\Security\Browser;

if ( function_exists( 'Altis\\Security\\bootstrap' ) ) {
	// Being loaded via Altis, skip bootstrap.
	return;
}

bootstrap( [
	'automatic-integrity' => defined( 'ABS_AUTOMATIC_INTEGRITY' ) ? ABS_AUTOMATIC_INTEGRITY : true,
	'nosniff-header' => defined( 'ABS_NOSNIFF_HEADER' ) ? ABS_NOSNIFF_HEADER : true,
	'frame-options-header' => defined( 'ABS_FRAME_OPTIONS_HEADER' ) ? ABS_FRAME_OPTIONS_HEADER : true,
	'xss-protection-header' => defined( 'ABS_XSS_PROTECTION_HEADER' ) ? ABS_XSS_PROTECTION_HEADER :true,
] );
