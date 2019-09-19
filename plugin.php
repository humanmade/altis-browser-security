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
] );
