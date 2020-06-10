<?php
/**
 * Intercept header() calls by defining a header() method within the plugin's
 * own namespace, to permit inspecting output without sending real headers.
 *
 * Hat-tip https://mwop.net/blog/2014-08-11-testing-output-generating-code.html
 */

namespace Altis\Security\Browser;

/**
 * Store 
 */
abstract class Output {
    public static $headers = [];

    public static function reset() {
        self::$headers = [];
    }
}

// Force headers_sent to always return false, to obviate process isolation.
function headers_sent() {
    return false;
}

// Redefine header() to push the provided value into our output array.
function header( $value ) {
    Output::$headers[] = $value;
}
