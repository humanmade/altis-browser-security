<?php

namespace Altis\Security\Browser;

use WP_UnitTestCase;
use WP_REST_Request;

class Test_Rest_Allow_Origins extends WP_UnitTestCase {

	function setUp() {
		parent::setUp();
	}

	function test_filter_is_added() {
		add_filter( 'altis.security.browser.rest_allow_origin', '__return_false' );
		$this->assertTrue( has_filter( 'altis.security.browser.rest_allow_origin' ) );
	}

	function test_dynamic_filter_disallow_local() {
		$allow = true;
		$origin = 'https://example.local'; 

		add_filter( 'altis.security.browser.rest_allow_origin', function ( $allow, $origin ) {
			if ( strpos( $origin, '.local' ) >= 0 ) {
				return false;
			}
		
			return false;
		}, 10, 2 );

		$result = apply_filters( 'altis.security.browser.rest_allow_origin', $allow, $origin );

		$this->assertFalse( $result );
	}
}
