<?php

namespace Altis\Security\Browser;

use WP_UnitTestCase;
use WP_REST_Request;

class Test_Rest_Allow_Origins extends WP_UnitTestCase {

	function setUp() {
		parent::setUp();
	}

	function test_filter_function() {
		$result = restrict_cors_origin( true );
		$this->assertTrue( restrict_cors_origin( $result ) );
	}

	function test_filter_is_added() {
		add_filter( 'altis.security.browser.rest_allow_origin', '__return_false' );
		bootstrap( array() );

		$this->assertNotFalse( has_filter( 'rest_pre_dispatch', __NAMESPACE__ . '\\restrict_cors_origin' ) );
	}

	function test_dynamic_filter_disallow_local() {
		$allow = true;

		add_filter( 'altis.security.browser.rest_allow_origin', function ( $allow, $origin ) {
			if ( false !== strpos( $origin, '.local' ) ) {
				return false;
			}
			return true;
		}, 10, 2 );

		add_filter( 'http_origin', function( $origin ) {
			return 'https://example.local'; 
		} );

		$result = restrict_cors_origin( true );
		$this->assertInstanceOf( 'WP_Error', $result );

		add_filter( 'http_origin', function( $origin ) {
			return 'https://example.com'; 
		} );

		$result = restrict_cors_origin( true );
		$this->assertNotInstanceOf( 'WP_Error', $result );
	}
}
