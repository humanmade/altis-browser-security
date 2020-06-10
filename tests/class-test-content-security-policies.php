<?php

namespace Altis\Security\Browser;

use WP_UnitTestCase;

class Test_Content_Security_Policies extends WP_UnitTestCase {
	public function setUp() {
		Output::reset();
	}

	/**
	 * Filter the browser security module CSP hook.
	 *
	 * @param string[] $policies Map from directive name to value or list of values.
	 * @return array Filtered array.
	 */
	public function _filter_policies( array $policies ) : array {
		$policies['object-src'] = 'none';
		$policies['font-src'] = [
			'https://fonts.gstatic.com',
			'https://cdnjs.cloudflare.com',
		];
		return $policies;
	}

	public function test_csp_header_empty_by_default() {
		send_normal_csp_header();
		$this->assertEquals( [], Output::$headers );
	}

	public function test_report_only_csp_header_empty_by_default() {
		send_report_only_csp_header();
		$this->assertEquals( [], Output::$headers );
	}

	public function test_filter_csp_policies() {
		add_filter(
			'altis.security.browser.content_security_policies',
			[ $this, '_filter_policies' ]
		);
		send_normal_csp_header();
		$this->assertCount( 1, Output::$headers );
		$this->assertEquals(
			"Content-Security-Policy: font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com; object-src 'none'",
			Output::$headers[0]
		);
	}

	public function test_filter_report_only_csp_policies() {
		add_filter(
			'altis.security.browser.report_only_content_security_policies',
			[ $this, '_filter_policies' ]
		);
		send_report_only_csp_header();
		$this->assertCount( 1, Output::$headers );
		$this->assertEquals(
			"Content-Security-Policy-Report-Only: font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com; object-src 'none'",
			Output::$headers[0]
		);
	}

	public function test_filter_individual_report_only_directive() {
		add_filter(
			'altis.security.browser.filter_report_only_policy_value.object-src',
			function( $directive ) {
				return 'none';
			}
		);
		send_report_only_csp_header();
		$this->assertCount( 1, Output::$headers );
		$this->assertEquals(
			"Content-Security-Policy-Report-Only: object-src 'none'",
			Output::$headers[0]
		);
	}
}
