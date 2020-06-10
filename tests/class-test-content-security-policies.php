<?php

namespace Altis\Security\Browser;

use WP_UnitTestCase;

class Test_Content_Security_Policies extends WP_UnitTestCase {
	function setUp() {
		Output::reset();
		parent::setUp();
	}

	function test_csp_header_empty_by_default() {
		send_normal_csp_header();
		$this->assertEquals( [], Output::$headers );
	}

	function test_report_only_csp_header_empty_by_default() {
		send_report_only_csp_header();
		$this->assertEquals( [], Output::$headers );
	}

	/**
	 * Filter the browser security module CSP hook.
	 *
	 * @param string[] $policies Map from directive name to value or list of values.
	 * @return array Filtered array.
	 */
	function _filter_policies( array $policies ) : array {
		$policies['object-src'] = 'none';
		$policies['font-src'] = [
			'https://fonts.gstatic.com',
			'https://cdnjs.cloudflare.com',
		];
		return $policies;
	}

	function test_filter_csp_policies() {
		$filter_name = 'altis.security.browser.content_security_policies';
		add_filter( $filter_name, [ $this, '_filter_policies' ] );
		send_normal_csp_header();
		$this->assertEquals(
			[ "Content-Security-Policy: font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com; object-src 'none'" ],
			Output::$headers
		);
	}

	function test_filter_report_only_csp_policies() {
		$filter_name = 'altis.security.browser.report_only_content_security_policies';
		add_filter( $filter_name, [ $this, '_filter_policies' ] );
		send_report_only_csp_header();
		$this->assertEquals(
			[ "Content-Security-Policy-Report-Only: font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com; object-src 'none'" ],
			Output::$headers
		);
	}

	/**
	 * Filter the filter_policy_value.child-src hook.
	 *
	 * @param array $value An array of directive values (may be empty).
	 * @return array The filtered array of directive values.
	 */
	function _filter_child_src_policy_value( array $directive ) : array {
		return [
			"'self'",
		];
	}

	function test_filter_individual_directive() {
		add_filter(
			'altis.security.browser.filter_policy_value.child-src',
			[ $this, '_filter_child_src_policy_value' ]
		);
		send_normal_csp_header();
		$this->assertEquals(
			[ "Content-Security-Policy: child-src 'self'" ],
			Output::$headers
		);
	}

	function test_filter_individual_report_only_directive() {
		add_filter(
			'altis.security.browser.filter_report_only_policy_value.child-src',
			[ $this, '_filter_child_src_policy_value' ]
		);
		send_report_only_csp_header();
		$this->assertEquals(
			[ "Content-Security-Policy-Report-Only: child-src 'self'" ],
			Output::$headers
		);
	}
}
