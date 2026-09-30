<?php

namespace Altis\Security\Browser;

use WP_UnitTestCase;

class Test_Integrity_Quote_Styles extends WP_UnitTestCase {
	function test_output_integrity_for_script_with_single_quoted_src() {
		wp_scripts()->add( 'test-script', 'https://example.com/script.js' );
		set_hash_for_script( 'test-script', 'sha384-abc123' );

		$tag = output_integrity_for_script(
			"<script src='https://example.com/script.js' id='test-script-js'></script>\n",
			'test-script'
		);

		$this->assertEquals(
			"<script integrity='sha384-abc123' src='https://example.com/script.js' id='test-script-js'></script>\n",
			$tag
		);
	}

	function test_output_integrity_for_script_with_double_quoted_src() {
		wp_scripts()->add( 'test-script', 'https://example.com/script.js' );
		set_hash_for_script( 'test-script', 'sha384-abc123' );

		$tag = output_integrity_for_script(
			'<script src="https://example.com/script.js" id="test-script-js"></script>' . "\n",
			'test-script'
		);

		$this->assertEquals(
			'<script integrity="sha384-abc123" src="https://example.com/script.js" id="test-script-js"></script>' . "\n",
			$tag
		);
	}

	function test_output_integrity_for_script_without_hash_returns_tag_unmodified() {
		wp_scripts()->add( 'test-script-no-hash', 'https://example.com/script.js' );

		$tag = '<script src="https://example.com/script.js" id="test-script-no-hash-js"></script>' . "\n";

		$this->assertEquals( $tag, output_integrity_for_script( $tag, 'test-script-no-hash' ) );
	}

	function test_output_integrity_for_style_with_single_quoted_href() {
		wp_styles()->add( 'test-style', 'https://example.com/style.css' );
		set_hash_for_style( 'test-style', 'sha384-def456' );

		$html = output_integrity_for_style(
			"<link rel='stylesheet' id='test-style-css' href='https://example.com/style.css' media='all' />\n",
			'test-style'
		);

		$this->assertEquals(
			"<link rel='stylesheet' id='test-style-css' integrity='sha384-def456' href='https://example.com/style.css' media='all' />\n",
			$html
		);
	}

	function test_output_integrity_for_style_with_double_quoted_href() {
		wp_styles()->add( 'test-style', 'https://example.com/style.css' );
		set_hash_for_style( 'test-style', 'sha384-def456' );

		$html = output_integrity_for_style(
			'<link rel="stylesheet" id="test-style-css" href="https://example.com/style.css" media="all" />' . "\n",
			'test-style'
		);

		$this->assertEquals(
			'<link rel="stylesheet" id="test-style-css" integrity="sha384-def456" href="https://example.com/style.css" media="all" />' . "\n",
			$html
		);
	}

	function test_output_integrity_for_style_without_hash_returns_html_unmodified() {
		wp_styles()->add( 'test-style-no-hash', 'https://example.com/style.css' );

		$html = '<link rel="stylesheet" id="test-style-no-hash-css" href="https://example.com/style.css" media="all" />' . "\n";

		$this->assertEquals( $html, output_integrity_for_style( $html, 'test-style-no-hash' ) );
	}
}
