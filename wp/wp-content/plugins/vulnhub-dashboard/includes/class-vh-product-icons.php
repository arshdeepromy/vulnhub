<?php
/**
 * Bundled brand logos for the "Exposure by product" widget.
 *
 * Inline SVG so nothing is fetched (CSP-safe) and each mark recolours to white
 * on its brand-coloured chip. These are recognisable brand *motifs* drawn as
 * clean single-colour glyphs — the coffee cup for Java, the hexagon for
 * Node.js, the four panes for Windows — not traced vendor artwork, so they
 * carry no licensing baggage and read at 22px.
 *
 * Keyed by product slug (VH_Product::slug()). Anything without an entry falls
 * back to the brand-coloured monogram chip. Filterable, so a licensed icon set
 * can be dropped in later without touching this file:
 *
 *     add_filter( 'vulnhub_product_icons', fn( $m ) => $m + array( 'zoom' => '<path .../>' ) );
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_filter(
	'vulnhub_product_icons',
	static function ( array $icons ): array {
		$mark = array(

			// Windows — four panes.
			'os_windows_glyph' => '<path fill="#fff" d="M3 5.6l7.2-1v6.6H3zM11.2 4.4L21 3v8.9h-9.8zM3 12.9h7.2v6.5l-7.2-1zM11.2 12.9H21V21l-9.8-1.4z"/>',

			// Google Chrome — outer ring, hub, three spokes.
			'google-chrome' => '<circle cx="12" cy="12" r="9" fill="none" stroke="#fff" stroke-width="1.7"/><circle cx="12" cy="12" r="3.4" fill="none" stroke="#fff" stroke-width="1.7"/><path d="M12 8.6h8M12 8.6L7.6 15.4M12 8.6 8.9 15.1" stroke="#fff" stroke-width="1.5" fill="none" stroke-linecap="round"/>',

			// Mozilla Firefox — flame.
			'mozilla-firefox' => '<path fill="#fff" d="M12 3c1.4 1.8 1 3.4.2 4.6 1-.5 2.2-.3 2.9.6.3-.7.2-1.5-.2-2.1 2.3 1.4 3.6 4 3.6 6.7A6.5 6.5 0 1 1 6.3 8.6c-.2 1.2.2 2.4 1.1 3.2-.3-1.9.6-3.8 2.3-4.8C11 6 12 4.7 12 3z"/>',

			// Microsoft Edge — swirl arc.
			'microsoft-edge' => '<path fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" d="M20 13.5A8 8 0 1 0 6 17c2 2.4 6 2.7 8.2.6 1.3-1.2 1.2-3-.2-3.8-1.6-.9-4.2-.4-6 .2"/>',

			// Java family — coffee cup + steam.
			'oracle-java-se' => '<path fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" d="M9 3.5c-1 1 .4 1.8 0 3M12.5 3c-1 1 .4 1.8 0 3"/><path fill="#fff" d="M5 10h11v3a4 4 0 0 1-4 4H9a4 4 0 0 1-4-4z"/><path fill="none" stroke="#fff" stroke-width="1.6" d="M16 11h1.6a1.9 1.9 0 0 1 0 3.8H16"/><path fill="#fff" d="M5 19h11v1.6H5z"/>',

			// Node.js — hexagon + N.
			'node-js' => '<path fill="none" stroke="#fff" stroke-width="1.6" stroke-linejoin="round" d="M12 3l7.4 4.3v8.6L12 20.2 4.6 15.9V7.3z"/><path fill="none" stroke="#fff" stroke-width="1.7" stroke-linecap="round" d="M9.4 15V9.4l5.2 5.2V9"/>',

			// SQLite — database cylinder.
			'sqlite' => '<path fill="none" stroke="#fff" stroke-width="1.6" d="M5 6.5c0-1.4 3.1-2.5 7-2.5s7 1.1 7 2.5-3.1 2.5-7 2.5-7-1.1-7-2.5z"/><path fill="none" stroke="#fff" stroke-width="1.6" d="M5 6.5v11c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-11M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5"/>',

			// Apache family — feather.
			'apache-log4j' => '<path fill="#fff" d="M18.5 4.2c-4 .3-8.6 2.6-10.8 7.3-.7 1.5-1 3.2-1 4.9L4 20l1.6-1.7c1.7.2 3.5-.1 5-.9C15.4 15 17.7 10 18.5 4.2z"/><path fill="none" stroke="#fff" stroke-width="1.3" d="M15.5 7.5C12 9 9.4 11.8 7.6 15.4"/>',

			// Zoom — video camera.
			'zoom' => '<rect x="3.5" y="7" width="11" height="10" rx="2.5" fill="#fff"/><path fill="#fff" d="M15.5 10.2l4.5-2.6v8.8l-4.5-2.6z"/>',

			// OpenSSL — padlock.
			'openssl' => '<rect x="5" y="10.5" width="14" height="9" rx="2" fill="#fff"/><path fill="none" stroke="#fff" stroke-width="1.7" d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/><circle cx="12" cy="14.5" r="1.4" fill="#0b1220"/>',

			// Docker — container stack + whale hint.
			'docker-desktop' => '<path fill="#fff" d="M4 12h3v3H4zm3.6 0h3v3h-3zm3.6 0h3v3h-3zM7.6 8.5h3v3h-3zm3.6 0h3v3h-3zm0-3.5h3v3h-3z"/><path fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" d="M3 15.5c3 2.5 12 2.4 15.5-1.5 1.6 .4 2.6-.3 3-1"/>',

			// Notepad++ — document with plus.
			'notepad-plus-plus' => '<path fill="none" stroke="#fff" stroke-width="1.6" stroke-linejoin="round" d="M6 3.5h8l4 4V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20z"/><path stroke="#fff" stroke-width="1.5" stroke-linecap="round" d="M13.5 11v4M11.5 13h4"/>',

			// libcurl — terminal prompt.
			'libcurl' => '<rect x="3.5" y="5" width="17" height="14" rx="2.5" fill="none" stroke="#fff" stroke-width="1.6"/><path stroke="#fff" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" fill="none" d="M7 10l2.5 2L7 14M12.5 14.5h4"/>',
		);

		// Alias sibling products to the same mark.
		$mark['openjdk']                   = $mark['oracle-java-se'];
		$mark['azul-zulu-java']            = $mark['oracle-java-se'];
		$mark['amazon-corretto-java']      = $mark['oracle-java-se'];
		$mark['apache-tomcat']             = $mark['apache-log4j'];
		$mark['apache-commons-fileupload'] = $mark['apache-log4j'];

		return array_merge( $mark, $icons ); // caller's entries win if any overlap.
	}
);
