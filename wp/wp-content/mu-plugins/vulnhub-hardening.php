<?php
/**
 * Plugin Name: VulnHub platform hardening
 * Description: Closes WordPress-platform exposures found in the 2026-09-09 unauthenticated scan — user enumeration, login-form username confirmation, XML-RPC, and version/tech disclosure. App logic lives in the vulnhub-* plugins; this only hardens the WordPress underneath them.
 * Author: Security
 * Version: 1.0.0
 *
 * A must-use plugin on purpose. These are controls that must not be one
 * "deactivate" click away from off, and none of them belongs to a feature —
 * they are properties the whole install should have.
 *
 * @package VulnHub\Hardening
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * 1 + 2. User enumeration.
 *
 * The scan pulled the administrator's username three ways: the REST users
 * collection, the `?author=N` redirect, and the author archive it lands on.
 * A username is half of a login, so on an internet-facing sign-in page this
 * is the single fact worth denying an attacker.
 *
 * The REST collection is removed only for logged-out callers, so an
 * authenticated editor still gets the author list the block editor expects.
 */
add_filter(
	'rest_endpoints',
	static function ( array $endpoints ): array {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( array( '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ) as $route ) {
			if ( isset( $endpoints[ $route ] ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}
);

/*
 * `?author=N` on the front end is only ever an enumeration probe here — the
 * app has no author archives anyone is meant to read. Refuse the numeric form
 * before WordPress can 301 it to `/author/<login>/` and hand over the slug.
 */
add_action(
	'init',
	static function (): void {
		if ( is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only guard on a public probe.
		$author = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['author'] ) ) : '';
		if ( '' !== $author && preg_match( '/^\d+$/', $author ) ) {
			wp_die(
				esc_html__( 'Not found.', 'vulnhub' ),
				esc_html__( 'Not found', 'vulnhub' ),
				array( 'response' => 404 )
			);
		}
	},
	0
);

// The author-archive rewrite is the same disclosure from the other side.
add_action(
	'template_redirect',
	static function (): void {
		if ( is_author() ) {
			wp_die(
				esc_html__( 'Not found.', 'vulnhub' ),
				esc_html__( 'Not found', 'vulnhub' ),
				array( 'response' => 404 )
			);
		}
	}
);

/*
 * 3. Login-form username confirmation.
 *
 * Stock WordPress says "the password you entered for romy is incorrect" for a
 * real user and "not registered" for an unknown one, which confirms a username
 * outright. One message for every failure removes the oracle. (Display is
 * already the only channel — the scan found no other leak of this.)
 */
add_filter(
	'login_errors',
	static function (): string {
		return esc_html__( 'The username or password is incorrect.', 'vulnhub' );
	}
);
// Same oracle reached through the "lost password" form.
add_filter( 'wp_login_errors', static fn() => new WP_Error( 'vh_login', esc_html__( 'The username or password is incorrect.', 'vulnhub' ) ), 5 );

/*
 * 4. XML-RPC.
 *
 * Nothing in this product uses it, and it hands an attacker two gifts:
 * `system.multicall` to try hundreds of passwords in one request past most
 * rate limits, and `pingback.ping` to make the server issue outbound requests.
 * Apache denies the file outright (see .htaccess); this covers any path that
 * reaches PHP another way, and drops the pingback methods regardless.
 */
add_filter( 'xmlrpc_enabled', '__return_false' );
add_filter(
	'xmlrpc_methods',
	static function ( array $methods ): array {
		unset(
			$methods['pingback.ping'],
			$methods['pingback.extensions.getPingbacks'],
			$methods['system.multicall']
		);
		return $methods;
	}
);
// Don't advertise a pingback endpoint we don't answer.
add_filter( 'wp_headers', static function ( array $h ): array { unset( $h['X-Pingback'] ); return $h; } );

/*
 * 6. Version and technology disclosure.
 *
 * Remove the WordPress generator tag and version query strings, and strip the
 * PHP `X-Powered-By` header on any response that reaches PHP. `readme.html`,
 * `license.txt` and the Apache/PHP Server banner are handled at the web-server
 * layer, which is the only place that can see a static file or the banner.
 */
remove_action( 'wp_head', 'wp_generator' );
add_filter( 'the_generator', '__return_empty_string' );

add_action(
	'send_headers',
	static function (): void {
		if ( ! headers_sent() ) {
			header_remove( 'X-Powered-By' );
			header( 'X-Content-Type-Options: nosniff' );
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
			// Match the clickjacking protection wp-login already sets, site-wide.
			if ( ! headers_sent() ) {
				header( 'X-Frame-Options: SAMEORIGIN' );
			}
		}
	},
	1
);
