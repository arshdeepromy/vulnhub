<?php
/**
 * Plugin Name:       VulnHub AWS
 * Description:       Reads network exposure straight from the AWS account: which instances the internet can actually reach, and on which ports.
 * Version:           0.3.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            VulnHub
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * The listening-port inventory says what a host has open. It cannot say who
 * can reach it, because that lives in the network and not on the host. AWS is
 * the one place where that question is answerable rather than inferable, and
 * this is where those answers arrive.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_AWS_DIR', plugin_dir_path( __FILE__ ) );

/*
 * Only the classes that depend on nothing of ours load at file scope.
 *
 * Plugins load alphabetically, so `vulnhub-aws` is parsed before
 * `vulnhub-core` and \VulnHub\Core\Connector does not exist yet -- requiring
 * the connector here fatals the whole site on activation. Core fires
 * `vulnhub_register_connectors` on plugins_loaded:5, so everything that
 * extends or calls core waits for that, the same way vulnhub-intune does.
 */
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-sigv4.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-client.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-inspector.php';

add_action(
	'vulnhub_register_connectors',
	static function ( $connectors ): void {
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-setup.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-accounts.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-reachability.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-connector.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-admin.php';

		VulnHub_AWS_Reachability::install();
		VulnHub_AWS_Accounts::install();
		VulnHub_AWS_Admin::init();

		// Registering here is what puts it on the Integrations screen beside
		// the others, with the same form, health panel, Test connection,
		// Sync now and schedule -- rather than a second settings page that
		// looks almost but not quite like the first.
		$connectors->register( new VulnHub_AWS_Connector() );
	}
);

/**
 * Hand the exposure rule what AWS observed.
 *
 * A filter rather than a direct call because vulnhub-threat must keep working
 * with this plugin absent: exposure degrades to the listening-port evidence
 * instead of fataling on a missing class.
 */
add_filter(
	'vulnhub_cloud_reachable_assets',
	static function ( array $assets ): array {
		if ( ! class_exists( 'VulnHub_AWS_Reachability' ) ) {
			return $assets;
		}

		return $assets + VulnHub_AWS_Reachability::reachable_assets();
	}
);

/**
 * Serve the CloudFormation template.
 *
 * A route rather than a static file so the policy in the template is built
 * from the same list the connector documents, and the two cannot drift apart.
 * It contains no secrets -- only the names of read-only permissions -- but it
 * is gated on managing connectors anyway, because nothing about this install
 * needs to be anonymously readable.
 */
add_action(
	'rest_api_init',
	static function (): void {
		register_rest_route(
			'vulnhub-aws/v1',
			'/cloudformation-template',
			array(
				'methods'             => 'GET',
				'permission_callback' => static fn (): bool => current_user_can( \VulnHub\Core\Caps::MANAGE ),
				'callback'            => static function () {
					require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-setup.php';

					$body = VulnHub_AWS_Setup::template();

					header( 'Content-Type: text/yaml; charset=utf-8' );
					header( 'Content-Disposition: attachment; filename="vulnhub-aws-readonly.yaml"' );
					header( 'Content-Length: ' . strlen( $body ) );

					echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					exit;
				},
			)
		);
	}
);
