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
define( 'VULNHUB_AWS_URL', plugin_dir_url( __FILE__ ) );
if ( ! defined( 'VULNHUB_AWS_VERSION' ) ) { define( 'VULNHUB_AWS_VERSION', '0.3.0' ); }

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
	require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-sso.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-inspector.php';

add_action(
	'vulnhub_register_connectors',
	static function ( $connectors ): void {
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-setup.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-accounts.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-inventory.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-explorer.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-reachability.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-network.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-connector.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-admin.php';
		require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-sso-auth.php';

		VulnHub_AWS_Reachability::install();
		VulnHub_AWS_Network::install();
		VulnHub_AWS_Accounts::install();
		VulnHub_AWS_Inventory::install();
		VulnHub_AWS_Admin::init();
		VulnHub_AWS_SSO_Auth::init();

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
		// The network map first: it is read from the captured rules and
		// needs no live session. The older live-API walk fills in behind it.
		if ( class_exists( 'VulnHub_AWS_Exposure' ) ) {
			$assets = $assets + VulnHub_AWS_Exposure::reachable_assets();
		}

		if ( ! class_exists( 'VulnHub_AWS_Reachability' ) ) {
			return $assets;
		}

		return $assets + VulnHub_AWS_Reachability::reachable_assets();
	}
);

/**
 * Hand the threat context every way in, port by port: which servers the
 * internet can open which ports on, and how. See VulnHub_AWS_Exposure::all().
 */
add_filter(
	'vulnhub_internet_paths',
	static function ( array $paths ): array {
		return class_exists( 'VulnHub_AWS_Exposure' ) ? VulnHub_AWS_Exposure::all() : $paths;
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
			'/network',
			array(
				'methods'             => 'GET',
				'permission_callback' => static fn (): bool => is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW ),
				'callback'            => static function ( $req ) {
					$acct = sanitize_text_field( (string) $req->get_param( 'account' ) );
					$vpc  = sanitize_text_field( (string) $req->get_param( 'vpc' ) );
					return rest_ensure_response( VulnHub_AWS_Network::arch_graph( $acct, $vpc ) );
				},
			)
		);

		/*
		 * The whole estate as one tree. It is a read across every captured
		 * account, so it is built once per request and sent whole -- the
		 * browser expands branches out of what it already holds, which is why
		 * opening one has no spinner. Same capability as the per-account map.
		 */
		register_rest_route(
			'vulnhub-aws/v1',
			'/topology',
			array(
				'methods'             => 'GET',
				'permission_callback' => static fn (): bool => is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW ),
				'callback'            => static function ( $req ) {
					$env = sanitize_key( (string) $req->get_param( 'env' ) );
					$env = in_array( $env, array( VulnHub_AWS_Environment::PROD, VulnHub_AWS_Environment::NONPROD ), true ) ? $env : '';

					return rest_ensure_response( VulnHub_AWS_Network::estate_flow( $env ) );
				},
			)
		);

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

/**
 * The Cloud Network map page registers on its own hooks, independent of the
 * connector registry (it only reads the stored network tables).
 */
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-environment.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-network.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-exposure.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-coverage.php';
VulnHub_AWS_Coverage::init();
// Account number -> name, reported by Plerion and the AWS sign-in.
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-account-names.php';
VulnHub_AWS_Account_Names::init();
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-network-page.php';
VulnHub_AWS_Network_Page::init();

/**
 * AWS cost: a read-only snapshot of spend and usage (Cost Explorer,
 * CloudWatch, the price list), the suggestions worked out from it, and the
 * two pages that show them. Refreshed on demand -- Cost Explorer bills per
 * request -- through the cron runner.
 */
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-cost-store.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-cost-collector.php';
add_action( 'init', array( 'VulnHub_AWS_Cost_Store', 'install' ), 5 );
VulnHub_AWS_Cost_Collector::init();
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-cost-recs.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-cost-pages.php';
VulnHub_AWS_Cost_Pages::init();

/**
 * How each EC2 instance runs (always on, scheduled, auto-scaling, off), read
 * from the cost snapshot and the capture, and what that does to its online
 * dot. See VulnHub_AWS_Run_Profile.
 */
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-run-profile.php';
VulnHub_AWS_Run_Profile::init();

/**
 * Serverless entry points: the API Gateway routes and Lambda function URLs
 * that anyone on the internet can invoke, the function behind each, and what
 * that function's role can reach. Kept in its own table because
 * `vh_vulnhub_asset_exposure` is keyed by an asset row and a Lambda function
 * is not an asset -- writing it there would silently drop every row.
 */
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-serverless.php';
add_action( 'init', array( 'VulnHub_AWS_Serverless', 'install' ), 5 );

/*
 * Domain names. Shared on purpose: the serverless card uses it first, but
 * the same store answers "what is this server called" for the network map
 * and the asset register, so it does not belong to any one page.
 */
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-domains.php';
add_action( 'init', array( 'VulnHub_AWS_Domains', 'install' ), 5 );

/*
 * Operator-supplied names and edge coverage. Not AWS, but they answer the
 * same question and feed the same store, so they sit beside it.
 */
require_once VULNHUB_AWS_DIR . 'includes/class-vh-domain-import.php';
add_action( 'init', array( 'VulnHub_Domain_Import', 'install' ), 5 );
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-serverless-page.php';
VulnHub_AWS_Serverless_Page::init();

/*
 * Internet exposure: the public surface end to end, across DNS, the CDN,
 * the WAF export and AWS. Loaded after the serverless page because it
 * borrows that page's icon vocabulary.
 */
require_once VULNHUB_AWS_DIR . 'includes/class-vh-internet-exposure-page.php';
VulnHub_Internet_Exposure_Page::init();
