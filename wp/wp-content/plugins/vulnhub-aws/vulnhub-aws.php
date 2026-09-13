<?php
/**
 * Plugin Name:       VulnHub AWS
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Reads network exposure straight from the AWS account: which instances the internet can actually reach, and on which ports.
 * Version:           0.1.0
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
 * At 0.1.0 this carries the signing layer and a read-only Inspector probe,
 * which exists to settle one question before any more is built: whether
 * Amazon Inspector is already computing network reachability for this account.
 * If it is, pulling its findings is far less work than deriving reachability
 * from security groups, route tables and gateways ourselves.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_AWS_DIR', plugin_dir_path( __FILE__ ) );

require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-sigv4.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-client.php';
require_once VULNHUB_AWS_DIR . 'includes/class-vh-aws-inspector.php';
