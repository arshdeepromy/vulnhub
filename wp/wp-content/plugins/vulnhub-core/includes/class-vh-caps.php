<?php
/**
 * Roles and capabilities.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Caps {

	public const MANAGE            = 'vulnhub_manage';
	public const VIEW              = 'vulnhub_view';
	public const TRIAGE            = 'vulnhub_triage';
	public const RAISE_TICKET      = 'vulnhub_raise_ticket';
	public const REQUEST_EXCEPTION = 'vulnhub_request_exception';
	public const APPROVE_EXCEPTION = 'vulnhub_approve_exception';
	public const RUN_SYNC          = 'vulnhub_run_sync';
	public const VIEW_AUDIT        = 'vulnhub_view_audit';

	/**
	 * @return array<string,string>
	 */
	public static function all(): array {
		return array(
			self::VIEW              => __( 'View dashboards, assets and findings', 'vulnhub' ),
			self::TRIAGE            => __( 'Triage findings (assign, comment, change state)', 'vulnhub' ),
			self::RAISE_TICKET      => __( 'Raise and update Jira tickets', 'vulnhub' ),
			self::REQUEST_EXCEPTION => __( 'Request a vulnerability exception', 'vulnhub' ),
			self::APPROVE_EXCEPTION => __( 'Approve or reject exceptions', 'vulnhub' ),
			self::RUN_SYNC          => __( 'Trigger connector syncs on demand', 'vulnhub' ),
			self::VIEW_AUDIT        => __( 'View the audit trail', 'vulnhub' ),
			self::MANAGE            => __( 'Manage integrations, automation and platform settings', 'vulnhub' ),
		);
	}

	/**
	 * @return array<string,array{label:string,caps:string[]}>
	 */
	public static function roles(): array {
		return array(
			'vulnhub_admin'    => array(
				'label' => __( 'VulnHub Administrator', 'vulnhub' ),
				'caps'  => array_keys( self::all() ),
			),
			'vulnhub_analyst'  => array(
				'label' => __( 'VulnHub Analyst', 'vulnhub' ),
				'caps'  => array(
					self::VIEW,
					self::TRIAGE,
					self::RAISE_TICKET,
					self::REQUEST_EXCEPTION,
					self::RUN_SYNC,
					self::VIEW_AUDIT,
				),
			),
			'vulnhub_approver' => array(
				'label' => __( 'VulnHub Risk Approver', 'vulnhub' ),
				'caps'  => array(
					self::VIEW,
					self::REQUEST_EXCEPTION,
					self::APPROVE_EXCEPTION,
					self::VIEW_AUDIT,
				),
			),
			'vulnhub_viewer'   => array(
				'label' => __( 'VulnHub Viewer', 'vulnhub' ),
				'caps'  => array( self::VIEW ),
			),
		);
	}

	public static function install_roles(): void {
		foreach ( self::roles() as $slug => $def ) {
			$caps = array( 'read' => true );
			foreach ( $def['caps'] as $cap ) {
				$caps[ $cap ] = true;
			}
			remove_role( $slug );
			add_role( $slug, $def['label'], $caps );
		}

		// Site administrators get everything.
		$admin = get_role( 'administrator' );
		if ( $admin ) {
			foreach ( array_keys( self::all() ) as $cap ) {
				$admin->add_cap( $cap );
			}
		}

		update_option( 'vulnhub_roles_version', VULNHUB_VERSION, false );
	}

	public static function maybe_install_roles(): void {
		if ( get_option( 'vulnhub_roles_version' ) !== VULNHUB_VERSION ) {
			self::install_roles();
		}
	}

	/**
	 * Capability check that degrades gracefully for logged-out REST calls.
	 */
	public static function can( string $cap ): bool {
		return is_user_logged_in() && current_user_can( $cap );
	}
}

