<?php
/**
 * Connector registry.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Connectors {

	/** @var array<string,Connector> */
	private array $items = array();

	public function register( Connector $connector ): void {
		$this->items[ $connector->id() ] = $connector;
	}

	public function get( string $id ): ?Connector {
		return $this->items[ $id ] ?? null;
	}

	public function has( string $id ): bool {
		return isset( $this->items[ $id ] );
	}

	/**
	 * @return array<string,Connector>
	 */
	public function all(): array {
		return $this->items;
	}

	/**
	 * @return array<string,Connector>
	 */
	public function by_category( string $category ): array {
		return array_filter(
			$this->items,
			static fn( Connector $c ): bool => $c->category() === $category
		);
	}

	/**
	 * Connectors that are enabled and eligible for a scheduled run.
	 *
	 * @return array<string,Connector>
	 */
	public function schedulable(): array {
		return array_filter(
			$this->items,
			static fn( Connector $c ): bool => $c->supports_sync() && $c->is_enabled()
		);
	}

	/**
	 * Category labels for the Integrations screen.
	 *
	 * @return array<string,string>
	 */
	public static function categories(): array {
		return array(
			'vulnerability' => __( 'Vulnerability data', 'vulnhub' ),
			'identity'      => __( 'Identity &amp; device', 'vulnhub' ),
			'cmdb'          => __( 'CMDB &amp; documentation', 'vulnhub' ),
			'itsm'          => __( 'Ticketing &amp; ITSM', 'vulnhub' ),
			'auth'          => __( 'Authentication &amp; SSO', 'vulnhub' ),
			'email'         => __( 'Email &amp; notifications', 'vulnhub' ),
			'other'         => __( 'Other', 'vulnhub' ),
		);
	}
}

