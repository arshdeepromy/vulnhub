<?php
/**
 * The Intune Data Warehouse connector.
 *
 * Deliberately a reader before it is an importer. The warehouse's shape
 * differs by tenant -- which collections exist, and what is in them, depends
 * on licensing and on which Intune features are in use -- so the first thing
 * this does is ask the feed what it has and write that down. Mapping rows into
 * the asset register comes after somebody has looked at the answer, rather
 * than from a schema guessed in advance and wrong in the details.
 *
 * @package VulnHub\IntuneDW
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use VulnHub\Core\Connector;

final class VulnHub_Intune_DW_Connector extends Connector {

	/** Where the last discovery run is kept, for the admin screen. */
	private const SURVEY_OPTION = 'vh_intune_dw_survey';

	/**
	 * Collections worth counting on every run.
	 *
	 * The warehouse has dozens, most of them dimensions with a handful of
	 * rows. These are the ones that say something about the estate, so they
	 * get counted every time; everything else is listed but not opened.
	 *
	 * @var string[]
	 */
	private const INTERESTING = array(
		'devices',
		'users',
		'mdmDeviceInventoryHistories',
		'devicePropertyHistory',
		'applicationInventory',
		'enrollmentActivities',
		'compliancePolicies',
		'complianceStates',
		'managementStates',
		'ownerTypes',
		'deviceTypes',
	);

	public function id(): string {
		return 'intune-dw';
	}

	public function label(): string {
		return __( 'Intune Data Warehouse', 'vulnhub' );
	}

	public function category(): string {
		return 'inventory';
	}

	public function description(): string {
		return __( 'Reads the Intune Data Warehouse OData feed — the reporting model behind Intune, refreshed daily, with about a month of history. Read-only.', 'vulnhub' );
	}

	public function default_interval(): string {
		/*
		 * The warehouse refreshes once a day. Asking more often than that
		 * returns the same rows and spends the tenant's throttle budget on
		 * nothing.
		 */
		return 'daily';
	}

	public function supports_mock(): bool {
		return false;
	}

	/**
	 * What the operator has to create, and where.
	 *
	 * @return array<int,array<string,string>>
	 */
	public static function required_permissions(): array {
		return array(
			array(
				'name'    => 'get_data_warehouse',
				'why'     => __( 'Microsoft Intune API → Application permissions → "Get data warehouse information from Microsoft Intune". This is the only permission the feed needs.', 'vulnhub' ),
				'consent' => __( 'Admin consent required', 'vulnhub' ),
			),
		);
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array(
			array(
				'key'  => 'setup',
				'type' => 'note',
				'help' => __(
					'In <strong>Entra admin centre → App registrations</strong> create an app, then under <strong>API permissions → Add a permission → Microsoft Intune API → Application permissions</strong> tick <strong>get_data_warehouse</strong> and grant admin consent. Add a client secret and copy its <em>Value</em> straight away — it is shown once. The feed URL is in <strong>Intune admin centre → Reports → Intune Data warehouse</strong>. This connector only reads.',
					'vulnhub'
				),
			),
			array(
				'key'         => 'feed_url',
				'label'       => __( 'Data Warehouse feed URL', 'vulnhub' ),
				'type'        => 'url',
				'required'    => true,
				'placeholder' => 'https://fef.msuc03.manage.microsoft.com/ReportingService/DataWarehouseFEService?api-version=v1.0',
				'help'        => __( 'Paste it exactly as the Intune admin centre shows it, query string and all — the version is read off it and the rest is trimmed.', 'vulnhub' ),
			),
			array(
				'key'         => 'tenant_id',
				'label'       => __( 'Directory (tenant) ID', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => '00000000-0000-0000-0000-000000000000',
				'help'        => __( 'From the app registration Overview page. The domain (contoso.onmicrosoft.com) works too.', 'vulnhub' ),
			),
			array(
				'key'         => 'client_id',
				'label'       => __( 'Application (client) ID', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => '00000000-0000-0000-0000-000000000000',
			),
			array(
				'key'      => 'client_secret',
				'label'    => __( 'Client secret', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'The secret <em>Value</em>, not the Secret ID. Encrypted at rest. Leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'         => 'scope',
				'label'       => __( 'Token scope', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => 'https://api.manage.microsoft.com/.default',
				'help'        => __( 'Leave blank unless a token request fails in a way that names the audience. The connector asks for a v2 token first and falls back to the older resource form by itself.', 'vulnhub' ),
			),
			array(
				'key'            => 'count_rows',
				'label'          => __( 'Row counts', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => true,
				'checkbox_label' => __( 'Count the rows in the collections worth counting', 'vulnhub' ),
				'help'           => __( 'Reads each of a short list of collections whole so the survey can say how many rows are actually there. Turn it off to list the collections only.', 'vulnhub' ),
			),
			array(
				'key'     => 'max_pages',
				'label'   => __( 'Page cap', 'vulnhub' ),
				'type'    => 'number',
				'default' => 50,
				'help'    => __( 'Stops a single collection from running away. Counted and reported rather than silently truncated.', 'vulnhub' ),
			),
		);
	}

	/**
	 * @return array{ok:bool,message:string}
	 */
	public function test_connection(): array {
		$client = $this->client();

		if ( ! $client || ! $client->is_configured() ) {
			return array(
				'ok'      => false,
				'message' => __( 'The feed URL, tenant id, client id and client secret are all required.', 'vulnhub' ),
			);
		}

		// Token first, and said separately: a refused token and a refused
		// read are different problems with different fixes.
		$client->forget_token();
		$token = $client->token();

		if ( ! $token['ok'] ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: what Entra said. */
					__( 'Could not get a token: %s', 'vulnhub' ),
					$token['error']
				),
			);
		}

		$found = $client->collections();

		if ( ! $found['ok'] ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: what the service said. */
					__( 'Token accepted, but the feed refused to list its collections: %s', 'vulnhub' ),
					$found['error']
				),
			);
		}

		$names = $found['names'];

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: number of collections, 2: a few of their names. */
				__( 'Connected. The feed offers %1$d collections, including %2$s. Run a sync to survey what is in them.', 'vulnhub' ),
				count( $names ),
				implode( ', ', array_slice( array_intersect( self::INTERESTING, $names ) ?: $names, 0, 5 ) )
			),
		);
	}

	/**
	 * Survey the feed: what collections exist, and how much is in the ones
	 * that matter.
	 *
	 * @param array<string,mixed> $args Unused.
	 * @return array<string,mixed>
	 */
	protected function do_sync( array $args = array() ): array {
		$client = $this->client();

		if ( ! $client || ! $client->is_configured() ) {
			return array( 'ok' => false, 'message' => __( 'Not configured.', 'vulnhub' ) );
		}

		$found = $client->collections();

		if ( ! $found['ok'] ) {
			return array( 'ok' => false, 'message' => $found['error'] );
		}

		$names = $found['names'];
		$this->log( sprintf( 'Feed offers %d collections: %s', count( $names ), implode( ', ', $names ) ) );

		$survey = array(
			'at'          => vh_now(),
			'feed'        => $client->feed(),
			'collections' => $names,
			'counts'      => array(),
			'columns'     => array(),
			'capped'      => array(),
		);

		if ( $this->get( 'count_rows', true ) ) {
			$cap = max( 1, min( 500, (int) $this->get( 'max_pages', 50 ) ) );

			foreach ( self::INTERESTING as $collection ) {
				if ( ! in_array( $collection, $names, true ) ) {
					continue;
				}

				$columns = array();

				$read = $client->each(
					$collection,
					function ( array $rows ) use ( &$columns ): void {
						// The first row names the columns. Recorded once so
						// the survey says what a collection actually holds in
						// this tenant, not what the documentation says.
						if ( ! $columns && isset( $rows[0] ) ) {
							$columns = array_keys( (array) $rows[0] );
						}
					},
					$cap
				);

				if ( ! $read['ok'] ) {
					$this->log( sprintf( '%s: %s', $collection, $read['error'] ) );
					$survey['counts'][ $collection ] = -1;
					continue;
				}

				$survey['counts'][ $collection ]  = $read['rows'];
				$survey['columns'][ $collection ] = $columns;

				if ( $read['pages'] >= $cap ) {
					$survey['capped'][] = $collection;
				}

				$this->log( sprintf( '%s: %d rows over %d page(s), %d columns', $collection, $read['rows'], $read['pages'], count( $columns ) ) );
			}
		}

		update_option( self::SURVEY_OPTION, $survey, false );

		$counted = array_filter( $survey['counts'], static fn( int $n ): bool => $n > 0 );
		arsort( $counted );

		$said = array();

		foreach ( array_slice( $counted, 0, 4, true ) as $collection => $rows ) {
			$said[] = sprintf( '%s %s', number_format_i18n( $rows ), $collection );
		}

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: collections offered, 2: the biggest few, 3: API calls. */
				__( '%1$d collections offered. Read %2$s. %3$d API calls.', 'vulnhub' ),
				count( $names ),
				$said ? implode( ', ', $said ) : __( 'nothing — row counts are off', 'vulnhub' ),
				$client->calls()
			),
			'counts'  => $survey['counts'],
		);
	}

	/** The last survey, for the admin screen and for whoever maps this next. */
	public static function survey(): array {
		$survey = get_option( self::SURVEY_OPTION, array() );

		return is_array( $survey ) ? $survey : array();
	}

	private function client(): ?VulnHub_Intune_DW_Client {
		$feed = (string) $this->get( 'feed_url' );

		if ( '' === trim( $feed ) ) {
			return null;
		}

		return new VulnHub_Intune_DW_Client(
			$feed,
			(string) $this->get( 'tenant_id' ),
			(string) $this->get( 'client_id' ),
			$this->secret( 'client_secret' ),
			(string) $this->get( 'scope' ),
			function ( string $message ): void {
				$this->log( $message );
			}
		);
	}
}
