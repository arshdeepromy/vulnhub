<?php
/**
 * Microsoft Intune + Entra ID connector.
 *
 * Order of work in do_sync() is not arbitrary:
 *   1. people first — a device cannot point at a person who does not exist yet;
 *   2. group memberships (optional) — needed before team resolution when the
 *      operator derives teams from group names;
 *   3. devices — joined to their primary user on the immutable directory GUID;
 *   4. the primary user's UPN written into raw['intune']['userPrincipalName'],
 *      which is the exact key core's `person_from_intune` mapping rule reads;
 *   5. asset_type derived from operatingSystem;
 *   6. team and location resolved onto the PERSON. Core's mapping engine
 *      propagates those to the person's devices — this connector never writes
 *      owner_person_id / team_id / location_id onto an asset.
 *
 * @package VulnHub\Intune
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use VulnHub\Core\Repo;

/**
 * The connector core registers as `intune`.
 */
final class VulnHub_Intune_Connector extends \VulnHub\Core\Connector {

	/**
	 * Source key used for every person and asset this connector writes.
	 */
	public const SOURCE = 'intune';

	/**
	 * Properties GET /users must be asked for explicitly.
	 *
	 * Graph returns only a limited default set (businessPhones, displayName,
	 * givenName, id, jobTitle, mail, mobilePhone, officeLocation,
	 * preferredLanguage, surname, userPrincipalName). Everything this platform
	 * cares about for ownership — department, city, state, country,
	 * companyName, employeeId, usageLocation, accountEnabled, userType — is
	 * NOT in that set and comes back missing unless $select names it.
	 */
	private const USER_SELECT = array(
		'id',
		'userPrincipalName',
		'displayName',
		'givenName',
		'surname',
		'mail',
		'jobTitle',
		'department',
		'officeLocation',
		'city',
		'state',
		'country',
		'companyName',
		'employeeId',
		'usageLocation',
		'accountEnabled',
		'userType',
	);

	/**
	 * Application permissions the Entra app registration needs. All three
	 * require tenant administrator consent.
	 *
	 * @return array<int,array{name:string,why:string,consent:string}>
	 */
	public static function required_permissions(): array {
		return array(
			array(
				'name'    => 'DeviceManagementManagedDevices.Read.All',
				'why'     => __( 'Read Intune managed devices (GET /deviceManagement/managedDevices).', 'vulnhub' ),
				'consent' => __( 'Admin consent required', 'vulnhub' ),
			),
			array(
				'name'    => 'User.Read.All',
				'why'     => __( 'Read every user profile and manager (GET /users).', 'vulnhub' ),
				'consent' => __( 'Admin consent required', 'vulnhub' ),
			),
			array(
				'name'    => 'Group.Read.All',
				'why'     => __( 'Read groups and memberships — only needed when group sync is enabled.', 'vulnhub' ),
				'consent' => __( 'Admin consent required', 'vulnhub' ),
			),
			array(
				'name'    => 'Organization.Read.All',
				'why'     => __( 'Optional: lets the connection test name the tenant (GET /organization). Directory.Read.All also works.', 'vulnhub' ),
				'consent' => __( 'Admin consent required', 'vulnhub' ),
			),
		);
	}

	/**
	 * Directory GUID (lowercased) => user summary, built during the people pass
	 * and used to join devices to their owner.
	 *
	 * @var array<string,array<string,mixed>>
	 */
	private array $user_index = array();

	/**
	 * Group display names collected per directory GUID.
	 *
	 * @var array<string,array<int,string>>
	 */
	private array $group_index = array();

	/**
	 * Devices seen with no primary user, for the run log and the admin screen.
	 *
	 * @var array<int,string>
	 */
	private array $userless = array();

	/**
	 * Cached client for the current run.
	 *
	 * @var VulnHub_Intune_Client|null
	 */
	private ?VulnHub_Intune_Client $client = null;

	/* -----------------------------------------------------------------
	 * Identity
	 * --------------------------------------------------------------- */

	/**
	 * Machine id.
	 *
	 * @return string
	 */
	public function id(): string {
		return self::SOURCE;
	}

	/**
	 * Human label.
	 *
	 * @return string
	 */
	public function label(): string {
		return __( 'Microsoft Intune & Entra ID', 'vulnhub' );
	}

	/**
	 * One-line description for the Integrations screen.
	 *
	 * @return string
	 */
	public function description(): string {
		return __( 'Imports Entra ID people and Intune managed devices, and supplies the primary-user signal that resolves workstation ownership.', 'vulnhub' );
	}

	/**
	 * Dashicon slug.
	 *
	 * @return string
	 */
	public function icon(): string {
		return 'dashicons-groups';
	}

	/**
	 * Connector category.
	 *
	 * @return string
	 */
	public function category(): string {
		return 'identity';
	}

	/**
	 * Default schedule.
	 *
	 * @return string
	 */
	public function default_interval(): string {
		return 'vh_12hours';
	}

	/**
	 * Settings fields.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array(
			array(
				'key'         => 'tenant_id',
				'label'       => __( 'Directory (tenant) ID', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => '00000000-0000-0000-0000-000000000000',
				'help'        => __( 'From Entra admin centre → App registrations → Overview. A verified domain name also works.', 'vulnhub' ),
			),
			array(
				'key'         => 'client_id',
				'label'       => __( 'Application (client) ID', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => '00000000-0000-0000-0000-000000000000',
				'help'        => __( 'The app registration this connector authenticates as.', 'vulnhub' ),
			),
			array(
				'key'      => 'client_secret',
				'label'    => __( 'Client secret', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'Client secret VALUE, not the secret ID. Encrypted at rest; leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'     => 'base_url',
				'label'   => __( 'Graph base URL', 'vulnhub' ),
				'type'    => 'url',
				'default' => 'https://graph.microsoft.com/v1.0',
				'help'    => __( 'Change only for sovereign clouds (US Gov, China, Germany) or to pin the beta endpoint.', 'vulnhub' ),
			),
			array(
				'key'            => 'sync_groups',
				'label'          => __( 'Group memberships', 'vulnhub' ),
				'type'           => 'checkbox',
				'checkbox_label' => __( 'Also sync group memberships', 'vulnhub' ),
				'default'        => 0,
				'help'           => __( 'Adds one batched Graph call per 20 people. Needed if teams are derived from group names.', 'vulnhub' ),
			),
			array(
				'key'     => 'team_source',
				'label'   => __( 'Team source', 'vulnhub' ),
				'type'    => 'select',
				'options' => array(
					'department'   => __( 'Entra ID department', 'vulnhub' ),
					'group-prefix' => __( 'Group name with a given prefix', 'vulnhub' ),
					'office'       => __( 'Office location', 'vulnhub' ),
				),
				'default' => 'department',
				'help'    => __( 'Where a person\'s team name comes from. Their devices inherit it through the ownership mapping engine.', 'vulnhub' ),
			),
			array(
				'key'         => 'group_prefix',
				'label'       => __( 'Group name prefix', 'vulnhub' ),
				'type'        => 'text',
				'default'     => 'TEAM-',
				'placeholder' => 'TEAM-',
				'help'        => __( 'Used when team source is "group name with a prefix". The prefix is stripped from the team name. Requires group sync.', 'vulnhub' ),
			),
			array(
				'key'            => 'verbose_log',
				'label'          => __( 'Verbose logging', 'vulnhub' ),
				'type'           => 'checkbox',
				'checkbox_label' => __( 'Also mirror run log lines to debug.log', 'vulnhub' ),
				'default'        => 0,
				'help'           => __( 'For troubleshooting only. The run log in Sync activity is always written regardless.', 'vulnhub' ),
			),
			array(
				'key'     => 'page_size',
				'label'   => __( 'Page size', 'vulnhub' ),
				'type'    => 'number',
				'default' => 999,
				'help'    => __( 'Records per Graph page ($top). Graph may silently cap this per endpoint.', 'vulnhub' ),
			),
		);
	}

	/* -----------------------------------------------------------------
	 * Client
	 * --------------------------------------------------------------- */

	/**
	 * Build (once per run) the Graph client, live or mock.
	 *
	 * @return VulnHub_Intune_Client
	 */
	private function client(): VulnHub_Intune_Client {
		if ( $this->client instanceof VulnHub_Intune_Client ) {
			return $this->client;
		}

		$base_url = (string) $this->get( 'base_url', 'https://graph.microsoft.com/v1.0' );
		$base_url = '' !== trim( $base_url ) ? trim( $base_url ) : 'https://graph.microsoft.com/v1.0';

		$mock = null;
		if ( $this->is_mock() ) {
			// Deliberately small pages so the nextLink loop is genuinely
			// exercised rather than satisfied by a single response.
			$mock = new VulnHub_Intune_Mock_Graph( $base_url, min( 25, max( 5, $this->page_size() ) ) );
		}

		$this->client = new VulnHub_Intune_Client(
			$this->http,
			array(
				'tenant_id'     => (string) $this->get( 'tenant_id', '' ),
				'client_id'     => (string) $this->get( 'client_id', '' ),
				'client_secret' => $this->secret( 'client_secret' ),
				'base_url'      => $base_url,
			),
			array( $this, 'log' ),
			$mock
		);

		return $this->client;
	}

	/**
	 * Configured page size, clamped to something Graph will accept.
	 *
	 * @return int
	 */
	private function page_size(): int {
		return max( 1, min( 999, $this->settings->get_int( $this->id(), 'page_size', 999 ) ) );
	}

	/* -----------------------------------------------------------------
	 * Connection test
	 * --------------------------------------------------------------- */

	/**
	 * Verify credentials and report which permissions look granted.
	 *
	 * A 403 on one endpoint while another succeeds is by far the most common
	 * misconfiguration (consent granted for some permissions but not all), so
	 * each endpoint is probed and reported separately rather than failing the
	 * whole test on the first error.
	 *
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	public function test_connection(): array {
		if ( $this->is_mock() ) {
			$mock   = new VulnHub_Intune_Mock_Graph( (string) $this->get( 'base_url', 'https://graph.microsoft.com/v1.0' ), 25 );
			$counts = $mock->counts();
			$tenant = $mock->tenant();

			return array(
				'ok'      => true,
				'message' => sprintf(
					/* translators: 1: tenant name, 2: user count, 3: device count, 4: userless device count. */
					__( 'Mock mode: generated tenant "%1$s" with %2$d users and %3$d Intune-managed devices (%4$d of them deliberately have no primary user). No credentials are used.', 'vulnhub' ),
					(string) $tenant['displayName'],
					(int) $counts['users'],
					(int) $counts['devices'],
					(int) $counts['userless']
				),
				'detail'  => array(
					'tenant'   => (string) $tenant['displayName'],
					'users'    => (int) $counts['users'],
					'devices'  => (int) $counts['devices'],
					'userless' => (int) $counts['userless'],
				),
			);
		}

		$client = $this->client();

		try {
			$client->token();
		} catch ( Throwable $e ) {
			return array(
				'ok'      => false,
				'message' => $e->getMessage(),
			);
		}

		// Cheap tenant identity call. Note that /organization needs
		// Organization.Read.All or Directory.Read.All — NOT one of the three
		// sync permissions — so a 403 here is informational, not fatal.
		$org         = $client->probe( 'organization', array( '$select' => 'displayName,id' ) );
		$tenant_name = __( '(name unavailable — grant Organization.Read.All to show it)', 'vulnhub' );
		if ( $org['ok'] ) {
			$data = $client->get( 'organization', array( '$select' => 'displayName,id' ) );
			$tenant_name = (string) ( $data['value'][0]['displayName'] ?? $tenant_name );
		}

		$users   = $client->probe( 'users', array( '$top' => 1, '$select' => 'id,userPrincipalName' ) );
		$devices = $client->probe( 'deviceManagement/managedDevices', array( '$top' => 1 ) );

		$lines = array(
			$this->permission_line( 'User.Read.All', 'GET /users', $users ),
			$this->permission_line( 'DeviceManagementManagedDevices.Read.All', 'GET /deviceManagement/managedDevices', $devices ),
		);

		if ( $this->settings->get_bool( $this->id(), 'sync_groups' ) ) {
			$groups  = $client->probe( 'groups', array( '$top' => 1, '$select' => 'id,displayName' ) );
			$lines[] = $this->permission_line( 'Group.Read.All', 'GET /groups', $groups );
		}

		$ok = $users['ok'] && $devices['ok'];

		return array(
			'ok'      => $ok,
			'message' => sprintf(
				/* translators: 1: tenant display name, 2: per-endpoint results. */
				__( 'Token acquired for tenant "%1$s". %2$s', 'vulnhub' ),
				$tenant_name,
				implode( ' ', $lines )
			),
			'detail'  => array(
				'tenant'       => $tenant_name,
				'organization' => $org,
				'users'        => $users,
				'devices'      => $devices,
			),
		);
	}

	/**
	 * Render one permission probe result.
	 *
	 * @param string                                          $permission Permission name.
	 * @param string                                          $endpoint   Endpoint probed.
	 * @param array{ok:bool,status:int,message:string,count:int} $result  Probe result.
	 * @return string
	 */
	private function permission_line( string $permission, string $endpoint, array $result ): string {
		if ( $result['ok'] ) {
			/* translators: 1: endpoint, 2: permission name. */
			return sprintf( __( '%1$s OK (%2$s granted).', 'vulnhub' ), $endpoint, $permission );
		}

		if ( 403 === (int) $result['status'] ) {
			/* translators: 1: endpoint, 2: permission name. */
			return sprintf( __( '%1$s returned 403 — %2$s is missing or has not been admin-consented.', 'vulnhub' ), $endpoint, $permission );
		}

		/* translators: 1: endpoint, 2: HTTP status, 3: error message. */
		return sprintf( __( '%1$s failed (HTTP %2$d): %3$s', 'vulnhub' ), $endpoint, (int) $result['status'], $result['message'] );
	}

	/* -----------------------------------------------------------------
	 * Sync
	 * --------------------------------------------------------------- */

	/**
	 * Run the sync.
	 *
	 * @param array<string,mixed> $args Sync options.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		$this->user_index  = array();
		$this->group_index = array();
		$this->userless    = array();
		$this->client      = null;

		$client = $this->client();

		// 1. People first: a device cannot be joined to a person who is not
		//    in the database yet.
		$people = $this->sync_people( $client );

		// 2. Group memberships, before team resolution needs them.
		$groups = 0;
		if ( $this->settings->get_bool( $this->id(), 'sync_groups' ) ) {
			$groups = $this->sync_group_memberships( $client );
		} else {
			$this->log( 'Group membership sync is off; skipping.' );
		}

		// 3-5. Devices, their primary user, and their derived asset type.
		$devices = $this->sync_devices( $client );

		// 6. Team and location go on the PERSON. Core's mapping engine pushes
		//    them down to that person's devices; we must never set them on an
		//    asset ourselves.
		$placed = $this->resolve_people_placement();

		$message = sprintf(
			/* translators: 1: people, 2: devices, 3: devices without a user, 4: people given a team/location, 5: request count. */
			__( 'Synced %1$d people and %2$d Intune devices (%3$d with no primary user). Resolved team/location for %4$d people. %5$d Graph requests.', 'vulnhub' ),
			$people,
			$devices,
			count( $this->userless ),
			$placed,
			$client->request_count()
		);

		if ( $groups ) {
			$message .= ' ' . sprintf(
				/* translators: %d: number of people whose group memberships were imported. */
				__( 'Group memberships imported for %d people.', 'vulnhub' ),
				$groups
			);
		}

		update_option(
			'vulnhub_intune_last_summary',
			array(
				'at'       => vh_now(),
				'mock'     => $client->is_mock(),
				'people'   => $people,
				'devices'  => $devices,
				'userless' => array_slice( $this->userless, 0, 50 ),
				'requests' => $client->request_count(),
			),
			false
		);

		return array(
			'ok'      => true,
			'message' => $message,
		);
	}

	/* ---------------- People ---------------- */

	/**
	 * Import Entra ID users.
	 *
	 * @param VulnHub_Intune_Client $client Graph client.
	 * @return int Number of people upserted.
	 */
	private function sync_people( VulnHub_Intune_Client $client ): int {
		$count = 0;
		$query = array(
			'$select' => implode( ',', self::USER_SELECT ),
			'$expand' => 'manager($select=id,displayName,userPrincipalName)',
			'$top'    => $this->page_size(),
		);

		// No ConsistencyLevel header here: it is only required for advanced
		// queries ($count / $search / advanced $filter / $orderby), and $expand
		// is not supported alongside advanced queries at all. Where this
		// connector does use an advanced query — the OData cast in the group
		// membership batch — the header is set explicitly, and re-sent on every
		// page, because Graph does not carry custom headers into a nextLink.
		$handler = function ( array $items ) use ( &$count ): void {
			foreach ( $items as $user ) {
				if ( $this->import_person( (array) $user ) ) {
					++$count;
				}
			}
		};

		try {
			$client->paginate( 'users', $query, array(), $handler );
		} catch ( RuntimeException $e ) {
			// Some tenants (and the beta endpoint) reject a nested $select
			// inside $expand. Losing the manager is far better than losing the
			// whole people sync, so fall back and carry on. Upserts are
			// idempotent, so re-reading page 1 costs nothing.
			if ( ! str_contains( $e->getMessage(), '400' ) ) {
				throw $e;
			}
			$this->log( 'Graph rejected $expand=manager($select=…); retrying without the nested $select.' );
			$query['$expand'] = 'manager';
			$client->paginate( 'users', $query, array(), $handler );
		}

		$this->log( sprintf( 'People: %d imported, %d in the join index.', $count, count( $this->user_index ) ) );

		return $count;
	}

	/**
	 * Normalise and store one Graph user.
	 *
	 * @param array<string,mixed> $user Graph user object.
	 * @return bool True when the person was written.
	 */
	private function import_person( array $user ): bool {
		$uid = trim( (string) ( $user['id'] ?? '' ) );
		$upn = strtolower( trim( (string) ( $user['userPrincipalName'] ?? '' ) ) );

		if ( '' === $uid || '' === $upn ) {
			$this->bump( 'skipped' );
			return false;
		}

		$manager     = is_array( $user['manager'] ?? null ) ? (array) $user['manager'] : array();
		$office      = (string) ( $user['officeLocation'] ?? '' );
		$department  = (string) ( $user['department'] ?? '' );
		$mail        = strtolower( trim( (string) ( $user['mail'] ?? '' ) ) );

		$result = Repo::upsert_person(
			array(
				'source'          => self::SOURCE,
				'source_uid'      => $uid,
				'upn'             => $upn,
				'email'           => '' !== $mail ? $mail : $upn,
				'display_name'    => (string) ( $user['displayName'] ?? '' ),
				'given_name'      => (string) ( $user['givenName'] ?? '' ),
				'surname'         => (string) ( $user['surname'] ?? '' ),
				'job_title'       => (string) ( $user['jobTitle'] ?? '' ),
				'department'      => $department,
				'company'         => (string) ( $user['companyName'] ?? '' ),
				'employee_id'     => (string) ( $user['employeeId'] ?? '' ),
				'manager_upn'     => strtolower( (string) ( $manager['userPrincipalName'] ?? '' ) ),
				'manager_name'    => (string) ( $manager['displayName'] ?? '' ),
				'office_location' => $office,
				'city'            => (string) ( $user['city'] ?? '' ),
				'state'           => (string) ( $user['state'] ?? '' ),
				'country'         => (string) ( $user['country'] ?? '' ),
				'usage_location'  => (string) ( $user['usageLocation'] ?? '' ),
				'is_active'       => (bool) ( $user['accountEnabled'] ?? true ),
				'raw'             => array( 'entra' => $user ),
			)
		);

		$this->bump( 'processed' );
		$this->bump( $result['created'] ? 'created' : 'updated' );

		// The join index is keyed on the immutable directory GUID.
		$this->user_index[ strtolower( $uid ) ] = array(
			'person_id'  => (int) $result['id'],
			'upn'        => $upn,
			'department' => $department,
			'office'     => $office,
			'city'       => (string) ( $user['city'] ?? '' ),
			'country'    => (string) ( $user['country'] ?? '' ),
		);

		return true;
	}

	/* ---------------- Groups ---------------- */

	/**
	 * Import group memberships into each person's `groups` field.
	 *
	 * Uses POST /$batch (20 requests maximum per the documentation) so a
	 * thousand-person tenant costs fifty round trips instead of a thousand.
	 *
	 * @param VulnHub_Intune_Client $client Graph client.
	 * @return int Number of people whose memberships were written.
	 */
	private function sync_group_memberships( VulnHub_Intune_Client $client ): int {
		if ( ! $this->user_index ) {
			return 0;
		}

		$requests = array();
		foreach ( $this->user_index as $uid => $info ) {
			// The OData cast to microsoft.graph.group is an advanced query, so
			// ConsistencyLevel: eventual and $count=true are both required.
			$requests[ $uid ] = sprintf(
				'/users/%s/memberOf/microsoft.graph.group?$select=id,displayName&$count=true&$top=100',
				rawurlencode( $uid )
			);
		}

		$responses = $client->batch( $requests, array( 'ConsistencyLevel' => 'eventual' ) );
		$written   = 0;

		foreach ( $responses as $uid => $response ) {
			if ( 200 !== (int) $response['status'] ) {
				$this->log( sprintf( 'Group memberships for %s returned HTTP %d; skipping.', $uid, (int) $response['status'] ) );
				continue;
			}

			$names = array();
			foreach ( (array) ( $response['body']['value'] ?? array() ) as $group ) {
				$name = trim( (string) ( $group['displayName'] ?? '' ) );
				if ( '' !== $name ) {
					$names[] = $name;
				}
			}

			$this->group_index[ $uid ] = $names;

			Repo::upsert_person(
				array(
					'source'     => self::SOURCE,
					'source_uid' => $uid,
					'upn'        => (string) $this->user_index[ $uid ]['upn'],
					'groups'     => $names,
				)
			);
			++$written;
		}

		$this->log( sprintf( 'Group memberships imported for %d of %d people.', $written, count( $this->user_index ) ) );

		return $written;
	}

	/* ---------------- Devices ---------------- */

	/**
	 * Import Intune managed devices.
	 *
	 * @param VulnHub_Intune_Client $client Graph client.
	 * @return int Number of devices upserted.
	 */
	private function sync_devices( VulnHub_Intune_Client $client ): int {
		$count = 0;

		$client->paginate(
			'deviceManagement/managedDevices',
			array( '$top' => $this->page_size() ),
			array(),
			function ( array $items ) use ( &$count ): void {
				foreach ( $items as $device ) {
					if ( $this->import_device( (array) $device ) ) {
						++$count;
					}
				}
			}
		);

		if ( $this->userless ) {
			$this->log(
				sprintf(
					'%d device(s) have no primary user (shared, kiosk or device-enrolled): %s',
					count( $this->userless ),
					vh_trim( implode( ', ', $this->userless ), 300 )
				)
			);
		}

		$this->log( sprintf( 'Devices: %d imported.', $count ) );

		return $count;
	}

	/**
	 * Normalise and store one Graph managedDevice.
	 *
	 * @param array<string,mixed> $device Graph managedDevice object.
	 * @return bool True when the asset was written.
	 */
	private function import_device( array $device ): bool {
		$intune_id = trim( (string) ( $device['id'] ?? '' ) );
		$hostname  = trim( (string) ( $device['deviceName'] ?? '' ) );

		if ( '' === $intune_id ) {
			$this->bump( 'skipped' );
			return false;
		}

		// --- primary user -------------------------------------------------
		// Join on userId, the immutable directory object GUID. A UPN can be
		// renamed (marriage, rebrand, domain migration) while the GUID never
		// changes, so joining on the UPN silently loses ownership after any
		// rename.
		$user_id = strtolower( trim( (string) ( $device['userId'] ?? '' ) ) );
		$upn     = '';

		if ( '' !== $user_id && isset( $this->user_index[ $user_id ] ) ) {
			$upn = (string) $this->user_index[ $user_id ]['upn'];
		} elseif ( '' !== $user_id ) {
			// Device points at a directory object we did not import: a guest, a
			// deleted account, or a user outside the synced scope. Fall back to
			// whatever UPN Intune reports so ownership can still resolve if that
			// person arrives later.
			$upn = strtolower( trim( (string) ( $device['userPrincipalName'] ?? '' ) ) );
			$this->log(
				sprintf(
					'Device %s references user id %s which was not in the Entra ID import; falling back to the reported UPN%s.',
					$hostname,
					$user_id,
					'' !== $upn ? ' ' . $upn : ' (none reported)'
				)
			);
		} else {
			// Normal and expected for shared, kiosk and userless devices.
			// Log it, do not treat it as an error.
			$this->userless[] = '' !== $hostname ? $hostname : $intune_id;
		}

		$os         = (string) ( $device['operatingSystem'] ?? '' );
		$asset_type = $this->asset_type_from_os( $os, (string) ( $device['model'] ?? '' ) );
		$last_sync  = (string) ( $device['lastSyncDateTime'] ?? '' );
		$serial     = (string) ( $device['serialNumber'] ?? '' );
		$aad_id     = (string) ( $device['azureADDeviceId'] ?? '' );

		// Graph reports MAC addresses as undelimited hex. Wi-Fi first: on a laptop
		// the Ethernet MAC usually belongs to whichever dock it was last plugged in
		// to, so it is the less stable identifier of the two.
		$wifi_mac = (string) ( $device['wiFiMacAddress'] ?? '' );
		$mac      = $this->format_mac( '' !== $wifi_mac ? $wifi_mac : (string) ( $device['ethernetMacAddress'] ?? '' ) );

		$payload = array(
			'primary_source'     => self::SOURCE,
			'intune_id'          => $intune_id,
			'azure_ad_device_id' => $aad_id,
			'hostname'           => $hostname,
			'serial_number'      => $serial,
			'model'              => (string) ( $device['model'] ?? '' ),
			'manufacturer'       => (string) ( $device['manufacturer'] ?? '' ),
			'operating_system'   => $os,
			'os_version'         => (string) ( $device['osVersion'] ?? '' ),
			'compliance_state'   => (string) ( $device['complianceState'] ?? '' ),
			'enrollment_type'    => (string) ( $device['deviceEnrollmentType'] ?? '' ),
			'mac_address'        => $mac,
			'asset_type'         => $asset_type,
			'is_managed'         => true,
			'has_agent'          => true,
			'first_seen'         => (string) ( $device['enrolledDateTime'] ?? '' ),
			'last_seen'          => $last_sync,
			'last_intune_sync'   => $last_sync,
			'raw'                => array(
				// The ownership rule `person_from_intune` reads exactly
				// raw['intune']['userPrincipalName']. Nothing else in this payload
				// is load-bearing for ownership — this one key is.
				'intune' => array(
					'userPrincipalName'       => $upn,
					'userId'                  => $user_id,
					'userDisplayName'         => (string) ( $device['userDisplayName'] ?? '' ),
					'managedDeviceOwnerType'  => (string) ( $device['managedDeviceOwnerType'] ?? '' ),
					'deviceCategory'          => (string) ( $device['deviceCategoryDisplayName'] ?? '' ),
					'deviceRegistrationState' => (string) ( $device['deviceRegistrationState'] ?? '' ),
					'managementAgent'         => (string) ( $device['managementAgent'] ?? '' ),
					'lastSyncDateTime'        => $last_sync,
					'isEncrypted'             => (bool) ( $device['isEncrypted'] ?? false ),
				),
				'graph'  => $device,
			),
		);

		$result = Repo::upsert_asset( $payload );

		$this->bump( 'processed' );
		$this->bump( $result['created'] ? 'created' : 'updated' );

		return true;
	}

	/**
	 * Derive an asset type from the Intune operatingSystem value.
	 *
	 * Intune reports a short OS family string: "Windows", "macOS", "iOS",
	 * "Android", "Windows Server" (rare — Intune manages very few servers),
	 * and occasionally "iPadOS" on newer builds.
	 *
	 * Order matters. "Windows Server" also contains "Windows", so servers must
	 * be tested first or every domain controller in the tenant would be filed
	 * as a workstation and then wrongly demand an individual human owner.
	 *
	 * @param string $os    operatingSystem value.
	 * @param string $model model value, used only to separate iPads from iPhones.
	 * @return string One of core's vh_asset_types() keys.
	 */
	private function asset_type_from_os( string $os, string $model = '' ): string {
		$needle = strtolower( trim( $os ) );

		if ( '' === $needle ) {
			return 'unknown';
		}

		// Servers first — see the note above.
		if ( str_contains( $needle, 'server' ) ) {
			return 'server';
		}

		// Mobile. iPadOS devices historically report "iOS", so the model is the
		// tie-breaker; either way both land on 'mobile'.
		foreach ( array( 'ios', 'ipados', 'android', 'windowsphone', 'windows phone' ) as $mobile ) {
			if ( str_starts_with( $needle, $mobile ) ) {
				return 'mobile';
			}
		}
		if ( str_contains( strtolower( $model ), 'ipad' ) || str_contains( strtolower( $model ), 'iphone' ) ) {
			return 'mobile';
		}

		// Desktop operating systems.
		foreach ( array( 'windows', 'macos', 'mac os', 'os x', 'macmdm', 'chromeos', 'linux' ) as $desktop ) {
			if ( str_contains( $needle, $desktop ) ) {
				return 'workstation';
			}
		}

		return 'unknown';
	}

	/**
	 * Normalise a MAC address. Graph returns undelimited hex.
	 *
	 * @param string $mac Raw value.
	 * @return string
	 */
	private function format_mac( string $mac ): string {
		$hex = strtoupper( (string) preg_replace( '/[^0-9A-Fa-f]/', '', $mac ) );
		if ( 12 !== strlen( $hex ) ) {
			return '' === $hex ? '' : strtoupper( trim( $mac ) );
		}
		return implode( ':', str_split( $hex, 2 ) );
	}

	/* ---------------- Team & location ---------------- */

	/**
	 * Resolve each person's team and location and write them onto the PERSON.
	 *
	 * Core's mapping engine then inherits both onto that person's devices, which
	 * is why this connector never touches team_id / location_id on an asset.
	 *
	 * @return int Number of people updated.
	 */
	private function resolve_people_placement(): int {
		$source  = (string) $this->get( 'team_source', 'department' );
		$prefix  = trim( (string) $this->get( 'group_prefix', 'TEAM-' ) );
		$updated = 0;

		if ( 'group-prefix' === $source && ! $this->group_index ) {
			$this->log( 'Team source is "group name prefix" but group sync is off — falling back to department.' );
			$source = 'department';
		}

		foreach ( $this->user_index as $uid => $info ) {
			$team_name = match ( $source ) {
				'group-prefix' => $this->team_from_groups( $this->group_index[ $uid ] ?? array(), $prefix ),
				'office'       => (string) $info['office'],
				default        => (string) $info['department'],
			};

			$fields = array(
				'source'     => self::SOURCE,
				'source_uid' => (string) $uid,
				'upn'        => (string) $info['upn'],
			);

			if ( '' !== trim( $team_name ) ) {
				$team_id = Repo::ensure_team( $team_name, self::SOURCE );
				if ( $team_id ) {
					$fields['team_id'] = $team_id;
				}
			}

			$location_id = Repo::ensure_location(
				(string) $info['office'],
				(string) $info['city'],
				(string) $info['country']
			);
			if ( $location_id ) {
				$fields['location_id'] = $location_id;
			}

			if ( isset( $fields['team_id'] ) || isset( $fields['location_id'] ) ) {
				Repo::upsert_person( $fields );
				++$updated;
			}
		}

		$this->log( sprintf( 'Team/location resolved for %d people (team source: %s).', $updated, $source ) );

		return $updated;
	}

	/**
	 * First group whose name carries the configured prefix, with the prefix
	 * stripped so "TEAM-Finance" becomes the team "Finance".
	 *
	 * @param array<int,string> $groups Group display names.
	 * @param string            $prefix Configured prefix.
	 * @return string
	 */
	private function team_from_groups( array $groups, string $prefix ): string {
		if ( '' === $prefix ) {
			return '';
		}

		foreach ( $groups as $name ) {
			if ( stripos( $name, $prefix ) === 0 ) {
				return trim( substr( $name, strlen( $prefix ) ) );
			}
		}

		return '';
	}
}

