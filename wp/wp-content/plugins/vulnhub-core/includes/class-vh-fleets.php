<?php
/**
 * Pooled fleets: many short-lived machines, one asset record.
 *
 * An AppStream fleet starts a fresh instance for every streaming session,
 * each with a new random computer name and a new scanner agent, and throws it
 * away when the session ends. Every system then records it as a new machine:
 * Tenable registers a new asset per session, Intune enrols it, Defender
 * onboards it, the image builder shows up under its own names. The estate
 * ended up holding dozens of rows for what is, from a remediation point of
 * view, one thing: the golden image the fleet runs. Filters listed it over and
 * over, and there was nothing single to raise a ticket against or to watch
 * progress on.
 *
 * So a fleet is one asset record, and this class keeps it that way:
 *
 * - **Discovery** reads the AWS network capture. AWS names every AppStream
 *   interface after what it belongs to ("AppStream 2.0 - fleet: NAME - …",
 *   "AppStream 2.0 - image-builder: NAME - …"), which gives the fleets, the
 *   account, and the subnets they use; the subnets' address ranges are what a
 *   scanner record is placed by.
 * - **Membership**: an address inside a fleet's subnets, or -- for records
 *   with no address -- the random 15-hex computer name AppStream gives every
 *   session.
 * - **Routing** (`vulnhub_asset_route`, asked by `Repo::upsert_asset()` before
 *   it matches anything): a scanner record folds into the fleet record, and
 *   its asset id is kept as an alias so the session's findings land there
 *   too. Every other source -- Intune, the CMDB, Defender -- is ignored for a
 *   fleet member: a session's enrolment is noise, and letting those feeds
 *   re-create or re-match the rows is exactly how an earlier merge came
 *   undone on the next sync.
 * - **Latest scan wins**: all sessions run the same image, so after each
 *   scanner sync a finding the newest session no longer shows is closed as
 *   fixed. That is what makes a golden-image upgrade show up as progress on
 *   the ticket raised against the fleet.
 *
 * The fleet definitions are a setting (`vulnhub_fleets`), not code: they name
 * the estate's own accounts and address ranges.
 *
 * See docs/APPSTREAM.md, "One record per fleet".
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Fleets {

	public const OPTION = 'vulnhub_fleets';

	/** `primary_source` of a fleet record. Nothing else writes it. */
	public const SOURCE = 'fleet';

	/**
	 * How much older than the newest session's scan a finding may be before it
	 * counts as gone. Two days, not one: sessions run side by side and their
	 * agents scan at different times, so the newest image's findings arrive
	 * spread over a day or more.
	 */
	private const STALE_AFTER = 2 * DAY_IN_SECONDS;

	/** The computer name AppStream gives every session. */
	private const SESSION_NAME = '/^[0-9a-f]{15}$/';

	/** @var array<string,mixed>|null */
	private static ?array $config = null;

	/** @var array<string,string>|null Private address => fleet name, from the capture. */
	private static ?array $eni_fleet = null;

	public static function init(): void {
		add_filter( 'vulnhub_asset_route', array( __CLASS__, 'route' ), 10, 2 );
		add_action( 'vulnhub_sync_complete', array( __CLASS__, 'on_sync' ), 15, 1 );
	}

	/* =================================================================
	 * Configuration
	 * ============================================================== */

	/**
	 * The stored definition:
	 * { enabled: bool, fleets: [ { key, name, account, cidrs[], builders[],
	 *   asset_id, primary } ] }.
	 *
	 * @return array<string,mixed>
	 */
	public static function config(): array {
		if ( null === self::$config ) {
			$c            = get_option( self::OPTION, array() );
			self::$config = is_array( $c ) ? $c + array( 'enabled' => false, 'fleets' => array() ) : array( 'enabled' => false, 'fleets' => array() );
		}

		return self::$config;
	}

	private static function save( array $config ): void {
		self::$config = $config;
		update_option( self::OPTION, $config, false );
	}

	public static function enabled(): bool {
		return ! empty( self::config()['enabled'] ) && ! empty( self::config()['fleets'] );
	}

	/**
	 * What the AWS capture says the AppStream estate is.
	 *
	 * @return array<int,array<string,mixed>> Fleets, busiest first.
	 */
	public static function discover(): array {
		global $wpdb;

		$nodes = $wpdb->prefix . 'vulnhub_aws_net_nodes';

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $nodes ) ) !== $nodes ) {
			return array();
		}

		$fleets  = array();
		$subnets = array();

		foreach ( (array) $wpdb->get_results( "SELECT account_id, subnet_id, private_ip, detail FROM {$nodes} WHERE node_type = 'eni' AND source = 'aws' AND LOCATE('AppStream 2.0 - ', detail) > 0", ARRAY_A ) as $r ) { // phpcs:ignore
			$d = json_decode( (string) $r['detail'], true );

			if ( ! is_array( $d ) || ! preg_match( '/^AppStream 2\.0 - (fleet|image-builder): (.+?) - [0-9a-f]+$/', (string) ( $d['desc'] ?? '' ), $m ) ) {
				continue;
			}

			$acct = (string) $r['account_id'];

			if ( 'fleet' === $m[1] ) {
				$key = sanitize_key( $acct . '-' . $m[2] );

				$fleets[ $key ] = $fleets[ $key ] ?? array(
					'key'      => $key,
					'name'     => $m[2],
					'account'  => $acct,
					'sessions' => 0,
					'subnets'  => array(),
					'builders' => array(),
				);
				++$fleets[ $key ]['sessions'];
				$fleets[ $key ]['subnets'][ (string) $r['subnet_id'] ] = true;
			} else {
				$subnets[ $acct ]['builders'][ $m[2] ] = true;
				$subnets[ $acct ]['builder_subnets'][ (string) $r['subnet_id'] ] = true;
			}
		}

		$cidr_of = array();

		foreach ( (array) $wpdb->get_results( "SELECT resource_id, detail FROM {$nodes} WHERE node_type = 'subnet' AND source = 'aws'", ARRAY_A ) as $r ) { // phpcs:ignore
			$d = json_decode( (string) $r['detail'], true );

			if ( is_array( $d ) && '' !== (string) ( $d['cidr'] ?? '' ) ) {
				$cidr_of[ (string) $r['resource_id'] ] = (string) $d['cidr'];
			}
		}

		foreach ( $fleets as $key => $f ) {
			// Image builders in the same account build the images these
			// fleets run; their subnets belong to the fleet's range too.
			$extra = array_keys( (array) ( $subnets[ $f['account'] ]['builder_subnets'] ?? array() ) );
			$ids   = array_values( array_unique( array_merge( array_keys( $f['subnets'] ), $extra ) ) );

			$fleets[ $key ]['subnets']  = $ids;
			$fleets[ $key ]['cidrs']    = array_values( array_unique( array_filter( array_map( static fn( string $s ): string => $cidr_of[ $s ] ?? '', $ids ) ) ) );
			$fleets[ $key ]['builders'] = array_keys( (array) ( $subnets[ $f['account'] ]['builders'] ?? array() ) );
		}

		$fleets = array_values( $fleets );
		usort( $fleets, static fn( array $a, array $b ): int => $b['sessions'] <=> $a['sessions'] );

		return $fleets;
	}

	/**
	 * Fold what the capture discovered into the stored definition. New
	 * fleets are added; a known fleet gains any new ranges and keeps its
	 * record and its `enabled` state. The busiest fleet of an account is its
	 * primary: a record with no address to place it by goes there.
	 *
	 * @return array<string,mixed> The stored definition.
	 */
	public static function refresh_config(): array {
		$config = self::config();
		$known  = array();

		foreach ( (array) $config['fleets'] as $f ) {
			$known[ (string) $f['key'] ] = $f;
		}

		$primary = array();

		foreach ( self::discover() as $d ) {
			$k = $d['key'];

			$known[ $k ] = array(
				'key'      => $k,
				'name'     => $d['name'],
				'account'  => $d['account'],
				'cidrs'    => array_values( array_unique( array_merge( (array) ( $known[ $k ]['cidrs'] ?? array() ), $d['cidrs'] ) ) ),
				'builders' => $d['builders'],
				'sessions' => (int) $d['sessions'],
				'asset_id' => (int) ( $known[ $k ]['asset_id'] ?? 0 ),
				'primary'  => false,
			);

			if ( ! isset( $primary[ $d['account'] ] ) ) {
				$primary[ $d['account'] ] = $k;
			}
		}

		foreach ( $known as $k => $f ) {
			$known[ $k ]['primary'] = ( $primary[ (string) $f['account'] ] ?? '' ) === $k || ( ! isset( $primary[ (string) $f['account'] ] ) && ! empty( $f['primary'] ) );
		}

		$config['fleets'] = array_values( $known );
		self::save( $config );

		return $config;
	}

	/* =================================================================
	 * Membership
	 * ============================================================== */

	/**
	 * Which fleet a record belongs to, or null.
	 *
	 * @param array<string,mixed> $data Asset fields (hostname, ipv4, ipv4s, operating_system).
	 * @return array<string,mixed>|null The fleet definition.
	 */
	public static function fleet_of( array $data ): ?array {
		if ( ! self::enabled() ) {
			return null;
		}

		$fleets = (array) self::config()['fleets'];
		$ips    = self::ips( $data );

		foreach ( $ips as $ip ) {
			$in = array_values( array_filter( $fleets, static fn( array $f ): bool => self::in_any( $ip, (array) ( $f['cidrs'] ?? array() ) ) ) );

			if ( ! $in ) {
				continue;
			}

			// Several fleets share the range: the interface says which one.
			$named = self::eni_fleets()[ $ip ] ?? '';

			foreach ( $in as $f ) {
				if ( '' !== $named && $named === (string) $f['name'] ) {
					return $f;
				}
			}

			foreach ( $in as $f ) {
				if ( ! empty( $f['primary'] ) ) {
					return $f;
				}
			}

			return $in[0];
		}

		// No address (an enrolment record): the session name is the tell,
		// and only on Windows, which is all AppStream runs.
		$name = strtolower( trim( (string) ( $data['hostname'] ?? '' ) ) );

		if ( ! $ips && preg_match( self::SESSION_NAME, $name ) && str_contains( strtolower( (string) ( $data['operating_system'] ?? 'windows' ) ), 'windows' ) ) {
			foreach ( $fleets as $f ) {
				if ( ! empty( $f['primary'] ) ) {
					return $f;
				}
			}
		}

		return null;
	}

	/**
	 * The `vulnhub_asset_route` answer for one incoming record.
	 *
	 * @param mixed               $route Earlier answer.
	 * @param array<string,mixed> $data  Normalised asset fields.
	 * @return mixed
	 */
	public static function route( $route, array $data ) {
		if ( null !== $route ) {
			return $route;
		}

		$fleet = self::fleet_of( $data );

		if ( ! $fleet ) {
			return null;
		}

		$source = vh_normalise_source( (string) ( $data['source'] ?? $data['primary_source'] ?? '' ) );

		// Only the scanner speaks for the fleet. Every other feed's copy of a
		// session is ignored, so it cannot re-create or re-match the rows.
		if ( 'tenable' !== $source ) {
			return array( 'action' => 'ignore', 'fleet' => (string) $fleet['key'] );
		}

		$id = self::record_for( $fleet );

		if ( ! $id ) {
			return null;
		}

		$uuid = (string) ( $data['tenable_uuid'] ?? '' );

		if ( '' !== $uuid ) {
			self::alias( 'tenable', $uuid, $id, (string) ( $data['hostname'] ?? '' ), (string) ( $data['last_seen'] ?? '' ) );
		}

		return array(
			'action'   => 'fold',
			'asset_id' => $id,
			'data'     => self::fleet_fields( $data, $id ),
		);
	}

	/**
	 * What a session record may say about the fleet record: when it was last
	 * seen and scanned, what it runs, the agent -- never who it is. And only
	 * when it is the newest session: an older one arriving later in the same
	 * export must not wind the clock back.
	 *
	 * @param array<string,mixed> $data Session record.
	 * @return array<string,mixed>
	 */
	private static function fleet_fields( array $data, int $asset_id ): array {
		global $wpdb;

		$held = (string) $wpdb->get_var( $wpdb->prepare( 'SELECT COALESCE(tenable_last_scan, last_seen) FROM ' . vh_table( 'assets' ) . ' WHERE id = %d', $asset_id ) );
		$mine = (string) ( vh_to_mysql( $data['tenable_last_scan'] ?? $data['last_seen'] ?? '' ) ?? '' );
		$out  = array( 'source' => (string) ( $data['source'] ?? $data['primary_source'] ?? 'tenable' ) );

		if ( '' !== $mine && $mine >= $held ) {
			foreach ( array( 'tenable_uuid', 'tenable_last_scan', 'last_seen', 'operating_system', 'os_version', 'has_agent', 'agent_status', 'agent_last_connect', 'agent_status_since', 'ipv4' ) as $k ) {
				if ( isset( $data[ $k ] ) && '' !== (string) $data[ $k ] ) {
					$out[ $k ] = $data[ $k ];
				}
			}
		}

		return $out;
	}

	/* =================================================================
	 * The fleet record
	 * ============================================================== */

	/**
	 * The fleet's asset id, creating the record the first time.
	 *
	 * @param array<string,mixed> $fleet Definition.
	 */
	public static function record_for( array $fleet ): int {
		global $wpdb;

		$a  = vh_table( 'assets' );
		$id = (int) ( $fleet['asset_id'] ?? 0 );

		if ( $id && $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$a} WHERE id = %d AND primary_source = %s", $id, self::SOURCE ) ) ) { // phpcs:ignore
			return $id;
		}

		$name = sprintf( 'AppStream fleet: %s', (string) $fleet['name'] );
		$now  = vh_now();
		$tags = array( 'appstream', 'golden-image', 'fleet:' . (string) $fleet['name'] );

		$wpdb->insert(
			$a,
			array(
				'primary_source'   => self::SOURCE,
				'hostname'         => mb_substr( $name, 0, 191 ),
				'asset_type'       => 'server',
				'operating_system' => 'Windows',
				'environment'      => str_contains( strtolower( (string) $fleet['name'] ), 'staging' ) ? 'staging' : 'production',
				'cloud_provider'   => 'aws',
				'cloud_account_id' => (string) $fleet['account'],
				'lifecycle_status' => 'in_service',
				'tags_json'        => (string) wp_json_encode( $tags ),
				'sources_json'     => '{}',
				'first_seen'       => $now,
				'last_seen'        => $now,
				'created_at'       => $now,
				'updated_at'       => $now,
			)
		);

		$id = (int) $wpdb->insert_id;

		if ( $id ) {
			$config = self::config();

			foreach ( $config['fleets'] as $i => $f ) {
				if ( (string) $f['key'] === (string) $fleet['key'] ) {
					$config['fleets'][ $i ]['asset_id'] = $id;
				}
			}

			self::save( $config );
			vulnhub()->logger->audit( 'fleet.record_created', sprintf( 'One record for AppStream fleet %s', (string) $fleet['name'] ), 'asset', $id );
		}

		return $id;
	}

	/** Every fleet record id. @return int[] */
	public static function record_ids(): array {
		global $wpdb;

		return array_map( 'intval', (array) $wpdb->get_col( $wpdb->prepare( 'SELECT id FROM ' . vh_table( 'assets' ) . ' WHERE primary_source = %s', self::SOURCE ) ) );
	}

	public static function is_record( int $asset_id ): bool {
		return in_array( $asset_id, self::record_ids(), true );
	}

	/* =================================================================
	 * Aliases
	 * ============================================================== */

	public static function alias( string $source, string $external_id, int $asset_id, string $hostname = '', string $seen = '' ): void {
		global $wpdb;

		$now  = vh_now();
		$seen = (string) ( vh_to_mysql( $seen ) ?? '' ) ?: $now;

		$wpdb->query( // phpcs:ignore
			$wpdb->prepare(
				'INSERT INTO ' . vh_table( 'asset_aliases' ) . ' (source, external_id, asset_id, hostname, first_seen, last_seen)
				 VALUES (%s,%s,%d,%s,%s,%s)
				 ON DUPLICATE KEY UPDATE asset_id = VALUES(asset_id), hostname = VALUES(hostname), last_seen = GREATEST(last_seen, VALUES(last_seen))',
				$source,
				$external_id,
				$asset_id,
				mb_substr( $hostname, 0, 191 ),
				$seen,
				$seen
			)
		);
	}

	/**
	 * The asset an alias stands for, or 0.
	 */
	public static function aliased( string $source, string $external_id ): int {
		global $wpdb;

		if ( '' === $external_id ) {
			return 0;
		}

		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT asset_id FROM ' . vh_table( 'asset_aliases' ) . ' WHERE source = %s AND external_id = %s', $source, $external_id ) );
	}

	/* =================================================================
	 * Keeping it one record
	 * ============================================================== */

	/**
	 * Fold every existing member row into its fleet record: its findings move
	 * (the newer copy wins where both hold one), its scanner id becomes an
	 * alias, and the row is retired pointing at the fleet. Nothing is copied
	 * onto the fleet record -- it must not take on one session's identity.
	 *
	 * @return array{members:int,folded:int,findings_moved:int,findings_newer:int}
	 */
	public static function absorb( bool $dry_run = false ): array {
		global $wpdb;

		$out = array( 'members' => 0, 'folded' => 0, 'findings_moved' => 0, 'findings_newer' => 0, 'by_fleet' => array() );

		if ( ! self::enabled() ) {
			return $out;
		}

		$a    = vh_table( 'assets' );
		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT id, hostname, ipv4, ipv4s, operating_system, tenable_uuid, last_seen, tenable_last_scan, duplicate_of FROM {$a} WHERE primary_source <> %s", self::SOURCE ), ARRAY_A ); // phpcs:ignore

		foreach ( $rows as $r ) {
			$fleet = self::fleet_of( $r );

			if ( ! $fleet ) {
				continue;
			}

			++$out['members'];
			$out['by_fleet'][ (string) $fleet['name'] ] = ( $out['by_fleet'][ (string) $fleet['name'] ] ?? 0 ) + 1;

			if ( $dry_run ) {
				continue;
			}

			$id = self::record_for( $fleet );

			if ( ! $id || (int) $r['duplicate_of'] === $id ) {
				continue;
			}

			if ( '' !== (string) $r['tenable_uuid'] ) {
				self::alias( 'tenable', (string) $r['tenable_uuid'], $id, (string) $r['hostname'], (string) ( $r['tenable_last_scan'] ?: $r['last_seen'] ) );
			}

			$moved = array();
			Duplicates::move_findings( (int) $r['id'], $id, false, $moved );
			$out['findings_moved'] += (int) $moved['findings_moved'];
			$out['findings_newer'] += (int) $moved['findings_newer'];

			$wpdb->update(
				$a,
				array(
					'lifecycle_status' => 'retired',
					'duplicate_of'     => $id,
					'updated_at'       => vh_now(),
				),
				array( 'id' => (int) $r['id'] )
			);

			// The newest session's scan is the fleet's scan.
			$wpdb->query( // phpcs:ignore
				$wpdb->prepare(
					"UPDATE {$a} SET tenable_last_scan = GREATEST(COALESCE(tenable_last_scan, '1970-01-01'), COALESCE(%s, '1970-01-01')),
					                 last_seen = GREATEST(COALESCE(last_seen, '1970-01-01'), COALESCE(%s, '1970-01-01'))
					 WHERE id = %d", // phpcs:ignore
					$r['tenable_last_scan'],
					$r['last_seen'],
					$id
				)
			);

			++$out['folded'];
		}

		if ( ! $dry_run && $out['folded'] ) {
			foreach ( self::record_ids() as $id ) {
				Duplicates::recount( $id );
			}

			vulnhub()->logger->audit( 'fleet.absorbed', sprintf( 'Folded %d AppStream session records into their fleet records', $out['folded'] ), 'asset', 'fleet', $out );
		}

		return $out;
	}

	/**
	 * Latest scan wins. Every session runs the same image, so a finding the
	 * newest session's scan did not report is gone from the image: closed as
	 * fixed, with the date of the scan that no longer saw it. A finding that
	 * comes back on a later session reopens the usual way.
	 *
	 * First the other half: a finding the newest scans *did* report, but that
	 * sits archived, is current. Before the fleet record existed, every
	 * session's row was retired when AWS terminated the instance -- and its
	 * findings archived with it -- so the image's live vulnerabilities were
	 * the ones hidden, while an older session nobody retired kept its stale
	 * findings open.
	 *
	 * @return array<int,array{restored:int,closed:int}> Per fleet record.
	 */
	public static function reconcile(): array {
		global $wpdb;

		$f   = vh_table( 'findings' );
		$a   = vh_table( 'assets' );
		$out = array();

		foreach ( self::record_ids() as $id ) {
			$latest = (string) $wpdb->get_var( $wpdb->prepare( "SELECT tenable_last_scan FROM {$a} WHERE id = %d", $id ) ); // phpcs:ignore

			if ( '' === $latest ) {
				continue;
			}

			$cutoff = gmdate( 'Y-m-d H:i:s', (int) strtotime( $latest . ' UTC' ) - self::STALE_AFTER );

			$restored = (int) $wpdb->query( // phpcs:ignore
				$wpdb->prepare(
					"UPDATE {$f} SET state = IF(state IN ('open','reopened'), state, IF(prev_state IN ('open','reopened'), prev_state, 'open')), archived_at = NULL, updated_at = %s
					 WHERE asset_id = %d AND ( state = 'archived' OR ( archived_at IS NOT NULL AND state IN ('open','reopened') ) )
					   AND LEFT(source, 7) = 'tenable' AND last_found IS NOT NULL AND last_found >= %s", // phpcs:ignore
					vh_now(),
					$id,
					$cutoff
				)
			);

			$closed = (int) $wpdb->query( // phpcs:ignore
				$wpdb->prepare(
					// An open row a session's retirement archived counts too:
					// it was open, and it is gone from the image all the same.
					"UPDATE {$f} SET prev_state = state, state = 'fixed', last_fixed = %s, archived_at = NULL, updated_at = %s
					 WHERE asset_id = %d AND state IN ('open','reopened')
					   AND LEFT(source, 7) = 'tenable' AND last_found IS NOT NULL AND last_found < %s", // phpcs:ignore
					$latest,
					vh_now(),
					$id,
					$cutoff
				)
			);

			$out[ $id ] = array( 'restored' => $restored, 'closed' => $closed );

			Duplicates::recount( $id );
		}

		$restored = array_sum( array_column( $out, 'restored' ) );
		$closed   = array_sum( array_column( $out, 'closed' ) );

		if ( $restored + $closed > 0 ) {
			vulnhub()->logger->audit( 'fleet.reconciled', sprintf( 'Fleet findings: %d current ones restored, %d the newest sessions no longer report closed', $restored, $closed ), 'asset', 'fleet', $out );
		}

		return $out;
	}

	/**
	 * After a sync: an AWS capture may have found fleets or ranges; a scanner
	 * sync may have brought a newer session. Fold, then reconcile.
	 */
	public static function on_sync( string $connector = '' ): void {
		if ( 'aws' === $connector ) {
			self::refresh_config();
		}

		if ( ! self::enabled() ) {
			return;
		}

		if ( in_array( $connector, array( 'aws', 'tenable', 'intune', 'cmdb', 'defender', '' ), true ) ) {
			self::absorb();
		}

		if ( in_array( $connector, array( 'tenable', '' ), true ) ) {
			self::reconcile();
		}
	}

	/* =================================================================
	 * Internals
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $data Asset fields.
	 * @return string[]
	 */
	private static function ips( array $data ): array {
		$out = array();

		foreach ( array( (string) ( $data['ipv4'] ?? '' ), (string) ( $data['ipv4s'] ?? '' ) ) as $blob ) {
			foreach ( preg_split( '/[\s,;]+/', $blob ) ?: array() as $ip ) {
				if ( filter_var( trim( $ip ), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					$out[] = trim( $ip );
				}
			}
		}

		return array_values( array_unique( $out ) );
	}

	/** @param string[] $cidrs Ranges. */
	private static function in_any( string $ip, array $cidrs ): bool {
		$long = ip2long( $ip );

		if ( false === $long ) {
			return false;
		}

		foreach ( $cidrs as $cidr ) {
			[ $base, $bits ] = array_pad( explode( '/', (string) $cidr, 2 ), 2, '32' );
			$bits            = max( 0, min( 32, (int) $bits ) );
			$mask            = 0 === $bits ? 0 : ( -1 << ( 32 - $bits ) );
			$b               = ip2long( $base );

			if ( false !== $b && ( $long & $mask ) === ( $b & $mask ) ) {
				return true;
			}
		}

		return false;
	}

	/** @return array<string,string> Private address => fleet name, from the capture. */
	private static function eni_fleets(): array {
		global $wpdb;

		if ( null !== self::$eni_fleet ) {
			return self::$eni_fleet;
		}

		self::$eni_fleet = array();
		$nodes           = $wpdb->prefix . 'vulnhub_aws_net_nodes';

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $nodes ) ) !== $nodes ) {
			return self::$eni_fleet;
		}

		foreach ( (array) $wpdb->get_results( "SELECT private_ip, detail FROM {$nodes} WHERE node_type = 'eni' AND LOCATE('AppStream 2.0 - fleet: ', detail) > 0", ARRAY_A ) as $r ) { // phpcs:ignore
			$d = json_decode( (string) $r['detail'], true );

			if ( is_array( $d ) && preg_match( '/^AppStream 2\.0 - fleet: (.+?) - [0-9a-f]+$/', (string) ( $d['desc'] ?? '' ), $m ) ) {
				self::$eni_fleet[ (string) $r['private_ip'] ] = $m[1];
			}
		}

		return self::$eni_fleet;
	}
}
