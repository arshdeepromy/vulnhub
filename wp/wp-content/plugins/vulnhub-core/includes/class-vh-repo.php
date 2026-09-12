<?php
/**
 * Data access layer. Every connector and screen goes through here.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Repo {

	/* =================================================================
	 * People
	 * ============================================================== */

	/**
	 * Upsert a person by (source, source_uid), falling back to UPN/email.
	 *
	 * @param array<string,mixed> $data Person fields.
	 * @return array{id:int,created:bool}
	 */
	public static function upsert_person( array $data ): array {
		global $wpdb;

		$table  = vh_table( 'people' );
		$source = (string) ( $data['source'] ?? 'manual' );
		$uid    = (string) ( $data['source_uid'] ?? '' );
		$upn    = strtolower( trim( (string) ( $data['upn'] ?? '' ) ) );
		$email  = strtolower( trim( (string) ( $data['email'] ?? '' ) ) );

		$existing = null;
		if ( $uid ) {
			$existing = $wpdb->get_row(
				$wpdb->prepare( "SELECT id FROM {$table} WHERE source = %s AND source_uid = %s", $source, $uid ),
				ARRAY_A
			);
		}
		if ( ! $existing && $upn ) {
			$existing = $wpdb->get_row( $wpdb->prepare( "SELECT id FROM {$table} WHERE upn = %s", $upn ), ARRAY_A );
		}
		if ( ! $existing && $email ) {
			$existing = $wpdb->get_row( $wpdb->prepare( "SELECT id FROM {$table} WHERE email = %s", $email ), ARRAY_A );
		}

		$row = array_filter(
			array(
				'source'          => $source,
				'source_uid'      => $uid,
				'upn'             => $upn,
				'email'           => $email,
				'display_name'    => (string) ( $data['display_name'] ?? '' ),
				'given_name'      => (string) ( $data['given_name'] ?? '' ),
				'surname'         => (string) ( $data['surname'] ?? '' ),
				'job_title'       => (string) ( $data['job_title'] ?? '' ),
				'department'      => (string) ( $data['department'] ?? '' ),
				'company'         => (string) ( $data['company'] ?? '' ),
				'employee_id'     => (string) ( $data['employee_id'] ?? '' ),
				'manager_upn'     => strtolower( (string) ( $data['manager_upn'] ?? '' ) ),
				'manager_name'    => (string) ( $data['manager_name'] ?? '' ),
				'office_location' => (string) ( $data['office_location'] ?? '' ),
				'city'            => (string) ( $data['city'] ?? '' ),
				'state'           => (string) ( $data['state'] ?? '' ),
				'country'         => (string) ( $data['country'] ?? '' ),
				'usage_location'  => (string) ( $data['usage_location'] ?? '' ),
			),
			static fn( $v ): bool => '' !== $v
		);

		if ( isset( $data['is_active'] ) ) {
			$row['is_active'] = (int) (bool) $data['is_active'];
		}
		if ( isset( $data['team_id'] ) ) {
			$row['team_id'] = (int) $data['team_id'];
		}
		if ( isset( $data['location_id'] ) ) {
			$row['location_id'] = (int) $data['location_id'];
		}
		if ( isset( $data['groups'] ) ) {
			$row['groups_json'] = (string) wp_json_encode( $data['groups'] );
		}
		if ( isset( $data['raw'] ) ) {
			$row['raw_json'] = (string) wp_json_encode( $data['raw'] );
		}

		$row['last_synced_at'] = vh_now();
		$row['updated_at']     = vh_now();

		if ( $existing ) {
			$wpdb->update( $table, $row, array( 'id' => (int) $existing['id'] ) );
			return array(
				'id'      => (int) $existing['id'],
				'created' => false,
			);
		}

		$row['created_at'] = vh_now();
		$wpdb->insert( $table, $row );

		return array(
			'id'      => (int) $wpdb->insert_id,
			'created' => true,
		);
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function person( int $id ): ?array {
		global $wpdb;
		if ( ! $id ) {
			return null;
		}
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'people' ) . ' WHERE id = %d', $id ), ARRAY_A );
		return $row ?: null;
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function person_by_upn( string $upn ): ?array {
		global $wpdb;
		$upn = strtolower( trim( $upn ) );
		if ( '' === $upn ) {
			return null;
		}
		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM ' . vh_table( 'people' ) . ' WHERE upn = %s OR email = %s LIMIT 1', $upn, $upn ),
			ARRAY_A
		);
		return $row ?: null;
	}

	/* =================================================================
	 * Teams & locations
	 * ============================================================== */

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public static function teams(): array {
		global $wpdb;
		return (array) $wpdb->get_results( 'SELECT * FROM ' . vh_table( 'teams' ) . ' ORDER BY name ASC', ARRAY_A );
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function team( int $id ): ?array {
		global $wpdb;
		if ( ! $id ) {
			return null;
		}
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'teams' ) . ' WHERE id = %d', $id ), ARRAY_A );
		return $row ?: null;
	}

	public static function team_id_by_slug( string $slug ): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM ' . vh_table( 'teams' ) . ' WHERE slug = %s', sanitize_title( $slug ) ) );
	}

	/**
	 * Find a team by fuzzy name (used to map Intune "department" to a team).
	 */
	public static function team_id_by_name( string $name ): int {
		global $wpdb;
		$name = trim( $name );
		if ( '' === $name ) {
			return 0;
		}
		$id = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM ' . vh_table( 'teams' ) . ' WHERE name = %s OR slug = %s LIMIT 1', $name, sanitize_title( $name ) ) );
		return $id;
	}

	/**
	 * Create the team if it does not exist. Returns the id.
	 */
	public static function ensure_team( string $name, string $source = 'sync' ): int {
		global $wpdb;

		$name = trim( $name );
		if ( '' === $name ) {
			return 0;
		}
		$existing = self::team_id_by_name( $name );
		if ( $existing ) {
			return $existing;
		}

		$wpdb->insert(
			vh_table( 'teams' ),
			array(
				'name'       => $name,
				'slug'       => sanitize_title( $name ),
				'source'     => $source,
				'created_at' => vh_now(),
				'updated_at' => vh_now(),
			)
		);
		return (int) $wpdb->insert_id;
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public static function locations(): array {
		global $wpdb;
		return (array) $wpdb->get_results( 'SELECT * FROM ' . vh_table( 'locations' ) . ' ORDER BY name ASC', ARRAY_A );
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function location( int $id ): ?array {
		global $wpdb;
		if ( ! $id ) {
			return null;
		}
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'locations' ) . ' WHERE id = %d', $id ), ARRAY_A );
		return $row ?: null;
	}

	/**
	 * Resolve (or create) a location from a free-text office / city string.
	 */
	public static function ensure_location( string $name, string $city = '', string $country = '' ): int {
		global $wpdb;

		$name = trim( $name ) ?: trim( $city );
		if ( '' === $name ) {
			return 0;
		}

		$slug = sanitize_title( $name );
		$id   = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM ' . vh_table( 'locations' ) . ' WHERE slug = %s OR name = %s LIMIT 1', $slug, $name ) );
		if ( $id ) {
			return $id;
		}

		$wpdb->insert(
			vh_table( 'locations' ),
			array(
				'name'       => $name,
				'slug'       => $slug,
				'city'       => $city ?: $name,
				'country'    => $country,
				'source'     => 'sync',
				'created_at' => vh_now(),
				'updated_at' => vh_now(),
			)
		);
		return (int) $wpdb->insert_id;
	}

	/* =================================================================
	 * Assets
	 * ============================================================== */

	/**
	 * Upsert an asset. Matching order: tenable_uuid, intune_id,
	 * azure_ad_device_id, serial_number, then hostname, FQDN and IPv4.
	 *
	 * Pass `match_only` to enrich without ever creating. Some feeds are
	 * commentary on an estate rather than a census of it -- a Tenable cloud
	 * asset export, for instance, carries AWS account, region and resource
	 * tags for machines the inventory should already know about, and 2,272
	 * of its 2,950 rows are identity objects rather than hosts at all. For
	 * those, a row that matches nothing is a fact to report, not an asset to
	 * invent.
	 *
	 * @param array<string,mixed> $data Asset fields; `match_only` to forbid inserts.
	 * @return array{id:int,created:bool,matched:bool}
	 */
	/**
	 * Settle hostname and FQDN into one shape, whoever sent them.
	 *
	 * A dotted hostname is an FQDN somebody put in the wrong field. The short
	 * label becomes the hostname -- the thing every other feed reports and
	 * every match falls back to -- and the full name is kept in `fqdn`. A bare
	 * IP address is left alone: splitting 10.1.2.3 on its first dot would
	 * produce a machine called "10".
	 *
	 * @param array<string,mixed> $data Asset fields.
	 * @return array<string,mixed>
	 */
	private static function normalise_names( array $data ): array {
		$host = strtolower( trim( (string) ( $data['hostname'] ?? '' ) ) );
		$fqdn = strtolower( trim( (string) ( $data['fqdn'] ?? '' ) ) );

		/*
		 * A NetBIOS `DOMAIN\HOST` is not an FQDN, and neither is a bare
		 * workgroup name. The CMDB sends `workgroup\nzaklsbyrqims1` in its DNS
		 * column; stored as written it matches nothing, and the machine's real
		 * name is left sitting in a field nothing reads. Take the host part,
		 * and keep it only if it is actually qualified.
		 */
		if ( str_contains( $fqdn, '\\' ) ) {
			$fqdn = (string) substr( strrchr( $fqdn, '\\' ) ?: '', 1 );
		}

		$fqdn = rtrim( $fqdn, '.' );
		$host = rtrim( $host, '.' );

		if ( '' !== $fqdn && ! str_contains( $fqdn, '.' ) ) {
			if ( '' === $host ) {
				$host = $fqdn;
			}

			$fqdn             = '';
			$data['fqdn']     = '';
		}

		if ( '' !== $host && str_contains( $host, '.' ) && ! filter_var( $host, FILTER_VALIDATE_IP ) ) {
			if ( '' === $fqdn ) {
				$fqdn = $host;
			}
			$host = (string) strtok( $host, '.' );
		}

		if ( '' !== $host ) {
			$data['hostname'] = $host;
		}
		if ( '' !== $fqdn ) {
			$data['fqdn'] = $fqdn;
		}

		return $data;
	}

	/**
	 * Could an incoming record and a matched row be the same machine?
	 *
	 * Only ever asked of the soft keys. Where both sides carry the same kind
	 * of strong identifier and the two disagree, they are different assets and
	 * the weaker evidence that brought them together is wrong.
	 *
	 * @param array<string,mixed> $data     Incoming asset fields.
	 * @param array<string,mixed> $existing The row a soft key matched.
	 */
	private static function identities_agree( array $data, array $existing ): bool {
		foreach ( array( 'cmdb_id', 'tenable_uuid', 'intune_id', 'defender_id' ) as $id ) {
			$incoming = trim( (string) ( $data[ $id ] ?? '' ) );
			$held     = trim( (string) ( $existing[ $id ] ?? '' ) );

			if ( '' !== $incoming && '' !== $held && $incoming !== $held ) {
				return false;
			}
		}

		return true;
	}


	/**
	 * Record that a new row had to be written beside an existing one of the
	 * same name, because the two disagree on an identifier that cannot be
	 * wrong. Once per hostname per run: a 228,000-row import must not write
	 * 228,000 audit rows.
	 *
	 * @param string              $hostname Hostname both rows carry.
	 * @param int                 $twin_id  The row already holding it.
	 * @param array<string,mixed> $data     Incoming asset fields.
	 */
	private static function note_hostname_clash( string $hostname, int $twin_id, array $data ): void {
		static $told = array();

		$hostname = strtolower( trim( $hostname ) );

		if ( '' === $hostname || isset( $told[ $hostname ] ) ) {
			return;
		}

		$told[ $hostname ] = true;

		( new Logger() )->audit(
			'asset.duplicate_hostname',
			sprintf(
				/* translators: 1: hostname, 2: existing asset id. */
				__( '%1$s was imported as a second asset; asset %2$d already had that hostname but a different identifier.', 'vulnhub' ),
				$hostname,
				$twin_id
			),
			'asset',
			$twin_id,
			array(
				'hostname' => $hostname,
				'incoming' => array_intersect_key(
					$data,
					array_flip( array( 'primary_source', 'tenable_uuid', 'intune_id', 'defender_id', 'cmdb_id', 'serial_number', 'fqdn', 'ipv4' ) )
				),
			),
			'warning'
		);
	}

	/**
	 * Every domain suffix the estate actually uses, longest first.
	 *
	 * Read from the FQDNs already stored rather than configured, so it
	 * follows the estate instead of needing to be kept in step with it.
	 * Cached for the life of the request: an import asks this once per row.
	 *
	 * @return array<int,string>
	 */
	private static function known_domains(): array {
		static $cache = null;

		if ( null !== $cache ) {
			return $cache;
		}

		global $wpdb;

		$table = vh_table( 'assets' );
		$rows  = (array) $wpdb->get_col(
			"SELECT DISTINCT SUBSTRING( fqdn, LOCATE( '.', fqdn ) + 1 )
			 FROM {$table} WHERE fqdn LIKE '%.%' LIMIT 200" // phpcs:ignore WordPress.DB.PreparedSQL
		);

		$cache = array_values(
			array_filter(
				array_map( 'strtolower', array_map( 'strval', $rows ) ),
				static fn( string $d ): bool => str_contains( $d, '.' ) && strlen( $d ) < 190
			)
		);

		// Longest first, so `au.metering.elec.mass.security` is tried before
		// `mass.security` and the short name comes out whole.
		usort( $cache, static fn( string $a, string $b ): int => strlen( $b ) <=> strlen( $a ) );

		return $cache;
	}

	/**
	 * A hostname that is really an FQDN with its dots flattened to dashes.
	 *
	 * Defender exports five Linux servers on this estate as
	 * `nzaklp1mcapprh1-amssmp-local`, which matched nothing and became five
	 * second copies of machines the CMDB already held -- each reading "Not
	 * in Tenable" beside the row that was being scanned. Only suffixes the
	 * estate actually uses are accepted, so an ordinary hyphenated name like
	 * `aws-bc-syslog-01` is never mistaken for one.
	 *
	 * @param string $host Hostname, lowercased.
	 * @return array{host:string,fqdn:string}|array{}
	 */
	private static function dashed_fqdn( string $host ): array {
		if ( '' === $host || str_contains( $host, '.' ) || ! str_contains( $host, '-' ) ) {
			return array();
		}

		foreach ( self::known_domains() as $domain ) {
			$suffix = '-' . str_replace( '.', '-', $domain );

			if ( ! str_ends_with( $host, $suffix ) ) {
				continue;
			}

			$short = substr( $host, 0, -strlen( $suffix ) );

			if ( '' !== $short ) {
				return array(
					'host' => $short,
					'fqdn' => $short . '.' . $domain,
				);
			}
		}

		return array();
	}

	/**
	 * The asset a record is about, or null.
	 *
	 * One matching chain, used by `upsert_asset()` and by any importer that
	 * needs to know what it is about to write to before it writes. Every
	 * feed asking the same question the same way is the point: the Defender
	 * importer had its own narrower version, and the two disagreeing is how
	 * an estate ends up with a machine in it twice.
	 *
	 * Order is strongest evidence first:
	 *
	 *  1. an identifier issued by a system -- Tenable, Intune, Defender,
	 *     Entra, a cloud instance id, the CMDB number, a serial;
	 *  2. the name, in every spelling this record offers: the hostname, the
	 *     label in front of its FQDN, and the FQDN read back out of a
	 *     dash-flattened hostname. A stored row is compared on the same
	 *     three, so `aws-bc-index-se` (Tenable, truncated to the NetBIOS
	 *     limit of 15) and `aws-bc-index-server` (the CMDB) meet on the FQDN
	 *     they share;
	 *  3. a 15-character name that is the truncation of a longer one, but
	 *     only where the address agrees as well;
	 *  4. the address alone, and only for feeds that cannot create assets.
	 *     A DHCP lease is not an identity: 405 pairs of distinct machines on
	 *     this estate share one, and matching on it would fold them together.
	 *
	 * @param array<string,mixed> $data Asset fields; `match_only` widens step 4.
	 * @return array<string,mixed>|null
	 */
	public static function match_asset( array $data ): ?array {
		global $wpdb;

		$table  = vh_table( 'assets' );
		$select = "SELECT id, sources_json, primary_source, cmdb_id, tenable_uuid, intune_id, defender_id, hostname, fqdn, ipv4 FROM {$table}";

		// Callers other than `upsert_asset()` hand over raw column values.
		$data = self::normalise_names( $data );

		$strong = array(
			'tenable_uuid'       => (string) ( $data['tenable_uuid'] ?? '' ),
			'intune_id'          => (string) ( $data['intune_id'] ?? '' ),
			'defender_id'        => (string) ( $data['defender_id'] ?? '' ),
			'azure_ad_device_id' => (string) ( $data['azure_ad_device_id'] ?? '' ),
			'azure_vm_id'        => (string) ( $data['azure_vm_id'] ?? '' ),
			'aws_instance_id'    => (string) ( $data['aws_instance_id'] ?? '' ),
			'cmdb_id'            => (string) ( $data['cmdb_id'] ?? '' ),
			'serial_number'      => (string) ( $data['serial_number'] ?? '' ),
		);

		foreach ( $strong as $column => $value ) {
			if ( '' === $value ) {
				continue;
			}

			/*
			 * "LPAR" on every AIX partition, "Not Applicable" on everything
			 * virtual, "To Be Filled By O.E.M." straight from the BIOS. These
			 * are words in a serial column, not serial numbers, and matching on
			 * them folded seven distinct partitions into one asset.
			 */
			if ( 'serial_number' === $column && '' === vh_clean_serial( $value ) ) {
				continue;
			}

			$row = $wpdb->get_row(
				$wpdb->prepare( $select . " WHERE {$column} = %s LIMIT 1", $value ), // phpcs:ignore WordPress.DB.PreparedSQL
				ARRAY_A
			);

			/*
			 * A serial that matches a row already carrying a different CI
			 * number is not the same machine, whatever the serial says. Two
			 * CIs in one live export shared a VMware UUID; because serial is
			 * tried before hostname, the second silently overwrote the first.
			 */
			if ( $row && 'serial_number' === $column && ! self::identities_agree( $data, $row ) ) {
				continue;
			}

			if ( $row ) {
				return $row;
			}
		}

		$host  = strtolower( trim( (string) ( $data['hostname'] ?? '' ) ) );
		$fqdn  = strtolower( trim( (string) ( $data['fqdn'] ?? '' ) ) );
		$short = '' !== $fqdn ? (string) strtok( $fqdn, '.' ) : '';

		$names = array();
		$fqdns = array();

		foreach ( array( $host, $short ) as $name ) {
			if ( '' !== $name ) {
				$names[ $name ] = true;
			}
		}
		if ( '' !== $fqdn ) {
			$fqdns[ $fqdn ] = true;
		}

		$dashed = self::dashed_fqdn( $host );

		if ( $dashed ) {
			$names[ $dashed['host'] ] = true;
			$fqdns[ $dashed['fqdn'] ] = true;
		}

		$names = array_keys( $names );
		$fqdns = array_keys( $fqdns );

		if ( $names || $fqdns ) {
			$where  = array();
			$params = array();

			if ( $names ) {
				$in       = implode( ', ', array_fill( 0, count( $names ), '%s' ) );
				$where[]  = "hostname IN ({$in})";
				$params   = array_merge( $params, $names );
				$where[]  = "( fqdn <> '' AND SUBSTRING_INDEX( fqdn, '.', 1 ) IN ({$in}) )";
				$params   = array_merge( $params, $names );
			}

			if ( $fqdns ) {
				$in      = implode( ', ', array_fill( 0, count( $fqdns ), '%s' ) );
				$where[] = "fqdn IN ({$in})";
				$params  = array_merge( $params, $fqdns );
			}

			// Exact hostname is the answer if there is one; the softer
			// spellings only decide it when there is not.
			$order    = '' !== $host ? 'ORDER BY ( hostname = %s ) DESC, ( fqdn = %s ) DESC, id ASC' : 'ORDER BY id ASC';
			$params[] = $host;
			$params[] = $fqdn;

			if ( '' === $host ) {
				array_pop( $params );
				array_pop( $params );
			}

			$row = $wpdb->get_row(
				$wpdb->prepare( $select . ' WHERE ' . implode( ' OR ', $where ) . ' ' . $order . ' LIMIT 1', $params ), // phpcs:ignore WordPress.DB.PreparedSQL
				ARRAY_A
			);

			if ( $row && ! self::names_may_join( $data, $row ) ) {
				$row = null;
			}

			if ( $row ) {
				return $row;
			}
		}

		/*
		 * A NetBIOS name is capped at 15 characters, so `aws-bc-printapp`
		 * and `aws-bc-printapp-01` can be one machine. Corroborated by the
		 * address, because on its own a 15-character prefix would also
		 * match `nzwlghypeapprh1-legacy`, which is a different server on a
		 * different address.
		 */
		$ip = vh_clean_ip( (string) ( $data['ipv4'] ?? '' ) );

		if ( 15 === strlen( $host ) && '' !== $ip ) {
			$row = $wpdb->get_row(
				$wpdb->prepare(
					$select . ' WHERE hostname LIKE %s AND hostname <> %s AND ipv4 = %s ORDER BY id ASC LIMIT 1',
					$wpdb->esc_like( $host ) . '%',
					$host,
					$ip
				),
				ARRAY_A
			);

			if ( $row && self::names_may_join( $data, $row ) ) {
				return $row;
			}
		}

		if ( '' !== $ip && ! empty( $data['match_only'] ) ) {
			$row = $wpdb->get_row(
				$wpdb->prepare( $select . ' WHERE ipv4 = %s LIMIT 1', $ip ),
				ARRAY_A
			);

			if ( $row && self::names_may_join( $data, $row ) ) {
				return $row;
			}
		}

		return null;
	}

	/**
	 * May a record join a row it matched on nothing but a name or address?
	 *
	 * Only the CMDB number is tested. It is assigned by people and outlives
	 * a rebuild, so two rows holding different ones are two machines that
	 * happen to share a name -- and folding them together silently moved one
	 * team's findings onto another team's asset. A Tenable, Intune or
	 * Defender id is re-issued on re-enrolment, so testing those would split
	 * every re-imaged laptop in two, which is the fault this whole chain
	 * exists to prevent.
	 *
	 * @param array<string,mixed> $data     Incoming asset fields.
	 * @param array<string,mixed> $existing The row that matched.
	 */
	private static function names_may_join( array $data, array $existing ): bool {
		$ours   = trim( (string) ( $data['cmdb_id'] ?? '' ) );
		$theirs = trim( (string) ( $existing['cmdb_id'] ?? '' ) );

		if ( '' === $ours || '' === $theirs || $ours === $theirs ) {
			return true;
		}

		self::note_hostname_clash(
			(string) ( $data['hostname'] ?? ( $existing['hostname'] ?? '' ) ),
			(int) $existing['id'],
			$data
		);

		return false;
	}


	/**
	 * Which spelling of a machine's name is allowed to be written.
	 *
	 * The hostname is what the platform identifies a machine by, so it is
	 * the one field a feed must not be able to quietly degrade. Every export
	 * has its own way of getting it wrong: Tenable truncates to the NetBIOS
	 * limit of 15 (`aws-bc-index-se`), Defender flattens the FQDN's dots
	 * (`nzaklp1mcapprh1-amssmp-local`), and AWS answers with the address it
	 * gave the instance (`ip-10-31-3-194`). Left to overwrite, any of them
	 * renames the asset on the next import and the estate loses the name its
	 * people use.
	 *
	 * The CMDB decides names. Where it has no opinion, a later feed may set
	 * one, but never replace a name with a worse rendering of the same name.
	 *
	 * @param string              $incoming Hostname the record carries.
	 * @param array<string,mixed> $existing The row being written to.
	 * @param array<string,mixed> $data     Incoming asset fields.
	 * @return string|null The name to write, or null to keep what is stored.
	 */
	private static function authoritative_hostname( string $incoming, array $existing, array $data ): ?string {
		$incoming = strtolower( trim( $incoming ) );
		$stored   = strtolower( trim( (string) ( $existing['hostname'] ?? '' ) ) );

		if ( '' === $incoming || $incoming === $stored ) {
			return null;
		}

		if ( '' === $stored ) {
			return $incoming;
		}

		if ( 'cmdb' === vh_normalise_source( (string) ( $data['source'] ?? $data['primary_source'] ?? '' ) ) ) {
			return $incoming;
		}

		// A name the CMDB has already settled is not up for revision.
		if ( '' !== trim( (string) ( $existing['cmdb_id'] ?? '' ) ) ) {
			return null;
		}

		// The stored name, cut off at the NetBIOS limit.
		if ( 15 === strlen( $incoming ) && str_starts_with( $stored, $incoming ) ) {
			return null;
		}

		// The stored name with its dots flattened to dashes.
		$read = self::dashed_fqdn( $incoming );

		if ( $read && $read['host'] === $stored ) {
			return null;
		}

		// A cloud instance's default name against one a person chose.
		if ( 1 === preg_match( '/^ip-\d+-\d+-\d+-\d+$/', $incoming )
			&& 1 !== preg_match( '/^ip-\d+-\d+-\d+-\d+$/', $stored ) ) {
			return null;
		}

		return $incoming;
	}

	public static function upsert_asset( array $data ): array {
		global $wpdb;

		$table = vh_table( 'assets' );

		/*
		 * One spelling of a machine's name, settled before anything is matched
		 * on it.
		 *
		 * Tenable reports `nzaklmgtrh1.amssmp.local` in its hostname field and
		 * the CMDB reports `nzaklmgtrh1`. Stored as they arrive, those are two
		 * assets: the findings land on one row and the owner, site and
		 * lifecycle on the other, and the estate reports a scanning gap for a
		 * machine it is scanning. The domain is not discarded -- it moves to
		 * `fqdn`, which is where the rest of the platform already looks.
		 */
		$data = self::normalise_names( $data );

		$existing = self::match_asset( $data );

		/*
		 * A CMDB record that has not shown two of an address, a qualified
		 * name and a CI number -- or that does not say In Service -- is a
		 * record, not a machine. It is held rather than written: an asset
		 * nothing can scan, own or close is a coverage gap nobody can ever
		 * act on, and it is counted in every total forever. If a scanner or
		 * sensor later proves the machine is real, the hold is released on
		 * to it with everything the CMDB knew. Enrichment is untouched --
		 * this only ever declines to create.
		 */
		if ( ! $existing && self::fails_existence_rule( $data ) ) {
			return array(
				'id'      => 0,
				'created' => false,
				'matched' => false,
				'held'    => self::hold_stale_record( $data ) > 0,
			);
		}

		if ( ! $existing && ! empty( $data['match_only'] ) ) {
			return array(
				'id'      => 0,
				'created' => false,
				'matched' => false,
			);
		}

		$row = array();
		$map = array(
			'primary_source', 'tenable_uuid', 'intune_id', 'azure_ad_device_id', 'cmdb_id',
			'defender_id', 'defender_onboarding', 'defender_health', 'defender_risk',
			'defender_exposure', 'defender_managed_by', 'defender_coverage_state',
			'azure_vm_id', 'aws_instance_id', 'gcp_instance_id',
			'cloud_provider', 'cloud_account_id', 'cloud_region', 'patch_group', 'cmdb_key', 'sources_json',
			'hostname', 'fqdn', 'netbios_name', 'ipv4', 'ipv6', 'mac_address', 'serial_number',
			'asset_type', 'operating_system', 'os_version', 'manufacturer', 'model',
			'criticality', 'environment', 'business_service', 'compliance_state', 'lifecycle_status',
			'enrollment_type', 'join_type', 'owner_source', 'owner_confidence', 'owner_rule',
		);
		foreach ( $map as $key ) {
			if ( ! isset( $data[ $key ] ) || '' === $data[ $key ] ) {
				continue;
			}

			$value = (string) $data[ $key ];

			switch ( $key ) {
				case 'hostname':
				case 'fqdn':
					$value = strtolower( trim( $value ) );
					break;
				case 'ipv4':
					// "DHCP", "N/A" and friends are not addresses.
					$value = vh_clean_ip( $value );
					break;
				case 'mac_address':
					$value = vh_clean_mac( $value );
					break;
				case 'lifecycle_status':
					$value = array_key_exists( $value, vh_lifecycle_statuses() )
						? $value
						: vh_normalise_lifecycle( $value );
					break;
			}

			if ( '' !== $value ) {
				$row[ $key ] = $value;
			}
		}

		foreach ( array( 'has_agent', 'is_managed' ) as $flag ) {
			if ( isset( $data[ $flag ] ) ) {
				$row[ $flag ] = (int) (bool) $data[ $flag ];
			}
		}
		foreach ( array( 'owner_person_id', 'team_id', 'location_id' ) as $fk ) {
			if ( isset( $data[ $fk ] ) ) {
				$row[ $fk ] = (int) $data[ $fk ];
			}
		}
		foreach ( array( 'first_seen', 'last_seen', 'last_intune_sync', 'cmdb_last_scan', 'support_end_date', 'defender_first_seen', 'defender_last_seen' ) as $ts ) {
			if ( ! empty( $data[ $ts ] ) ) {
				$row[ $ts ] = vh_to_mysql( $data[ $ts ] );
			}
		}
		if ( isset( $data['ipv4s'] ) ) {
			$all  = is_array( $data['ipv4s'] ) ? $data['ipv4s'] : explode( ',', (string) $data['ipv4s'] );
			$all  = array_values( array_filter( array_map( 'vh_clean_ip', array_map( 'strval', $all ) ) ) );
			$row['ipv4s'] = implode( ',', $all );

			// A third of assets in a real Tenable export carry several
			// addresses; keep the first as the primary when none was given.
			if ( $all && empty( $row['ipv4'] ) ) {
				$row['ipv4'] = $all[0];
			}
		}
		if ( isset( $data['tags'] ) ) {
			$row['tags_json'] = (string) wp_json_encode( $data['tags'] );
		}
		if ( isset( $data['software'] ) ) {
			$row['software_json'] = (string) wp_json_encode( $data['software'] );
		}
		if ( isset( $data['raw'] ) ) {
			$row['raw_json'] = (string) wp_json_encode( $data['raw'] );
		}

		/*
		 * The name is settled before anything else is written, because it is
		 * what every other feed will match this asset on tomorrow.
		 */
		if ( $existing && isset( $row['hostname'] ) ) {
			$name = self::authoritative_hostname( (string) $row['hostname'], $existing, $data );

			if ( null === $name ) {
				unset( $row['hostname'] );
			} else {
				$row['hostname'] = $name;
			}
		}

		/*
		 * Sources accumulate; they are never replaced. `primary_source` is a
		 * single column and so records only whichever feed wrote last -- on
		 * this estate 474 assets that Intune, Tenable and the CMDB all know
		 * about said simply "tenable", because the Tenable import ran most
		 * recently. That is not wrong so much as unanswerable: the question
		 * a reader asks of an asset is "where did this come from", and the
		 * honest answer is usually more than one system.
		 */
		$claimed = vh_normalise_source( (string) ( $data['source'] ?? $data['primary_source'] ?? '' ) );

		if ( '' !== $claimed ) {
			$seen = $existing ? self::source_map( (string) ( $existing['sources_json'] ?? '' ) ) : array();

			/*
			 * The date matters as much as the name. "Both the CMDB and Intune
			 * know this laptop" is interesting; "the CMDB last claimed it in
			 * March and Intune saw it yesterday" is the fact that tells you
			 * which of the two needs cleaning up.
			 */
			$seen[ $claimed ] = gmdate( 'Y-m-d' );

			if ( count( $seen ) > 6 ) {
				$seen = array_slice( $seen, -6, null, true );
			}

			$row['sources_json'] = (string) wp_json_encode( $seen );
		}

		/*
		 * `primary_source` answers "whose record is this", and the answer is
		 * the CMDB wherever the CMDB has one. It is the register the estate
		 * is actually run from -- the CI number, the owner, the lifecycle --
		 * so a machine it knows is its record, whichever scanner happened to
		 * see the machine first.
		 *
		 * Otherwise it is written once and left alone. Letting every import
		 * overwrite it is what made the column read "tenable" for most of
		 * the estate: it recorded running order, not provenance.
		 */
		$held_source  = (string) ( $existing['primary_source'] ?? '' );
		$claim_source = vh_normalise_source( (string) ( $data['source'] ?? $data['primary_source'] ?? '' ) );

		if ( $existing && '' !== $held_source
			&& ! ( 'cmdb' === $claim_source && 'cmdb' !== vh_normalise_source( $held_source ) ) ) {
			unset( $row['primary_source'] );
		}

		if ( $existing && 'cmdb' === $claim_source && 'cmdb' !== vh_normalise_source( $held_source ) ) {
			$row['primary_source'] = (string) ( $data['source'] ?? $data['primary_source'] ?? 'cmdb' );
		}

		$row['last_synced_at'] = vh_now();
		$row['updated_at']     = vh_now();

		if ( $existing ) {
			$wpdb->update( $table, $row, array( 'id' => (int) $existing['id'] ) );

			self::release_stale_record(
				(string) ( $row['hostname'] ?? $existing['hostname'] ?? '' ),
				(int) $existing['id']
			);

			return array(
				'id'      => (int) $existing['id'],
				'created' => false,
				'matched' => true,
			);
		}

		/*
		 * Last look before a second row exists for one machine.
		 *
		 * Nothing above matched, but the estate may still hold this hostname
		 * under identifiers this feed does not carry -- which is exactly how
		 * the Tenable vulnerability export, whose rows name a host and nothing
		 * else, wrote a second `bchybxj5albjqmd` beside the one Intune and the
		 * CMDB already knew. The findings landed on one row and the owner,
		 * site and lifecycle on the other, and the coverage figure reported a
		 * scanning gap for a machine Tenable was scanning weekly.
		 *
		 * Where the two disagree on a strong identifier they are different
		 * machines that happen to share a name, and the row is still written
		 * -- but the clash is recorded rather than left to be discovered on a
		 * dashboard months later.
		 */
		$twin = self::hostname_twin( (string) ( $data['hostname'] ?? '' ) );

		if ( $twin ) {
			if ( self::identities_agree( $data, $twin ) ) {
				if ( '' !== (string) ( $twin['primary_source'] ?? '' ) ) {
					unset( $row['primary_source'] );
				}

				$seen = self::source_map( (string) ( $twin['sources_json'] ?? '' ) );
				$claimed = vh_normalise_source( (string) ( $data['source'] ?? $data['primary_source'] ?? '' ) );

				if ( '' !== $claimed ) {
					$seen[ $claimed ]    = gmdate( 'Y-m-d' );
					$row['sources_json'] = (string) wp_json_encode( array_slice( $seen, -6, null, true ) );
				}

				$wpdb->update( $table, $row, array( 'id' => (int) $twin['id'] ) );

				return array(
					'id'      => (int) $twin['id'],
					'created' => false,
					'matched' => true,
				);
			}

			self::note_hostname_clash( (string) ( $data['hostname'] ?? '' ), (int) $twin['id'], $data );
		}

		/*
		 * A feed that names itself in `source` has named itself. Without this
		 * the column default said `tenable` for every row created by anything
		 * that did not also spell out `primary_source` -- so a machine the CMDB
		 * discovered was filed as Tenable's.
		 */
		if ( empty( $row['primary_source'] ) && '' !== $claimed ) {
			$row['primary_source'] = (string) ( $data['source'] ?? $claimed );
		}

		$row['created_at'] = vh_now();
		$row['first_seen'] = $row['first_seen'] ?? vh_now();
		$wpdb->insert( $table, $row );

		$new_id = (int) $wpdb->insert_id;

		self::release_stale_record( (string) ( $row['hostname'] ?? '' ), $new_id );

		return array(
			'id'      => $new_id,
			'created' => true,
			'matched' => true,
		);
	}

	/**
	 * @return array<string,mixed>|null
	 */
	/**
	 * Another asset row carrying the same hostname.
	 *
	 * A hostname is unique on an estate in practice, so two rows holding the
	 * same one are one machine split in half -- and the half the scanner
	 * wrote to is the half the coverage figure believes. That split is how
	 * `bchybxj5albjqmd` came to read "Not in Tenable" on the row the CMDB,
	 * Intune and Defender all knew, while a second row of the same name held
	 * its thirty-one Tenable findings and no owner at all. It happened
	 * because Tenable reports `host.amssmp.local` where every other feed
	 * reports `host`: before `normalise_names()` settled that, the dotted
	 * form matched nothing and a new asset was written instead.
	 *
	 * Names are settled now, so this guards what remains -- a twin already
	 * on disk, or one made by any future feed that identifies a machine a
	 * way this one does not.
	 *
	 * @param string $hostname   Hostname, already normalised.
	 * @param int    $exclude_id Row to ignore (0 for none).
	 * @return array<string,mixed>|null
	 */
	public static function hostname_twin( string $hostname, int $exclude_id = 0 ): ?array {
		global $wpdb;

		$hostname = strtolower( trim( $hostname ) );

		if ( '' === $hostname ) {
			return null;
		}

		$table = vh_table( 'assets' );

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, sources_json, primary_source, cmdb_id, tenable_uuid, intune_id, defender_id
				 FROM {$table} WHERE hostname = %s AND id <> %d ORDER BY id ASC LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL
				$hostname,
				$exclude_id
			),
			ARRAY_A
		);

		return $row ?: null;
	}

	/**
	 * Could these two rows be merged without losing an identity?
	 *
	 * @param array<string,mixed> $data     Incoming asset fields.
	 * @param array<string,mixed> $existing Candidate row.
	 */
	public static function could_be_same_asset( array $data, array $existing ): bool {
		return self::identities_agree( $data, $existing );
	}

	/**
	 * Fold one asset row into another and delete the loser.
	 *
	 * Findings, tickets, exceptions and classification state move across;
	 * every identity, address and date the surviving row is missing is taken
	 * from the row being dropped, and nothing it already holds is
	 * overwritten. Identifiers that cannot fit -- a second Tenable UUID for
	 * the same machine -- are kept in `raw_json` under `merged` rather than
	 * thrown away, so the trail back to the other record survives.
	 *
	 * Callers are expected to run `recalculate_asset_rollups()` and
	 * `Coverage::recalculate()` once afterwards, not once per merge.
	 *
	 * @param int  $keep_id Row that survives.
	 * @param int  $drop_id Row that is folded in and deleted.
	 * @param bool $dry_run Report what would happen, change nothing.
	 * @return array<string,mixed> {merged:bool, reason:string, moved:array<string,int>, took:array<string,mixed>}
	 */
	public static function merge_assets( int $keep_id, int $drop_id, bool $dry_run = false ): array {
		global $wpdb;

		$out = array(
			'merged' => false,
			'reason' => '',
			'moved'  => array(),
			'took'   => array(),
		);

		if ( $keep_id === $drop_id || ! $keep_id || ! $drop_id ) {
			$out['reason'] = 'same-or-empty';
			return $out;
		}

		$keep = self::asset( $keep_id );
		$drop = self::asset( $drop_id );

		if ( ! $keep || ! $drop ) {
			$out['reason'] = 'missing';
			return $out;
		}

		$table = vh_table( 'assets' );

		/*
		 * Identity, address and hardware columns. First non-empty answer
		 * wins and the survivor already had first refusal, so a merge can
		 * only ever add to what is known about a machine.
		 */
		$fill = array(
			'tenable_uuid', 'intune_id', 'azure_ad_device_id', 'azure_vm_id', 'aws_instance_id',
			'gcp_instance_id', 'cmdb_id', 'cmdb_key', 'defender_id', 'serial_number',
			'netbios_name', 'fqdn', 'ipv4', 'ipv6', 'mac_address',
			'operating_system', 'os_version', 'manufacturer', 'model',
			'environment', 'business_service', 'compliance_state', 'patch_group',
			'cloud_provider', 'cloud_account_id', 'cloud_region',
			'enrollment_type', 'join_type',
			'defender_onboarding', 'defender_health', 'defender_risk', 'defender_exposure',
			'defender_managed_by',
		);

		$row = array();

		foreach ( $fill as $column ) {
			$mine   = trim( (string) ( $keep[ $column ] ?? '' ) );
			$theirs = trim( (string) ( $drop[ $column ] ?? '' ) );

			if ( '' === $mine && '' !== $theirs ) {
				$row[ $column ]          = $theirs;
				$out['took'][ $column ] = $theirs;
			}
		}

		foreach ( array( 'owner_person_id', 'team_id', 'location_id' ) as $fk ) {
			if ( ! (int) ( $keep[ $fk ] ?? 0 ) && (int) ( $drop[ $fk ] ?? 0 ) ) {
				$row[ $fk ]          = (int) $drop[ $fk ];
				$out['took'][ $fk ] = (int) $drop[ $fk ];
			}
		}

		foreach ( array( 'has_agent', 'is_managed' ) as $flag ) {
			if ( ! (int) ( $keep[ $flag ] ?? 0 ) && (int) ( $drop[ $flag ] ?? 0 ) ) {
				$row[ $flag ] = 1;
			}
		}

		// Earliest first sighting, latest of everything else.
		foreach ( array( 'first_seen' => 'min', 'last_seen' => 'max', 'last_intune_sync' => 'max', 'cmdb_last_scan' => 'max', 'tenable_last_scan' => 'max', 'defender_first_seen' => 'min', 'defender_last_seen' => 'max' ) as $ts => $pick ) {
			$mine   = (string) ( $keep[ $ts ] ?? '' );
			$theirs = (string) ( $drop[ $ts ] ?? '' );

			if ( '' === $theirs ) {
				continue;
			}
			if ( '' === $mine ) {
				$row[ $ts ] = $theirs;
				continue;
			}

			$row[ $ts ] = 'min' === $pick ? min( $mine, $theirs ) : max( $mine, $theirs );
		}

		// Addresses union, survivor's primary first.
		$ips = array_values(
			array_unique(
				array_filter(
					array_merge(
						explode( ',', (string) ( $keep['ipv4s'] ?? '' ) ),
						explode( ',', (string) ( $drop['ipv4s'] ?? '' ) )
					)
				)
			)
		);

		if ( $ips ) {
			$row['ipv4s'] = implode( ',', array_slice( $ips, 0, 20 ) );
		}

		// Sources accumulate here exactly as they do on import.
		$seen = self::source_map( (string) ( $keep['sources_json'] ?? '' ) );

		foreach ( self::source_map( (string) ( $drop['sources_json'] ?? '' ) ) as $slug => $date ) {
			if ( ! isset( $seen[ $slug ] ) || $date > $seen[ $slug ] ) {
				$seen[ $slug ] = $date;
			}
		}

		if ( $seen ) {
			$row['sources_json'] = (string) wp_json_encode( array_slice( $seen, -6, null, true ) );
		}

		// Identifiers with nowhere to go are recorded, not discarded.
		$raw     = json_decode( (string) ( $keep['raw_json'] ?? '' ), true );
		$raw     = is_array( $raw ) ? $raw : array();
		$theirs  = json_decode( (string) ( $drop['raw_json'] ?? '' ), true );
		$dropped = array(
			'asset_id'   => $drop_id,
			'merged_at'  => vh_now(),
			'hostname'   => (string) ( $drop['hostname'] ?? '' ),
			'raw'        => is_array( $theirs ) ? $theirs : null,
		);

		foreach ( array( 'tenable_uuid', 'intune_id', 'defender_id', 'cmdb_id', 'serial_number', 'ipv4', 'fqdn' ) as $column ) {
			$theirs_value = trim( (string) ( $drop[ $column ] ?? '' ) );

			if ( '' !== $theirs_value && $theirs_value !== trim( (string) ( $keep[ $column ] ?? '' ) ) && ! isset( $row[ $column ] ) ) {
				$dropped['also'][ $column ] = $theirs_value;
			}
		}

		$raw['merged']   = array_slice( array_merge( (array) ( $raw['merged'] ?? array() ), array( $dropped ) ), -5 );
		$row['raw_json'] = (string) wp_json_encode( $raw );

		if ( $dry_run ) {
			$out['merged'] = true;
			$out['reason'] = 'dry-run';
			$out['moved']  = array(
				'findings'   => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . vh_table( 'findings' ) . ' WHERE asset_id = %d', $drop_id ) ),
				'tickets'    => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . ' WHERE asset_id = %d', $drop_id ) ),
				'exceptions' => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . vh_table( 'exceptions' ) . ' WHERE asset_id = %d', $drop_id ) ),
			);
			return $out;
		}

		foreach ( array( 'findings', 'tickets', 'exceptions' ) as $child ) {
			$child_table          = vh_table( $child );
			$out['moved'][ $child ] = (int) $wpdb->query(
				$wpdb->prepare( "UPDATE {$child_table} SET asset_id = %d WHERE asset_id = %d", $keep_id, $drop_id ) // phpcs:ignore WordPress.DB.PreparedSQL
			);
		}

		/*
		 * One row per asset, so these move only into a vacancy; where the
		 * survivor already has its own, the dropped row's is discarded
		 * rather than colliding with it.
		 */
		foreach ( array( 'asset_exposure', 'class_asset_state' ) as $single ) {
			$single_table = vh_table( $single );
			$held         = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$single_table} WHERE asset_id = %d", $keep_id ) ); // phpcs:ignore WordPress.DB.PreparedSQL

			if ( $held ) {
				$wpdb->query( $wpdb->prepare( "DELETE FROM {$single_table} WHERE asset_id = %d", $drop_id ) ); // phpcs:ignore WordPress.DB.PreparedSQL
				continue;
			}

			$out['moved'][ $single ] = (int) $wpdb->query(
				$wpdb->prepare( "UPDATE {$single_table} SET asset_id = %d WHERE asset_id = %d", $keep_id, $drop_id ) // phpcs:ignore WordPress.DB.PreparedSQL
			);
		}

		$row['updated_at'] = vh_now();

		$wpdb->update( $table, $row, array( 'id' => $keep_id ) );
		$wpdb->delete( $table, array( 'id' => $drop_id ) );

		( new Logger() )->audit(
			'asset.merged',
			sprintf(
				/* translators: 1: surviving asset id, 2: dropped asset id, 3: hostname. */
				__( 'Asset %2$d was folded into %1$d; both were %3$s.', 'vulnhub' ),
				$keep_id,
				$drop_id,
				(string) ( $keep['hostname'] ?? '' )
			),
			'asset',
			$keep_id,
			array(
				'dropped' => $drop_id,
				'moved'   => $out['moved'],
				'took'    => $out['took'],
			)
		);

		$out['merged'] = true;
		$out['reason'] = 'merged';

		return $out;
	}

	/**
	 * Every hostname held by more than one asset row.
	 *
	 * @return array<int,array{hostname:string,ids:array<int,int>}>
	 */
	public static function duplicate_hostnames(): array {
		global $wpdb;

		$table = vh_table( 'assets' );
		$rows  = (array) $wpdb->get_results(
			"SELECT hostname, GROUP_CONCAT(id ORDER BY id ASC) AS ids, COUNT(*) AS n
			 FROM {$table} WHERE hostname <> ''
			 GROUP BY hostname HAVING n > 1 ORDER BY hostname ASC", // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		$out = array();

		foreach ( $rows as $row ) {
			$out[] = array(
				'hostname' => (string) $row['hostname'],
				'ids'      => array_map( 'intval', explode( ',', (string) $row['ids'] ) ),
			);
		}

		return $out;
	}


	/**
	 * Pairs of rows that look like one machine written down twice.
	 *
	 * The same evidence `match_asset()` matches on, asked backwards of the
	 * rows already stored. Prevention only helps the next import; this is
	 * what finds what earlier ones left behind.
	 *
	 * Each pair is reported once, lower id first, with the evidence that
	 * found it so a person can judge it.
	 *
	 * @return array<int,array{a:int,b:int,reason:string,label:string}>
	 */
	public static function duplicate_candidates(): array {
		global $wpdb;

		$t     = vh_table( 'assets' );
		$pairs = array();

		$add = static function ( int $a, int $b, string $reason, string $label ) use ( &$pairs ): void {
			if ( $a === $b ) {
				return;
			}

			$key = min( $a, $b ) . ':' . max( $a, $b );

			if ( isset( $pairs[ $key ] ) ) {
				return;
			}

			$pairs[ $key ] = array(
				'a'      => min( $a, $b ),
				'b'      => max( $a, $b ),
				'reason' => $reason,
				'label'  => $label,
			);
		};

		$queries = array(
			// One name, two rows. Nothing else needs to agree.
			'same hostname' => "SELECT a.id AS a, b.id AS b, a.hostname AS label
				FROM {$t} a JOIN {$t} b ON b.id > a.id AND a.hostname <> '' AND a.hostname = b.hostname",

			// One fully qualified name, two rows -- how a NetBIOS-truncated
			// `aws-bc-index-se` and the CMDB's `aws-bc-index-server` meet.
			'same FQDN' => "SELECT a.id AS a, b.id AS b, a.fqdn AS label
				FROM {$t} a JOIN {$t} b ON b.id > a.id AND a.fqdn <> '' AND a.fqdn = b.fqdn",

			// One row's name is the label in front of the other's FQDN.
			'name matches the other row\'s FQDN' => "SELECT a.id AS a, b.id AS b, a.hostname AS label
				FROM {$t} a JOIN {$t} b ON b.id <> a.id AND a.hostname <> '' AND b.fqdn <> ''
				 AND a.hostname = SUBSTRING_INDEX( b.fqdn, '.', 1 ) AND a.hostname <> b.hostname",

			// A 15-character NetBIOS truncation, with the address agreeing.
			'NetBIOS truncation on one address' => "SELECT a.id AS a, b.id AS b, b.hostname AS label
				FROM {$t} a JOIN {$t} b ON b.id <> a.id AND CHAR_LENGTH( a.hostname ) = 15
				 AND a.ipv4 <> '' AND a.ipv4 = b.ipv4
				 AND b.hostname LIKE CONCAT( a.hostname, '_%' )",
		);

		foreach ( $queries as $reason => $sql ) {
			foreach ( (array) $wpdb->get_results( $sql, ARRAY_A ) as $row ) { // phpcs:ignore WordPress.DB.PreparedSQL
				$add( (int) $row['a'], (int) $row['b'], (string) $reason, (string) $row['label'] );
			}
		}

		/*
		 * Dash-flattened FQDNs, which no SQL predicate can spot without
		 * knowing which suffixes are domains on this estate.
		 */
		$dashed = (array) $wpdb->get_results(
			"SELECT id, hostname FROM {$t} WHERE hostname LIKE '%-%' AND hostname NOT LIKE '%.%'", // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		foreach ( $dashed as $row ) {
			$read = self::dashed_fqdn( (string) $row['hostname'] );

			if ( ! $read ) {
				continue;
			}

			$twin = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT id FROM {$t} WHERE id <> %d AND ( fqdn = %s OR hostname = %s ) LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL
					(int) $row['id'],
					$read['fqdn'],
					$read['host']
				),
				ARRAY_A
			);

			if ( $twin ) {
				$add( (int) $row['id'], (int) $twin['id'], 'hostname is an FQDN with its dots flattened', (string) $row['hostname'] );
			}
		}

		return array_values( $pairs );
	}

	/**
	 * How well the inventory knows a row, for deciding which of two survives.
	 *
	 * A CMDB number, an ownership, a site: the row a person would recognise
	 * wins, and the scanner's copy is folded into it. Choosing by id instead
	 * would have kept an ownerless `ip-10-31-3-194` and thrown away the
	 * asset the service desk raises tickets against.
	 *
	 * @param array<string,mixed> $row Asset row.
	 */
	private static function inventory_weight( array $row ): int {
		$n = 0;

		$n += '' !== trim( (string) ( $row['cmdb_id'] ?? '' ) ) ? 4 : 0;
		$n += '' !== trim( (string) ( $row['intune_id'] ?? '' ) ) ? 3 : 0;
		$n += '' !== trim( (string) ( $row['defender_id'] ?? '' ) ) ? 3 : 0;
		$n += '' !== trim( (string) ( $row['serial_number'] ?? '' ) ) ? 2 : 0;
		$n += (int) ( $row['owner_person_id'] ?? 0 ) ? 3 : 0;
		$n += (int) ( $row['team_id'] ?? 0 ) ? 1 : 0;
		$n += (int) ( $row['location_id'] ?? 0 ) ? 1 : 0;

		// A name somebody typed beats one a scanner truncated or flattened.
		$n += strlen( (string) ( $row['hostname'] ?? '' ) ) < 15 ? 1 : 0;

		return $n;
	}

	/**
	 * Fold every duplicate the estate is currently carrying.
	 *
	 * Run at the end of each import, so a feed that finds a new way to spell
	 * a machine's name is corrected the same day rather than discovered on a
	 * dashboard months later. Pairs whose CMDB numbers disagree are two
	 * machines that share a name, and are reported rather than merged.
	 *
	 * @param bool $dry_run Report only.
	 * @param bool $force   Merge even where the CMDB numbers disagree.
	 * @return array{merged:array<int,string>,skipped:array<int,string>}
	 */
	public static function sweep_duplicates( bool $dry_run = false, bool $force = false ): array {
		$out = array(
			'merged'  => array(),
			'skipped' => array(),
		);

		foreach ( self::duplicate_candidates() as $pair ) {
			$a = self::asset( $pair['a'] );
			$b = self::asset( $pair['b'] );

			if ( ! $a || ! $b ) {
				// Already folded away by an earlier pair in this same sweep.
				continue;
			}

			$keep = self::inventory_weight( $a ) >= self::inventory_weight( $b ) ? $a : $b;
			$drop = $keep === $a ? $b : $a;

			$clash = trim( (string) $a['cmdb_id'] ) !== '' && trim( (string) $b['cmdb_id'] ) !== ''
				&& trim( (string) $a['cmdb_id'] ) !== trim( (string) $b['cmdb_id'] );

			if ( $clash && ! $force ) {
				$out['skipped'][] = sprintf(
					'%s: assets %d and %d hold different CMDB numbers (%s)',
					$pair['label'],
					(int) $a['id'],
					(int) $b['id'],
					$pair['reason']
				);
				continue;
			}

			$result = self::merge_assets( (int) $keep['id'], (int) $drop['id'], $dry_run );

			if ( empty( $result['merged'] ) ) {
				$out['skipped'][] = sprintf( '%s: %d could not be folded into %d (%s)', $pair['label'], (int) $drop['id'], (int) $keep['id'], (string) $result['reason'] );
				continue;
			}

			$out['merged'][] = sprintf(
				'%s: asset %d -> %d (%s)%s',
				$pair['label'],
				(int) $drop['id'],
				(int) $keep['id'],
				$pair['reason'],
				$clash ? ', CMDB numbers differed' : ''
			);
		}

		return $out;
	}


	/** Held stale names, loaded once per request. */
	private static ?array $held_names = null;

	/**
	 * Has this CMDB record shown enough for the machine to be real?
	 *
	 * A CI record is paperwork. To become an asset it must carry at least
	 * two of an address, a fully qualified name and a CI number -- the
	 * hostname does not count, because a name is what everything has and
	 * what nothing can be checked against -- and it must say the machine is
	 * In Service.
	 *
	 * One of anything is not enough: twenty-two rows on this estate arrived
	 * with a name and a support team and became permanent coverage gaps --
	 * nine "critical production" Oracle app servers no scanner or sensor has
	 * ever seen, eleven already-retired hosts, and two SOE image templates
	 * that are not machines at all. Nothing could scan them, own them or
	 * close them, and every total counted them.
	 *
	 * Two exemptions, and both matter:
	 *
	 *  - Only the CMDB is judged. It is where records are created from
	 *    paperwork, so it is where paperwork-only records come from.
	 *  - A record carrying a Tenable, Defender, Intune or cloud id is never
	 *    held. Those systems report machines they actually touched, so their
	 *    word is evidence rather than paperwork and it overrides this test.
	 *    Judging a Defender-discovered laptop -- a name and a device id, no
	 *    more -- by this rule would delete 44 machines on this estate whose
	 *    sensors are reporting right now.
	 *
	 * @param array<string,mixed> $data Asset fields.
	 */
	public static function fails_existence_rule( array $data ): bool {
		if ( 'cmdb' !== vh_normalise_source( (string) ( $data['source'] ?? $data['primary_source'] ?? '' ) ) ) {
			return false;
		}

		// No name means nothing to hold it by, and nothing to release it to.
		if ( '' === strtolower( trim( (string) ( $data['hostname'] ?? '' ) ) ) ) {
			return false;
		}

		foreach ( array( 'tenable_uuid', 'defender_id', 'intune_id', 'azure_ad_device_id', 'azure_vm_id', 'aws_instance_id', 'gcp_instance_id' ) as $seen_by ) {
			if ( '' !== trim( (string) ( $data[ $seen_by ] ?? '' ) ) ) {
				return false;
			}
		}

		$evidence = 0;

		$addresses = $data['ipv4s'] ?? '';
		$addresses = is_array( $addresses ) ? $addresses : explode( ',', (string) $addresses );
		$addresses[] = (string) ( $data['ipv4'] ?? '' );

		foreach ( $addresses as $address ) {
			if ( '' !== vh_clean_ip( (string) $address ) ) {
				++$evidence;
				break;
			}
		}

		if ( '' !== trim( (string) ( $data['fqdn'] ?? '' ) ) ) {
			++$evidence;
		}

		// Either spelling of the CI number counts: the sys_id the export
		// carries in `Datacom CMDB ID`, or the `Key` people quote (BIA-23826).
		if ( '' !== trim( (string) ( $data['cmdb_id'] ?? '' ) ) || '' !== trim( (string) ( $data['cmdb_key'] ?? '' ) ) ) {
			++$evidence;
		}

		if ( $evidence < 2 ) {
			return true;
		}

		$status = (string) ( $data['lifecycle_status'] ?? '' );
		$status = array_key_exists( $status, vh_lifecycle_statuses() ) ? $status : vh_normalise_lifecycle( $status );

		return 'in_service' !== $status;
	}

	/**
	 * Names currently being held out of the inventory.
	 *
	 * @return array<string,bool>
	 */
	private static function held_names(): array {
		if ( null !== self::$held_names ) {
			return self::$held_names;
		}

		global $wpdb;

		$table = vh_table( 'stale_records' );
		$rows  = (array) $wpdb->get_col( "SELECT name FROM {$table} WHERE released_at IS NULL" ); // phpcs:ignore WordPress.DB.PreparedSQL

		self::$held_names = array_flip( array_map( 'strval', $rows ) );

		return self::$held_names;
	}

	/**
	 * Keep a bare record without letting it into the inventory.
	 *
	 * Nothing is thrown away: the team, site, service and status the CMDB
	 * gave it are kept, so that if a scanner or sensor later proves the
	 * machine exists, everything the CMDB knew arrives with it.
	 *
	 * @param array<string,mixed> $data Asset fields.
	 * @return int Stale-record id, or 0.
	 */
	public static function hold_stale_record( array $data ): int {
		global $wpdb;

		$name = strtolower( trim( (string) ( $data['hostname'] ?? '' ) ) );

		if ( '' === $name ) {
			return 0;
		}

		$table  = vh_table( 'stale_records' );
		$source = vh_normalise_source( (string) ( $data['source'] ?? $data['primary_source'] ?? '' ) ) ?: 'cmdb';

		$keep = array_intersect_key(
			$data,
			array_flip(
				array(
					'hostname', 'asset_type', 'operating_system', 'os_version', 'criticality',
					'environment', 'business_service', 'compliance_state', 'lifecycle_status',
					'team_id', 'location_id', 'owner_person_id', 'patch_group', 'support_end_date',
					'manufacturer', 'model', 'tags', 'raw', 'source', 'primary_source',
				)
			)
		);

		$now      = vh_now();
		$existing = $wpdb->get_row(
			$wpdb->prepare( "SELECT id, times_seen FROM {$table} WHERE source = %s AND name = %s LIMIT 1", $source, $name ), // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		if ( $existing ) {
			/*
			 * Merged, not replaced. One export of the same record can be
			 * thinner than the last -- a run that carried only a name and a
			 * support team would otherwise throw away the site and service an
			 * earlier one gave us, and those are the whole reason for keeping
			 * the record at all.
			 */
			$was = json_decode( (string) $wpdb->get_var( $wpdb->prepare( "SELECT payload_json FROM {$table} WHERE id = %d", (int) $existing['id'] ) ), true ); // phpcs:ignore WordPress.DB.PreparedSQL

			if ( is_array( $was ) ) {
				foreach ( $was as $column => $value ) {
					$fresh = $keep[ $column ] ?? '';

					if ( ( is_array( $fresh ) ? ! $fresh : '' === trim( (string) $fresh ) ) && ( is_array( $value ) ? (bool) $value : '' !== trim( (string) $value ) ) ) {
						$keep[ $column ] = $value;
					}
				}
			}

			$wpdb->update(
				$table,
				array(
					'payload_json' => (string) wp_json_encode( $keep ),
					'times_seen'   => (int) $existing['times_seen'] + 1,
					'last_held_at' => $now,
					'released_at'  => null,
				),
				array( 'id' => (int) $existing['id'] )
			);

			self::$held_names = null;

			return (int) $existing['id'];
		}

		$wpdb->insert(
			$table,
			array(
				'source'        => $source,
				'name'          => $name,
				'payload_json'  => (string) wp_json_encode( $keep ),
				'times_seen'    => 1,
				'first_held_at' => $now,
				'last_held_at'  => $now,
			)
		);

		self::$held_names = null;

		( new Logger() )->audit(
			'asset.stale_record_held',
			sprintf(
				/* translators: %s: the name on the record. */
				__( '"%s" arrived from the CMDB with no CI number, address or DNS name, so it was held rather than added to the inventory.', 'vulnhub' ),
				$name
			),
			'stale_record',
			(int) $wpdb->insert_id,
			$keep,
			'warning'
		);

		return (int) $wpdb->insert_id;
	}

	/**
	 * Give a held record back, now that something real has been seen.
	 *
	 * Called after every asset write. Whatever the CMDB knew -- team, site,
	 * service, environment, criticality -- is applied to the fields the new
	 * asset has left empty, and nothing it already holds is overwritten.
	 *
	 * @param string $hostname Asset hostname.
	 * @param int    $asset_id The asset that now exists.
	 */
	public static function release_stale_record( string $hostname, int $asset_id ): void {
		global $wpdb;

		$name = strtolower( trim( $hostname ) );

		if ( '' === $name || ! $asset_id || ! isset( self::held_names()[ $name ] ) ) {
			return;
		}

		$table = vh_table( 'stale_records' );
		$row   = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE name = %s AND released_at IS NULL LIMIT 1", $name ), // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		if ( ! $row ) {
			return;
		}

		$payload = json_decode( (string) $row['payload_json'], true );
		$payload = is_array( $payload ) ? $payload : array();
		$asset   = self::asset( $asset_id );
		$fill    = array();

		if ( $asset ) {
			foreach ( array( 'asset_type', 'operating_system', 'os_version', 'environment', 'business_service', 'compliance_state', 'patch_group', 'manufacturer', 'model' ) as $column ) {
				$value = trim( (string) ( $payload[ $column ] ?? '' ) );

				if ( '' !== $value && '' === trim( (string) ( $asset[ $column ] ?? '' ) ) ) {
					$fill[ $column ] = $value;
				}
			}

			foreach ( array( 'team_id', 'location_id' ) as $column ) {
				if ( (int) ( $payload[ $column ] ?? 0 ) && ! (int) ( $asset[ $column ] ?? 0 ) ) {
					$fill[ $column ] = (int) $payload[ $column ];
				}
			}

			if ( 'unknown' === (string) ( $asset['asset_type'] ?? '' ) && '' !== (string) ( $fill['asset_type'] ?? '' ) ) {
				$fill['asset_type'] = $fill['asset_type'];
			}

			if ( $fill ) {
				$fill['updated_at'] = vh_now();
				$wpdb->update( vh_table( 'assets' ), $fill, array( 'id' => $asset_id ) );
			}
		}

		$wpdb->update(
			$table,
			array(
				'released_at'       => vh_now(),
				'released_asset_id' => $asset_id,
			),
			array( 'id' => (int) $row['id'] )
		);

		self::$held_names = null;

		( new Logger() )->audit(
			'asset.stale_record_released',
			sprintf(
				/* translators: 1: name, 2: asset id. */
				__( '"%1$s" was seen by a scanner or sensor, so the CMDB record held for it was released on to asset %2$d.', 'vulnhub' ),
				$name,
				$asset_id
			),
			'asset',
			$asset_id,
			array( 'filled' => $fill )
		);
	}

	/**
	 * Records currently held out of the inventory.
	 *
	 * @param bool $include_released Also list ones already given back.
	 * @return array<int,array<string,mixed>>
	 */
	public static function stale_records( bool $include_released = false ): array {
		global $wpdb;

		$table = vh_table( 'stale_records' );
		$where = $include_released ? '' : ' WHERE released_at IS NULL';

		return (array) $wpdb->get_results( "SELECT * FROM {$table}{$where} ORDER BY name ASC", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL
	}

	/**
	 * Move bare CMDB assets already in the inventory into the hold.
	 *
	 * The rule applies to imports from now on; this applies it to what
	 * earlier imports left behind. Nothing a scanner or sensor has ever
	 * touched is taken, and neither is anything carrying a finding, a ticket
	 * or an exception -- something real is attached to it.
	 *
	 * @param bool $dry_run Report only.
	 * @return array<int,string> What was held, one line each.
	 */
	public static function collect_stale_assets( bool $dry_run = false ): array {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$f    = vh_table( 'findings' );
		$t    = vh_table( 'tickets' );
		$e    = vh_table( 'exceptions' );
		$rows = (array) $wpdb->get_results(
			"SELECT * FROM {$a} a
			 WHERE a.primary_source = 'cmdb'
			   AND (
				 ( ( a.ipv4 <> '' ) + ( a.fqdn <> '' ) + ( a.cmdb_id <> '' OR a.cmdb_key <> '' ) ) < 2
				 OR a.lifecycle_status <> 'in_service'
			   )
			   AND a.tenable_uuid = '' AND a.intune_id = '' AND a.defender_id = ''
			   AND a.azure_ad_device_id = '' AND a.azure_vm_id = '' AND a.aws_instance_id = ''
			   AND a.gcp_instance_id = '' AND a.tenable_last_scan IS NULL
			   AND NOT EXISTS ( SELECT 1 FROM {$f} f WHERE f.asset_id = a.id )
			   AND NOT EXISTS ( SELECT 1 FROM {$t} k WHERE k.asset_id = a.id )
			   AND NOT EXISTS ( SELECT 1 FROM {$e} x WHERE x.asset_id = a.id )
			 ORDER BY a.hostname ASC", // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		$done = array();

		foreach ( $rows as $row ) {
			$done[] = sprintf( '%s (asset %d, %s)', (string) $row['hostname'], (int) $row['id'], (string) $row['lifecycle_status'] );

			if ( $dry_run ) {
				continue;
			}

			$row['source'] = 'cmdb';
			$row['tags']   = json_decode( (string) $row['tags_json'], true ) ?: array();
			$row['raw']    = json_decode( (string) $row['raw_json'], true ) ?: array();

			self::hold_stale_record( $row );

			$wpdb->delete( vh_table( 'asset_exposure' ), array( 'asset_id' => (int) $row['id'] ) );
			$wpdb->delete( vh_table( 'class_asset_state' ), array( 'asset_id' => (int) $row['id'] ) );
			$wpdb->delete( $a, array( 'id' => (int) $row['id'] ) );
		}

		return $done;
	}


	public static function asset( int $id ): ?array {
		global $wpdb;
		if ( ! $id ) {
			return null;
		}
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'assets' ) . ' WHERE id = %d', $id ), ARRAY_A );
		return $row ?: null;
	}

	/**
	 * Query assets with filters + pagination.
	 *
	 * @param array<string,mixed> $args search, asset_type, team_id, location_id,
	 *                                  owner_person_id, unowned, criticality,
	 *                                  orderby, order, limit, offset.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	/**
	 * Asset ids whose owner matches a search term.
	 *
	 * "Owner" on screen is two things stacked: the person the asset is
	 * assigned to and the team behind them, and on unassigned kit the team is
	 * the only thing shown. Somebody reading that column and typing what they
	 * see into Search means either -- so both match, and an asset with no
	 * person still answers to its team name.
	 *
	 * Resolved to an id list rather than joined into the caller's query for
	 * the same reason the vulnerability search resolves its own: people (501
	 * rows) and teams (16) are rounding errors next to 232,441 findings, and
	 * the callers already filter on indexed id columns.
	 *
	 * Email and UPN match too. They are what a ticket or an alert quotes, so
	 * pasting one in and getting that person's estate is the obvious move --
	 * and neither is displayed by this search, only used to find the row.
	 *
	 * @param string $like Term, already wrapped in % and esc_like()d.
	 * @return int[]
	 */
	/**
	 * Express "the rows of this small table matching a search" as cheaply as
	 * possible, for use against an indexed id column on a large table.
	 *
	 * An id list is the obvious answer and the right one for a selective
	 * term. It stops being right when the term is not selective: "bc" matches
	 * 10,733 of 11,774 vulnerabilities on this estate -- every hostname here
	 * begins `bchyb` or `aws-bc-` -- and testing 232,441 findings against a
	 * 10,733-entry IN list took thirteen seconds. The rows it excludes are the
	 * short list, so the complement says the same thing in 1,041 entries and
	 * runs in well under a second.
	 *
	 * So: count first (cheap, no rows materialised), then fetch whichever side
	 * is smaller. Three answers need no list at all -- everything matches,
	 * nothing matches, or the caller should use the complement.
	 *
	 * @param string   $from   FROM fragment, aliasing the searched table `x`.
	 * @param string   $where  WHERE fragment over `x` and its joins.
	 * @param string[] $params Bound values for $where.
	 * @param int      $total  Row count of the searched table.
	 * @return array{mode:string,ids:int[]} mode: all | none | in | not_in.
	 */
	private static function search_set( string $from, string $where, array $params, int $total ): array {
		global $wpdb;

		$n = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(DISTINCT x.id) FROM {$from} WHERE {$where}", $params ) // phpcs:ignore
		);

		if ( 0 === $n ) {
			return array( 'mode' => 'none', 'ids' => array() );
		}

		if ( $n >= $total ) {
			return array( 'mode' => 'all', 'ids' => array() );
		}

		// Past halfway the complement is the shorter list, and it is exactly
		// as true: "not one of the 1,041 that miss" is "one of the 10,733
		// that hit".
		$invert = ( $n * 2 ) > $total;
		$clause = $invert ? "NOT {$where}" : $where;

		return array(
			'mode' => $invert ? 'not_in' : 'in',
			'ids'  => array_map(
				'intval',
				(array) $wpdb->get_col(
					$wpdb->prepare( "SELECT DISTINCT x.id FROM {$from} WHERE {$clause}", $params ) // phpcs:ignore
				)
			),
		);
	}

	private static function owner_asset_ids( string $like ): array {
		global $wpdb;

		$a  = vh_table( 'assets' );
		$pp = vh_table( 'people' );
		$tm = vh_table( 'teams' );

		return array_map(
			'intval',
			(array) $wpdb->get_col(
				$wpdb->prepare(
					"SELECT a.id FROM {$a} a" // phpcs:ignore
					. " LEFT JOIN {$pp} p ON p.id = a.owner_person_id" // phpcs:ignore
					. " LEFT JOIN {$tm} t ON t.id = a.team_id" // phpcs:ignore
					. ' WHERE p.display_name LIKE %s OR p.email LIKE %s OR p.upn LIKE %s'
					. ' OR t.name LIKE %s',
					$like,
					$like,
					$like,
					$like
				)
			)
		);
	}

	public static function assets( array $args = array() ): array {
		global $wpdb;

		$where  = array( '1=1' );
		$params = array();
		$t      = vh_table( 'assets' );

		if ( ! empty( $args['search'] ) ) {
			$like    = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
			$clause  = 'hostname LIKE %s OR fqdn LIKE %s OR ipv4 LIKE %s OR serial_number LIKE %s OR model LIKE %s';
			array_push( $params, $like, $like, $like, $like, $like );

			// The Owner column is searchable too -- see owner_asset_ids().
			$owned = self::owner_asset_ids( $like );

			if ( $owned ) {
				$clause .= ' OR id IN (' . implode( ',', $owned ) . ')';
			}

			$where[] = '(' . $clause . ')';
		}
		foreach ( array( 'asset_type', 'criticality', 'compliance_state', 'environment', 'primary_source', 'operating_system', 'patch_group', 'cloud_account_id' ) as $col ) {
			if ( ! empty( $args[ $col ] ) ) {
				$where[]  = "{$col} = %s";
				$params[] = (string) $args[ $col ];
			}
		}
		foreach ( array( 'team_id', 'owner_person_id' ) as $col ) {
			if ( ! empty( $args[ $col ] ) ) {
				$where[]  = "{$col} = %d";
				$params[] = (int) $args[ $col ];
			}
		}

		/*
		 * Site, with `none` meaning "no site recorded".
		 *
		 * Out of the generic loop above because 0 is a real answer here and
		 * `! empty()` cannot express it. It is also the biggest single bucket
		 * on this estate -- 303 assets with no location, holding more coverage
		 * gaps than any named office -- and until this existed there was no
		 * way to ask for them at all: the bar on the chart was unclickable and
		 * the query silently ignored `location_id=0`.
		 */
		if ( isset( $args['location_id'] ) && '' !== $args['location_id'] ) {
			if ( 'none' === $args['location_id'] ) {
				$where[] = 'location_id = 0';
			} elseif ( (int) $args['location_id'] > 0 ) {
				$where[]  = 'location_id = %d';
				$params[] = (int) $args['location_id'];
			}
		}
		if ( ! empty( $args['unowned'] ) ) {
			$where[] = 'owner_person_id = 0 AND team_id = 0';
		}
		if ( ! empty( $args['needs_user'] ) ) {
			$types   = "'" . implode( "','", array_map( 'esc_sql', vh_user_bound_asset_types() ) ) . "'";
			$where[] = "asset_type IN ({$types}) AND owner_person_id = 0";
		}
		if ( ! empty( $args['coverage'] ) ) {
			$state = (string) $args['coverage'];

			if ( 'gap' === $state ) {
				$gap     = Coverage::gap_states();
				$where[] = "coverage_state IN ('" . implode( "','", array_map( 'esc_sql', $gap ) ) . "')";
			} elseif ( isset( Coverage::states()[ $state ] ) ) {
				$where[]  = 'coverage_state = %s';
				$params[] = $state;
			}
		}
		/*
		 * Endpoint coverage, filtered exactly as scanning coverage is.
		 *
		 * A separate argument rather than a mode on `coverage`, because the
		 * two are asked together far more often than apart: "servers Tenable
		 * has scanned but Defender has never onboarded" is one list, and it
		 * needs both filters live at once.
		 */
		if ( ! empty( $args['defender'] ) ) {
			$dstate = (string) $args['defender'];

			if ( 'gap' === $dstate ) {
				$dgap    = Defender_Coverage::gap_states();
				$where[] = "defender_coverage_state IN ('" . implode( "','", array_map( 'esc_sql', $dgap ) ) . "')";
			} elseif ( isset( Defender_Coverage::states()[ $dstate ] ) ) {
				$where[]  = 'defender_coverage_state = %s';
				$params[] = $dstate;
			}
		}
		if ( ! empty( $args['has_vulns'] ) ) {
			$where[] = '(open_critical + open_high + open_medium + open_low) > 0';
		}

		/*
		 * An explicit set of assets.
		 *
		 * This is how a chart segment becomes a list. Some groupings -- the
		 * end-of-life releases especially -- are not a column anybody can
		 * put in a WHERE clause: "Windows Server 2012 R2" is a build number
		 * pulled out of a version string that comes in four different
		 * shapes. Rather than reimplement that matching in SQL and let the
		 * two drift, the caller works out the ids once and hands them over.
		 */
		if ( ! empty( $args['ids'] ) ) {
			$ids = array_values( array_unique( array_filter( array_map( 'intval', (array) $args['ids'] ) ) ) );

			$where[] = $ids ? 'id IN (' . implode( ',', $ids ) . ')' : '1=0';
		}

		/*
		 * End of life, resolved through the same matcher the chart drew
		 * itself with, so the number on the bar and the length of the list
		 * cannot disagree.
		 */
		if ( ! empty( $args['eol'] ) ) {
			$ids = Eol::asset_ids( (string) $args['eol'] );

			$where[] = $ids ? 'id IN (' . implode( ',', array_map( 'intval', $ids ) ) . ')' : '1=0';
		}

		/*
		 * Lifecycle.
		 *
		 * `in_service_only` is what the assets list applies by default, so
		 * the inventory reads as the estate that is actually running rather
		 * than everything the organisation has ever owned. Decommissioned kit
		 * is one filter away, never gone.
		 */
		if ( ! empty( $args['lifecycle_status'] ) ) {
			/*
			 * Normalised, because importers legitimately hand this vendor
			 * spellings ("In Stock", "Decommsion"). A caller that has a slug
			 * already and needs a wrong one to fail rather than be guessed at
			 * -- a URL parameter, say -- validates before it gets here:
			 * vh_normalise_lifecycle() answers `unknown` for anything it does
			 * not recognise, which is a real status with real assets in it.
			 */
			$where[]  = 'lifecycle_status = %s';
			$params[] = vh_normalise_lifecycle( (string) $args['lifecycle_status'] );
		}

		if ( ! empty( $args['in_service_only'] ) ) {
			$where[] = 'lifecycle_status IN (' . vh_in_service_sql() . ')';
		}

		/*
		 * The reporting scope -- what every dashboard widget counts. Separate
		 * from `in_service_only` on purpose; see vh_reportable_statuses().
		 */
		if ( ! empty( $args['reportable_only'] ) ) {
			$where[] = 'lifecycle_status IN (' . vh_reportable_sql() . ')';
		}

		if ( ! empty( $args['not_reportable_only'] ) ) {
			$where[] = 'lifecycle_status NOT IN (' . vh_reportable_sql() . ')';
		}

		if ( ! empty( $args['out_of_service_only'] ) ) {
			$where[] = 'lifecycle_status NOT IN (' . vh_in_service_sql() . ')';
		}

		/*
		 * Which systems know this asset.
		 *
		 * `source` alone is the ordinary question. The other two are the
		 * cleanup questions, and they are the reason the column exists: an
		 * asset only the CMDB has heard of is either genuinely off the
		 * network or a record nobody has retired, and an asset the CMDB has
		 * but Intune has never seen is the same doubt from the other end.
		 *
		 * Matched against the stored JSON with a quoted key so that slugs
		 * cannot match each other's substrings.
		 */
		if ( ! empty( $args['source'] ) ) {
			$where[]  = 'sources_json LIKE %s';
			$params[] = '%' . $wpdb->esc_like( '"' . (string) $args['source'] . '"' ) . '%';
		}

		if ( ! empty( $args['without_source'] ) ) {
			$where[]  = "( sources_json = '' OR sources_json NOT LIKE %s )";
			$params[] = '%' . $wpdb->esc_like( '"' . (string) $args['without_source'] . '"' ) . '%';
		}

		// One entry, so no separator: true of the JSON shape and of the
		// comma-separated shape the first cut of this column wrote.
		if ( ! empty( $args['sole_source'] ) ) {
			// Bound rather than inlined: a literal % inside the SQL would be
			// read as a placeholder by $wpdb->prepare().
			$where[]  = "sources_json <> '' AND sources_json NOT LIKE %s";
			$params[] = '%,%';
		}

		$where_sql = implode( ' AND ', $where );

		$allowed_order = array( 'hostname', 'risk_score', 'last_seen', 'open_critical', 'open_high', 'asset_type', 'owner_person_id', 'created_at' );
		$orderby       = in_array( (string) ( $args['orderby'] ?? '' ), $allowed_order, true ) ? (string) $args['orderby'] : 'risk_score';
		$order         = 'ASC' === strtoupper( (string) ( $args['order'] ?? 'DESC' ) ) ? 'ASC' : 'DESC';
		$limit         = max( 1, min( 500, (int) ( $args['limit'] ?? 50 ) ) );
		$offset        = max( 0, (int) ( $args['offset'] ?? 0 ) );

		$count_sql = "SELECT COUNT(*) FROM {$t} WHERE {$where_sql}";
		$total     = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, ...$params ) ) : $wpdb->get_var( $count_sql ) ); // phpcs:ignore

		/*
		 * The tiebreaker matters more than it looks. Every asset starts at
		 * risk_score 0, so on a freshly imported estate the primary sort is
		 * flat and the tiebreaker decides the whole first page. Falling back
		 * to `id DESC` showed the last rows of whatever file was imported --
		 * which, for an Intune export, is a screenful of unowned cloud
		 * instances, and reads as "the owner data did not import". Hostname
		 * is stable, predictable and mixes the estate together.
		 */
		$tiebreak = 'hostname' === $orderby ? 'id ASC' : 'hostname ASC';

		$sql            = "SELECT * FROM {$t} WHERE {$where_sql} ORDER BY {$orderby} {$order}, {$tiebreak} LIMIT %d OFFSET %d";
		$query_params   = $params;
		$query_params[] = $limit;
		$query_params[] = $offset;

		$rows = (array) $wpdb->get_results( $wpdb->prepare( $sql, ...$query_params ), ARRAY_A ); // phpcs:ignore

		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}

	/**
	 * Record the outcome of re-checking a finding against the authoritative
	 * vulnerability source after its ticket was closed.
	 *
	 * @param string $state One of the \VulnHub\Core\Tickets::VERIFY_* constants.
	 */
	public static function record_finding_verification( int $finding_id, string $state, ?string $new_finding_state = null ): void {
		global $wpdb;

		if ( ! $finding_id ) {
			return;
		}

		$update = array(
			'verification_state' => $state,
			'verified_at'        => vh_now(),
			'updated_at'         => vh_now(),
		);

		if ( null !== $new_finding_state && array_key_exists( $new_finding_state, vh_finding_states() ) ) {
			$update['state'] = $new_finding_state;
		}

		$wpdb->update( vh_table( 'findings' ), $update, array( 'id' => $finding_id ) );
	}

	/**
	 * Recompute per-asset open counts and risk. Cheap enough to run nightly.
	 */
	public static function recalculate_asset_rollups(): void {
		global $wpdb;

		$a = vh_table( 'assets' );
		$f = vh_table( 'findings' );

		/**
		 * Filters the SQL expression that produces an asset's risk score.
		 *
		 * The roll-up is one set-based UPDATE over the whole estate -- 25,112
		 * assets against 425,289 findings in under a second -- so this is an
		 * expression filter rather than a per-asset value filter; returning a
		 * number here would mean 25,112 round trips. The expression is
		 * evaluated inside the UPDATE below, where `a` is the assets table and
		 * `x` is the per-asset aggregate over open, non-excepted findings
		 * (`x.rs` being the summed finding risk).
		 *
		 * Like WordPress's own `posts_where`, what you return is SQL: it is
		 * plugin code, not user input, and it is your job to keep it that way.
		 *
		 * @param string $expr     Default `COALESCE(x.rs, 0)`.
		 * @param string $assets   Assets table name.
		 * @param string $findings Findings table name.
		 */
		$expr = (string) apply_filters( 'vulnhub_asset_risk_score', 'COALESCE(x.rs, 0)', $a, $f );

		if ( '' === trim( $expr ) ) {
			$expr = 'COALESCE(x.rs, 0)';
		}

		// assets.risk_score is decimal(8,2), so the ceiling is 999999.99 --
		// the old cap of 99999999 was two orders of magnitude outside what
		// the column can hold.
		$wpdb->query(
			"UPDATE {$a} a
			 LEFT JOIN (
				SELECT asset_id,
					SUM(severity = 'critical') AS c,
					SUM(severity = 'high')     AS h,
					SUM(severity = 'medium')   AS m,
					SUM(severity = 'low')      AS l,
					COALESCE(SUM(risk_score), 0) AS rs
				FROM {$f}
				WHERE state IN ('open','reopened') AND exception_id = 0
				GROUP BY asset_id
			 ) x ON x.asset_id = a.id
			 SET a.open_critical = COALESCE(x.c, 0),
				 a.open_high     = COALESCE(x.h, 0),
				 a.open_medium   = COALESCE(x.m, 0),
				 a.open_low      = COALESCE(x.l, 0),
				 a.risk_score    = LEAST(GREATEST({$expr}, 0), 999999.99)" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);
	}

	/* =================================================================
	 * Vulnerability definitions
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $data Vuln fields.
	 */
	public static function upsert_vuln( array $data ): int {
		global $wpdb;

		$table  = vh_table( 'vulns' );
		$source = (string) ( $data['source'] ?? 'tenable' );
		$plugin = (string) ( $data['plugin_id'] ?? '' );

		if ( '' === $plugin ) {
			return 0;
		}

		$id = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT id FROM {$table} WHERE source = %s AND plugin_id = %s", $source, $plugin )
		);

		$severity = (string) ( $data['severity'] ?? 'info' );

		$row = array(
			'source'            => $source,
			'plugin_id'         => $plugin,
			'title'             => vh_trim( (string) ( $data['title'] ?? '' ), 250 ),
			'family'            => (string) ( $data['family'] ?? '' ),
			'severity'          => $severity,
			'severity_id'       => (int) ( vh_severities()[ $severity ]['id'] ?? 0 ),
			'cve_json'          => wp_json_encode( array_values( (array) ( $data['cve'] ?? array() ) ) ),
			'cvss2_base'        => (float) ( $data['cvss2_base'] ?? 0 ),
			'cvss3_base'        => (float) ( $data['cvss3_base'] ?? 0 ),
			'vpr_score'         => (float) ( $data['vpr_score'] ?? 0 ),
			'exploit_available' => (int) (bool) ( $data['exploit_available'] ?? false ),
			'description'       => (string) ( $data['description'] ?? '' ),
			'solution'          => (string) ( $data['solution'] ?? '' ),
			'see_also'          => is_array( $data['see_also'] ?? null ) ? implode( "\n", $data['see_also'] ) : (string) ( $data['see_also'] ?? '' ),
			'updated_at'        => vh_now(),
		);

		/*
		 * Stamp which product this vuln is about, from the title, so every
		 * widget groups on an indexed column instead of parsing 11k titles at
		 * read time. Same classifier the back-fill and the widgets use.
		 */
		if ( '' !== $row['title'] ) {
			$pc                     = \VH_Product::classify( $row['title'], $row['family'], (string) ( $data['description'] ?? '' ) );
			$row['component_class'] = $pc['class'];
			$row['product']         = $pc['product'];
			$row['product_kind']    = $pc['kind'];
			$row['product_slug']    = $pc['slug'];
		}

		if ( ! empty( $data['patch_publication_date'] ) ) {
			$row['patch_publication_date'] = gmdate( 'Y-m-d', (int) strtotime( (string) $data['patch_publication_date'] ) );
		}

		if ( $id ) {
			/*
			 * A column the export did not carry is not an answer of "none".
			 *
			 * Description, Solution and See Also are properties of the
			 * plugin, not of the finding, so a Tenable export repeats the
			 * same 2 KB of remediation text on every one of 228,000 rows --
			 * 268 MB of a 389 MB file, to say 13 MB of distinct things. The
			 * obvious economy is to leave those columns out of the export,
			 * and until now that quietly wiped the stored text for every
			 * plugin the estate already knew: the Remediation column went
			 * blank across the whole findings screen on the next import.
			 *
			 * So on an update, an empty incoming value leaves what is
			 * stored alone. Severity is deliberately not on this list -- it
			 * is a fact about this scan and it is allowed to change.
			 */
			foreach ( array( 'title', 'family', 'description', 'solution', 'see_also' ) as $text ) {
				if ( '' === trim( (string) $row[ $text ] ) ) {
					unset( $row[ $text ] );
				}
			}

			foreach ( array( 'cvss2_base', 'cvss3_base', 'vpr_score' ) as $score ) {
				if ( 0.0 === (float) $row[ $score ] ) {
					unset( $row[ $score ] );
				}
			}

			// A narrower export that drops the column must not clear a flag
			// that says somebody has working exploit code for this.
			if ( ! $row['exploit_available'] ) {
				unset( $row['exploit_available'] );
			}

			if ( '[]' === (string) $row['cve_json'] ) {
				unset( $row['cve_json'] );
			}

			$wpdb->update( $table, $row, array( 'id' => $id ) );
			return $id;
		}

		$row['created_at'] = vh_now();
		$wpdb->insert( $table, $row );
		return (int) $wpdb->insert_id;
	}

	/**
	 * Which systems know an asset, and when each of them last said so.
	 *
	 * Stored as a JSON object, but rows written by the first cut of this
	 * feature hold a bare comma-separated list, so both shapes are read here
	 * rather than migrated away: a source with no date attached is still a
	 * true fact, just a less useful one.
	 *
	 * Ordered by vh_asset_sources() rather than by when each feed arrived, so
	 * the same systems always read the same way down a column.
	 *
	 * @param string $stored Column value.
	 * @return array<string,string> slug => Y-m-d, or '' where the date is unknown.
	 */
	public static function source_map( string $stored ): array {
		$stored = trim( $stored );

		if ( '' === $stored ) {
			return array();
		}

		$seen = array();

		if ( '{' === $stored[0] ) {
			$decoded = json_decode( $stored, true );

			if ( is_array( $decoded ) ) {
				foreach ( $decoded as $slug => $date ) {
					$seen[ (string) $slug ] = is_string( $date ) ? substr( $date, 0, 10 ) : '';
				}
			}
		} else {
			foreach ( array_filter( array_map( 'trim', explode( ',', $stored ) ) ) as $slug ) {
				$seen[ $slug ] = '';
			}
		}

		$out = array();

		foreach ( array_keys( vh_asset_sources() ) as $slug ) {
			if ( isset( $seen[ $slug ] ) ) {
				$out[ $slug ] = $seen[ $slug ];
			}
		}

		// Anything a filter added that we have no label for still counts.
		foreach ( $seen as $slug => $date ) {
			if ( ! isset( $out[ $slug ] ) ) {
				$out[ $slug ] = $date;
			}
		}

		return $out;
	}

	/**
	 * The systems that know an asset, without the dates.
	 *
	 * @param string $stored Column value.
	 * @return array<int,string>
	 */
	public static function sources_of( string $stored ): array {
		return array_keys( self::source_map( $stored ) );
	}

	/**
	 * The age bands the platform reasons in.
	 *
	 * One definition, used by the dashboard table that shows the counts and
	 * by the finding filter that a reader lands on when they click one. Two
	 * definitions would eventually disagree, and a number that does not
	 * survive being clicked is worse than no number.
	 *
	 * `from` and `to` are days ago: a finding is in the band when it was
	 * first seen at least `from` days ago and less than `to` days ago.
	 *
	 * @return array<string,array{label:string,from:int,to:int|null}>
	 */
	public static function age_bands(): array {
		return array(
			'new' => array( 'label' => __( 'Under 30 days', 'vulnhub' ), 'from' => 0, 'to' => 30 ),
			'mid' => array( 'label' => __( '30–90 days', 'vulnhub' ), 'from' => 30, 'to' => 90 ),
			'old' => array( 'label' => __( 'Over 90 days', 'vulnhub' ), 'from' => 90, 'to' => null ),
		);
	}

	/* =================================================================
	 * Patch availability
	 *
	 * "Can this actually be fixed?" is a different question from "how bad is
	 * it?", and it is the one that decides who gets called. A critical with a
	 * vendor patch is a change request. A critical with no patch is a
	 * compensating-control conversation, and there is no point putting it on
	 * a patching team's queue at all.
	 *
	 * Tenable answers it in two places and neither alone is enough:
	 *
	 *   - `patch_publication_date` is set on 2,187 of the 11,746
	 *     vulnerabilities in this estate. When it is set there is definitely
	 *     a patch, but plenty of real fixes never get a date -- "Update the
	 *     affected packages" carries none.
	 *   - `solution` is the human sentence, and its "no patch" case is a
	 *     single fixed string Tenable emits verbatim: "There is no known
	 *     solution at this time." It is on 9,520 rows here, and it never
	 *     co-occurs with a patch date (measured: zero overlap).
	 *
	 * So: a date, or a solution that is not that sentence. That comes to
	 * 2,226 patchable of 11,746, and the 39 assets carrying the unpatchable
	 * findings are a list somebody can actually work.
	 *
	 * The SQL and the PHP have to agree, because the chart is drawn from the
	 * aggregate and the list it links to is filtered row by row. They are
	 * kept next to each other here for exactly that reason.
	 * ============================================================== */

	/**
	 * Tenable's fixed "nothing you can do yet" sentence.
	 *
	 * Matched as a prefix: the string has had a trailing space and a
	 * trailing newline in different exports.
	 */
	public const NO_SOLUTION = 'There is no known solution at this time.';

	/**
	 * The patch-availability test as SQL, against the vulns table.
	 *
	 * @param string $alias Table alias, or '' for an unaliased query.
	 */
	public static function patch_sql( string $alias = 'v' ): string {
		$a = $alias ? $alias . '.' : '';

		// The date guard is not paranoia: an import that could not parse a
		// date once wrote the epoch rather than NULL, and "patched on 1
		// January 1970" would have counted every one of those as fixed.
		return "( ( {$a}patch_publication_date IS NOT NULL"
			. " AND {$a}patch_publication_date > '1970-01-02' )"
			. " OR ( {$a}solution IS NOT NULL AND {$a}solution <> ''"
			. " AND {$a}solution NOT LIKE 'There is no known solution%' ) )";
	}

	/**
	 * The same test against a row already in memory.
	 *
	 * Takes a vulnerability row or a finding row hydrated by findings(),
	 * which carries both columns under their own names.
	 *
	 * @param array<string,mixed> $row Vulnerability or finding row.
	 */
	public static function has_patch( array $row ): bool {
		$date = trim( (string) ( $row['patch_publication_date'] ?? '' ) );

		if ( '' !== $date && '0000-00-00' !== $date && $date > '1970-01-02' ) {
			return true;
		}

		$solution = trim( (string) ( $row['solution'] ?? '' ) );

		return '' !== $solution && ! str_starts_with( $solution, 'There is no known solution' );
	}

	/**
	 * Open findings broken down by severity and by whether a fix exists.
	 *
	 * Three counts per cell because they answer three different questions
	 * and the honest answer to "how many" depends on which one was asked:
	 * `vulns` is how many distinct problems, `findings` is how much work,
	 * `assets` is how many machines somebody has to get to.
	 *
	 * @return array<int,array{severity:string,patchable:bool,vulns:int,findings:int,assets:int}>
	 */
	public static function patch_matrix(): array {
		global $wpdb;

		/*
		 * Memoised for the request, because the dashboard asks twice.
		 * VulnHub_Dash_Patching::render() calls by_severity() on its first
		 * line and self::matrix() again a hundred lines later, and this is a
		 * single query examining 1.26 million rows -- two slow-log entries,
		 * ~500ms each, on every cold board. The widget's own doc comment
		 * already claimed the result was cached; now it is.
		 *
		 * Request-scoped on purpose. A longer-lived cache here would have to
		 * be invalidated on import, which is what the widget transient above
		 * it already does.
		 */
		static $memo = null;

		if ( null !== $memo ) {
			return $memo;
		}

		$f     = vh_table( 'findings' );
		$v     = vh_table( 'vulns' );
		$patch = self::patch_sql( 'v' );

		/*
		 * Scoped to the reporting estate, because that is what the number
		 * next to it means.
		 *
		 * This counted every open finding when it was written, which was the
		 * same thing back then. Once the lists gained a reporting scope and
		 * started defaulting to it, the chart began promising 2,457 and
		 * landing on 2,453 -- four findings on assets the dashboard does not
		 * report on. A four-row gap is worse than a large one: it looks like
		 * a rounding error rather than a filter, so nobody investigates.
		 */
		$a = vh_table( 'assets' );

		$rows = (array) $wpdb->get_results(
			"SELECT f.severity AS severity,
			CASE WHEN {$patch} THEN 1 ELSE 0 END AS patchable,
			COUNT(DISTINCT f.vuln_id) AS vulns,
			COUNT(*) AS findings,
			COUNT(DISTINCT f.asset_id) AS assets
			FROM {$f} f
			INNER JOIN {$v} v ON v.id = f.vuln_id
			INNER JOIN {$a} a ON a.id = f.asset_id
			WHERE f.state IN ('open','reopened') AND f.exception_id = 0
			AND a.lifecycle_status IN (" . vh_reportable_sql() . ")
			GROUP BY f.severity, patchable", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		$seen = array();

		foreach ( $rows as $r ) {
			$seen[ (string) $r['severity'] . ':' . (int) $r['patchable'] ] = array(
				'severity'  => (string) $r['severity'],
				'patchable' => (bool) $r['patchable'],
				'vulns'     => (int) $r['vulns'],
				'findings'  => (int) $r['findings'],
				'assets'    => (int) $r['assets'],
			);
		}

		/*
		 * Fill the gaps and fix the order. A severity with no unpatchable
		 * findings still needs its zero, or the chart quietly drops a bar
		 * and the reader cannot tell "none" from "not measured".
		 */
		$out = array();

		foreach ( array_keys( vh_severities() ) as $sev ) {
			if ( 'info' === $sev ) {
				continue;
			}

			foreach ( array( 1, 0 ) as $patchable ) {
				$out[] = $seen[ $sev . ':' . $patchable ] ?? array(
					'severity'  => $sev,
					'patchable' => (bool) $patchable,
					'vulns'     => 0,
					'findings'  => 0,
					'assets'    => 0,
				);
			}
		}

		$memo = $out;

		return $memo;
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function vuln( int $id ): ?array {
		global $wpdb;
		if ( ! $id ) {
			return null;
		}
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'vulns' ) . ' WHERE id = %d', $id ), ARRAY_A );
		return $row ?: null;
	}

	/* =================================================================
	 * Findings
	 * ============================================================== */

	/**
	 * Upsert a finding. The fingerprint is (asset, vuln, port, protocol).
	 *
	 * @param array<string,mixed> $data Finding fields.
	 * @return array{id:int,created:bool,reopened:bool}
	 */
	/**
	 * Fill plugin output onto an existing finding without touching anything else.
	 *
	 * The enrichment import exists so a slim Tenable export can backfill the
	 * per-host detail (file paths, installed versions) that the first load
	 * lacked, without the normal upsert's side effects: this never creates a
	 * finding, never changes severity, state, risk or scan id, and never
	 * reopens anything. It only writes `output`.
	 *
	 * Matches by the full fingerprint when a port/protocol are given; otherwise
	 * by (asset, vuln), which is unique on this estate. Returns how many rows
	 * were updated -- 0 means there was no such finding to enrich.
	 */
	public static function enrich_finding_output( int $asset_id, int $vuln_id, int $port, string $protocol, string $output ): int {
		global $wpdb;

		if ( ! $asset_id || ! $vuln_id ) {
			return 0;
		}

		$table = vh_table( 'findings' );
		$now   = vh_now();
		$out   = mb_substr( $output, 0, 8000 );
		$app   = \VH_Product::app_from_output( $out );
		$aslug = \VH_Product::slug( $app );

		/*
		 * Match on (asset, vuln) first, not the fingerprint.
		 *
		 * Two Tenable exports of the same estate routinely disagree on port and
		 * protocol -- one leaves protocol blank, the next fills in "tcp" -- and
		 * the fingerprint folds those in, so keying on it makes an enrichment
		 * file miss every finding it was meant to update. On this data an
		 * (asset, vuln) pair is a single finding, so that is the right key.
		 *
		 * Port/protocol are only a tie-breaker, used when a pair genuinely has
		 * more than one finding (distinct network services). When they are
		 * given and they single out one row, prefer it; otherwise every finding
		 * for the pair gets the output.
		 */
		$rows = $wpdb->get_col(
			$wpdb->prepare( "SELECT id FROM {$table} WHERE asset_id = %d AND vuln_id = %d", $asset_id, $vuln_id ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);

		if ( ! $rows ) {
			return 0;
		}

		if ( count( $rows ) > 1 && ( $port > 0 || '' !== $protocol ) ) {
			$narrowed = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT id FROM {$table} WHERE asset_id = %d AND vuln_id = %d AND port = %d AND protocol = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$asset_id,
					$vuln_id,
					$port,
					$protocol
				)
			);
			if ( $narrowed ) {
				$rows = $narrowed;
			}
		}

		$ids = implode( ',', array_map( 'intval', $rows ) );

		return (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET output = %s, bundle_app = %s, bundle_app_slug = %s, last_synced_at = %s, updated_at = %s WHERE id IN ({$ids})", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$out,
				$app,
				$aslug,
				$now,
				$now
			)
		);
	}

	/**
	 * The existing finding an incoming scanner record belongs to, or null.
	 *
	 * The fingerprint folds port and protocol in, but two exports of the same
	 * estate routinely disagree about both: one leaves protocol blank and
	 * reports port 0, the next fills in "tcp" and the SMB port it scanned
	 * over. Keying the write path on the fingerprint alone therefore inserts a
	 * second row for a finding that already exists, and the new row carries
	 * none of the detail the old one had -- on this estate that produced
	 * 196,849 duplicated (asset, vuln) pairs across 393,706 rows in a single
	 * sync, every one of them losing the install path the original had
	 * captured. enrich_finding_output() already resolves a record to a finding
	 * the right way; this is the same rule applied to the path that creates
	 * the rows in the first place.
	 *
	 * A genuinely distinct network service is still a distinct finding, so two
	 * different non-zero ports never collapse into one another. Only port 0 --
	 * "there is no service behind this check", which is what a local or
	 * credentialed plugin reports -- is treated as interchangeable with a real
	 * port, and then only when exactly one row is in question. Anything
	 * ambiguous falls through to an insert rather than guessing, which also
	 * means this can never pick a row whose fingerprint is already taken.
	 *
	 * @return array{id:int|string,state:string}|null
	 */
	private static function resolve_finding( int $asset_id, int $vuln_id, int $port, string $protocol, string $fingerprint ): ?array {
		global $wpdb;

		$table = vh_table( 'findings' );

		// Same asset, vuln, port and protocol as last time.
		$row = $wpdb->get_row(
			$wpdb->prepare( "SELECT id, state FROM {$table} WHERE fingerprint = %s", $fingerprint ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);
		if ( $row ) {
			return $row;
		}

		$candidates = $wpdb->get_results(
			$wpdb->prepare( "SELECT id, state, port FROM {$table} WHERE asset_id = %d AND vuln_id = %d ORDER BY id", $asset_id, $vuln_id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);
		if ( ! $candidates ) {
			return null;
		}

		// Same port, protocol drifted ('' -> 'tcp').
		foreach ( $candidates as $candidate ) {
			if ( (int) $candidate['port'] === $port ) {
				return $candidate;
			}
		}

		// Port drifted between "no service" and a real one. Either direction
		// is the same finding, but only while there is exactly one row it
		// could mean.
		if ( 0 === $port ) {
			return 1 === count( $candidates ) ? $candidates[0] : null;
		}

		$portless = array_values(
			array_filter( $candidates, static fn( array $candidate ): bool => 0 === (int) $candidate['port'] )
		);

		return 1 === count( $portless ) ? $portless[0] : null;
	}

	public static function upsert_finding( array $data ): array {
		global $wpdb;

		$table    = vh_table( 'findings' );
		$asset_id = (int) ( $data['asset_id'] ?? 0 );
		$vuln_id  = (int) ( $data['vuln_id'] ?? 0 );

		if ( ! $asset_id || ! $vuln_id ) {
			return array(
				'id'       => 0,
				'created'  => false,
				'reopened' => false,
			);
		}

		$port        = (int) ( $data['port'] ?? 0 );
		$protocol    = (string) ( $data['protocol'] ?? '' );
		$fingerprint = vh_fingerprint( (string) $asset_id, (string) $vuln_id, (string) $port, $protocol );

		$existing = self::resolve_finding( $asset_id, $vuln_id, $port, $protocol, $fingerprint );

		$severity = (string) ( $data['severity'] ?? 'info' );
		$state    = (string) ( $data['state'] ?? 'open' );

		// A finding coming back after being fixed is a reopen, not a new find.
		$reopened = false;
		if ( $existing && 'fixed' === $existing['state'] && in_array( $state, array( 'open', 'reopened' ), true ) ) {
			$state    = 'reopened';
			$reopened = true;
		}

		/*
		 * A severity the product does not report on lands suppressed, whatever
		 * the scanner called the state.
		 *
		 * The connector setting stops Tenable sending informational findings
		 * in the first place, but that is one switch in one integration, and a
		 * sync runs unattended every hour. This is the backstop: turn the
		 * setting back on, add a second scanner, replay an old export, and the
		 * rows still arrive outside every count rather than quietly rejoining
		 * the totals. prev_state keeps the way back.
		 */
		if ( vh_severity_suppressed( $severity ) ) {
			$reopened = false;
			if ( $existing && ! in_array( (string) $existing['state'], array( 'suppressed' ), true ) ) {
				$row_prev = (string) $existing['state'];
			}
			$state = 'suppressed';
		}

		$row_prev        = '';
		$incoming_output = (string) ( $data['output'] ?? '' );

		/*
		 * Derived at write time, like bundle_app above it, because the
		 * alternative is scanning a 600MB text column on every dashboard
		 * load -- a LIKE over the findings table measured 1.8 seconds here,
		 * for a number a widget wants on every render.
		 */
		$incoming_zone = \VH_Product::path_zone( $incoming_output );

		$row = array(
			'fingerprint' => $fingerprint,
			'asset_id'    => $asset_id,
			'vuln_id'     => $vuln_id,
			'source'      => (string) ( $data['source'] ?? 'tenable' ),
			'severity'    => $severity,
			'state'       => $state,
			'port'        => $port,
			'protocol'    => $protocol,
			'service'     => (string) ( $data['service'] ?? '' ),
			'output'      => $incoming_output,
			'bundle_app'  => \VH_Product::app_from_output( $incoming_output ),
			'path_zone'   => $incoming_zone['zone'],
			'zone_path'   => mb_substr( $incoming_zone['path'], 0, 512 ),
			'risk_score'  => (float) ( $data['risk_score'] ?? 0 ),
			'scan_uuid'   => (string) ( $data['scan_uuid'] ?? '' ),
			'last_synced_at' => vh_now(),
			'updated_at'  => vh_now(),
		);
		foreach ( array( 'first_found', 'last_found', 'last_fixed', 'due_at' ) as $ts ) {
			if ( ! empty( $data[ $ts ] ) ) {
				$row[ $ts ] = vh_to_mysql( $data[ $ts ] );
			}
		}

		$row['bundle_app_slug'] = \VH_Product::slug( (string) $row['bundle_app'] );

		if ( '' !== $row_prev ) {
			$row['prev_state'] = $row_prev;
		}

		if ( $existing ) {
			/*
			 * An export run with include_plugin_output off carries no output
			 * at all, and writing that empty string over a path this finding
			 * already had would throw away the one line a patch engineer
			 * needs -- silently, on every finding, on any sync where the
			 * switch happened to be off. Detail is only ever added here;
			 * enrich_finding_output() is the path that deliberately rewrites
			 * it.
			 */
			if ( '' === $incoming_output ) {
				unset(
					$row['output'],
					$row['bundle_app'],
					$row['bundle_app_slug'],
					$row['path_zone'],
					$row['zone_path']
				);
			}

			$wpdb->update( $table, $row, array( 'id' => (int) $existing['id'] ) );
			return array(
				'id'       => (int) $existing['id'],
				'created'  => false,
				'reopened' => $reopened,
			);
		}

		$row['created_at'] = vh_now();
		$wpdb->insert( $table, $row );

		return array(
			'id'       => (int) $wpdb->insert_id,
			'created'  => true,
			'reopened' => false,
		);
	}

	/**
	 * Open findings in a path zone, counted per operating-system platform.
	 *
	 * Reads the indexed path_zone column, so this is a ~1ms lookup instead of
	 * the 1.8 second LIKE over the 600MB output column it replaced.
	 *
	 * Grouping happens on the raw OS string in SQL and the platform is decided
	 * in PHP by Os::platform(). The zone filter has already cut the set to a
	 * couple of thousand rows, so there is nothing to gain from pushing the
	 * classification into SQL, and this way the meaning of "Linux" is not
	 * written down twice.
	 *
	 * Informational findings are excluded, and that exclusion is the point of
	 * the method rather than a detail of it. Tenable ships a family of
	 * forensic enumeration plugins -- "User Download Folder Files", "Adobe
	 * Recent Files", "MUICache Program Execution History" -- whose job is to
	 * list what sits in a folder. Every one of their findings therefore quotes
	 * a download path, and counting them made this widget read 1,819 when the
	 * real exposure was 158: 93% of the number was Tenable correctly
	 * reporting, at severity info, that somebody has PDFs in Downloads.
	 *
	 * path_zone stays a factual statement about the path, so the severity cut
	 * belongs here in the exposure question -- which also leaves
	 * path_zone_enumeration() free to count those listings on purpose.
	 *
	 * @return array<string,int> Platform slug => count, including zeroes, in
	 *                           Os::platforms() order so the display is stable.
	 */
	public static function path_zone_platforms( string $zone ): array {
		global $wpdb;

		$out = array();
		foreach ( array_keys( Os::platforms() ) as $platform ) {
			$out[ $platform ] = 0;
		}

		if ( '' === $zone ) {
			return $out;
		}

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT a.operating_system AS os, COUNT(*) AS n
				   FROM ' . vh_table( 'findings' ) . ' f
				   INNER JOIN ' . vh_table( 'assets' ) . ' a ON a.id = f.asset_id
				  WHERE f.path_zone = %s
				    AND f.severity <> \'info\'
				    AND f.state IN (\'open\',\'reopened\')
				    AND f.exception_id = 0
				    AND a.lifecycle_status IN (' . vh_reportable_sql() . ')
				  GROUP BY a.operating_system', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$zone
			),
			ARRAY_A
		);

		foreach ( $rows as $row ) {
			$platform = Os::platform( (string) $row['os'] );
			$out[ $platform ] = ( $out[ $platform ] ?? 0 ) + (int) $row['n'];
		}

		return $out;
	}

	/**
	 * Distinct assets and people behind a path zone, for a widget's caption.
	 *
	 * @return array{assets:int,owners:int}
	 */
	public static function path_zone_reach( string $zone ): array {
		global $wpdb;

		if ( '' === $zone ) {
			return array( 'assets' => 0, 'owners' => 0 );
		}

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT COUNT(DISTINCT f.asset_id) AS assets,
				        COUNT(DISTINCT NULLIF(a.owner_person_id, 0)) AS owners
				   FROM ' . vh_table( 'findings' ) . ' f
				   INNER JOIN ' . vh_table( 'assets' ) . ' a ON a.id = f.asset_id
				  WHERE f.path_zone = %s
				    AND f.severity <> \'info\'
				    AND f.state IN (\'open\',\'reopened\')
				    AND f.exception_id = 0
				    AND a.lifecycle_status IN (' . vh_reportable_sql() . ')', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$zone
			),
			ARRAY_A
		);

		return array(
			'assets' => (int) ( $row['assets'] ?? 0 ),
			'owners' => (int) ( $row['owners'] ?? 0 ),
		);
	}

	/**
	 * The informational file listings in a path zone, counted on purpose.
	 *
	 * The other side of the cut path_zone_platforms() makes. These are not
	 * vulnerabilities and must never be added to an exposure number, but
	 * "Tenable has catalogued 1,695 files sitting in users' download folders"
	 * is a real data-hygiene signal, and deleting it to fix the exposure count
	 * would throw away something worth knowing.
	 *
	 * @return array{findings:int,assets:int}
	 */
	public static function path_zone_enumeration( string $zone ): array {
		global $wpdb;

		if ( '' === $zone ) {
			return array( 'findings' => 0, 'assets' => 0 );
		}

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT COUNT(*) AS findings, COUNT(DISTINCT f.asset_id) AS assets
				   FROM ' . vh_table( 'findings' ) . ' f
				   INNER JOIN ' . vh_table( 'assets' ) . ' a ON a.id = f.asset_id
				  WHERE f.path_zone = %s
				    AND f.severity = \'info\'
				    AND f.state IN (\'open\',\'reopened\')
				    AND f.exception_id = 0
				    AND a.lifecycle_status IN (' . vh_reportable_sql() . ')', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$zone
			),
			ARRAY_A
		);

		return array(
			'findings' => (int) ( $row['findings'] ?? 0 ),
			'assets'   => (int) ( $row['assets'] ?? 0 ),
		);
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function finding( int $id ): ?array {
		global $wpdb;
		if ( ! $id ) {
			return null;
		}
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'findings' ) . ' WHERE id = %d', $id ), ARRAY_A );
		return $row ?: null;
	}

	/**
	 * Rich finding query joined to asset + vuln.
	 *
	 * @param array<string,mixed> $args Filters.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	public static function findings( array $args = array() ): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$a = vh_table( 'assets' );
		$v = vh_table( 'vulns' );
		$p = vh_table( 'people' );
		$tm = vh_table( 'teams' );
		$tk = vh_table( 'tickets' );
		$lo = vh_table( 'locations' );

		$where  = array( '1=1' );
		$params = array();

		// Only join what the filters and ordering actually reference. The
		// display columns need people/teams/tickets, but nothing filters on
		// them, so joining those to count 354,000 rows cost 21 seconds.
		$need_a = false;
		$need_v = false;

		if ( ! empty( $args['state'] ) ) {
			if ( 'open_any' === $args['state'] ) {
				$where[] = "f.state IN ('open','reopened')";
			} else {
				$where[]  = 'f.state = %s';
				$params[] = (string) $args['state'];
			}
		}
		if ( ! empty( $args['severity'] ) ) {
			$sevs = is_array( $args['severity'] ) ? $args['severity'] : array( $args['severity'] );
			$sevs = array_values( array_filter( array_map( 'sanitize_key', $sevs ) ) );
			if ( $sevs ) {
				$where[] = "f.severity IN ('" . implode( "','", array_map( 'esc_sql', $sevs ) ) . "')";
			}
		}

		/*
		 * The inverse of the filter above, because the question the dashboard
		 * actually asks is "everything except informational" and an inclusive
		 * list cannot say that without naming every severity at every call
		 * site -- and then silently going wrong the day a new one is added.
		 * Accepts a comma-separated string or an array.
		 */
		if ( ! empty( $args['severity_not'] ) ) {
			$not = is_array( $args['severity_not'] )
				? $args['severity_not']
				: explode( ',', (string) $args['severity_not'] );
			$not = array_values( array_filter( array_map( 'sanitize_key', $not ) ) );
			if ( $not ) {
				$where[] = "f.severity NOT IN ('" . implode( "','", array_map( 'esc_sql', $not ) ) . "')";
			}
		}
		foreach ( array( 'asset_id' => 'f.asset_id', 'vuln_id' => 'f.vuln_id', 'ticket_id' => 'f.ticket_id', 'exception_id' => 'f.exception_id' ) as $arg => $col ) {
			if ( isset( $args[ $arg ] ) && '' !== $args[ $arg ] ) {
				$where[]  = "{$col} = %d";
				$params[] = (int) $args[ $arg ];
			}
		}
		if ( ! empty( $args['team_id'] ) ) {
			$where[]  = 'a.team_id = %d';
			$params[] = (int) $args['team_id'];
			$need_a   = true;
		}
		if ( ! empty( $args['owner_person_id'] ) ) {
			$where[]  = 'a.owner_person_id = %d';
			$params[] = (int) $args['owner_person_id'];
			$need_a   = true;
		}
		if ( ! empty( $args['asset_type'] ) ) {
			$where[]  = 'a.asset_type = %s';
			$params[] = (string) $args['asset_type'];
			$need_a   = true;
		}

		/*
		 * Where the vulnerable files sit -- currently only 'downloads'. Reads
		 * the column upsert_finding() derives, so this is an indexed equality
		 * rather than a LIKE across the output blob.
		 */
		if ( ! empty( $args['path_zone'] ) ) {
			$where[]  = 'f.path_zone = %s';
			$params[] = (string) $args['path_zone'];
		}

		/*
		 * Windows / Linux / macOS. The condition comes from Os::platform_sql()
		 * so the definition of "Linux" stays in the OS class instead of being
		 * retyped here, and it has to be SQL rather than a PHP pass because a
		 * paginated list cannot filter after LIMIT.
		 */
		if ( ! empty( $args['os_platform'] ) ) {
			$platform_sql = Os::platform_sql( (string) $args['os_platform'], 'a.operating_system' );
			if ( '' !== $platform_sql ) {
				$where[] = $platform_sql;
				$need_a  = true;
			}
		}

		/*
		 * Product / component, for the "Exposure by product" widget's
		 * drill-through. Joins the vulns table, which findings queries already
		 * do for severity/title display, so this adds a WHERE, not a join.
		 */
		if ( ! empty( $args['product_slug'] ) ) {
			// Match the same grouping the Exposure-by-product widget draws: a
			// bundled library belongs to the app that ships it (f.bundle_app),
			// everything else to its own product. Without this, clicking the
			// "Microsoft Teams" row searched for a vuln whose product is Teams
			// -- there is none -- instead of the libcurl it bundles.
			$where[]  = "( CASE WHEN v.product_kind = 'library' AND f.bundle_app <> '' THEN f.bundle_app_slug ELSE v.product_slug END ) = %s";
			$params[] = (string) $args['product_slug'];
			$need_v   = true;
		}
		if ( ! empty( $args['component_class'] ) ) {
			$where[]  = 'v.component_class = %s';
			$params[] = (string) $args['component_class'];
			$need_v   = true;
		}

		/*
		 * Lifecycle scope for findings.
		 *
		 * Until this existed the vulnerability list had no lifecycle filter at
		 * all, and its correctness was a side effect of the archive sweep:
		 * findings on assets that leave the estate get archived, so they fall
		 * out of the `open_any` state filter. That works, but it is invisible
		 * and there is nothing to catch a sweep that misses one. Filtering
		 * explicitly means the list is right because it asked, not because
		 * something else happened to have run.
		 *
		 * `reportable` is the default the screen sends; `all` sends nothing.
		 */
		if ( ! empty( $args['lifecycle'] ) ) {
			$life = (string) $args['lifecycle'];

			if ( 'reportable' === $life ) {
				$where[] = 'a.lifecycle_status IN (' . vh_reportable_sql() . ')';
				$need_a  = true;
			} elseif ( 'in_service_all' === $life ) {
				$where[] = 'a.lifecycle_status IN (' . vh_in_service_sql() . ')';
				$need_a  = true;
			} elseif ( 'all' !== $life && isset( vh_lifecycle_statuses()[ $life ] ) ) {
				$where[]  = 'a.lifecycle_status = %s';
				$params[] = $life;
				$need_a   = true;
			}
		}
		if ( isset( $args['location_id'] ) && '' !== $args['location_id'] ) {
			// `none` means "no site recorded", the same vocabulary the asset
			// list uses, so a site filter carries across the two screens.
			if ( 'none' === $args['location_id'] ) {
				$where[] = 'a.location_id = 0';
				$need_a  = true;
			} elseif ( (int) $args['location_id'] > 0 ) {
				$where[]  = 'a.location_id = %d';
				$params[] = (int) $args['location_id'];
				$need_a   = true;
			}
		}
		if ( isset( $args['has_ticket'] ) && '' !== $args['has_ticket'] ) {
			$where[] = $args['has_ticket'] ? 'f.ticket_id > 0' : 'f.ticket_id = 0';
		}
		if ( ! empty( $args['excepted'] ) ) {
			$where[] = 'f.exception_id > 0';
		} elseif ( isset( $args['excepted'] ) && '0' === (string) $args['excepted'] ) {
			$where[] = 'f.exception_id = 0';
		}
		if ( ! empty( $args['overdue'] ) ) {
			$where[]  = 'f.due_at IS NOT NULL AND f.due_at < %s';
			$params[] = vh_now();
		}

		/*
		 * Patch availability, so that a segment of the patch chart lands on
		 * exactly the rows it counted. Written against the vulns table, so
		 * it pulls that join in -- which is why it is a filter and not a
		 * post-pass over the page.
		 */
		if ( isset( $args['patch_available'] ) && '' !== $args['patch_available'] ) {
			$want    = in_array( (string) $args['patch_available'], array( '1', 'yes', 'true' ), true );
			$where[] = ( $want ? '' : 'NOT ' ) . self::patch_sql( 'v' );
			$need_v  = true;
		}

		/*
		 * Age band, in the same three buckets the severity-by-age table on
		 * the dashboard draws -- and aged the same way it ages them, by the
		 * vulnerability's OLDEST open instance rather than by each finding
		 * on its own.
		 *
		 * That distinction is the whole reason this is a join and not a
		 * WHERE clause. Age a finding individually and clicking "73 over 90
		 * days" lands on 196 rows instead of the 277 the cell promised,
		 * because the vulnerabilities in that cell also have instances found
		 * last week. A number that changes when you click it is worse than
		 * no number, so the filter answers the question the cell asked:
		 * every open instance of the vulnerabilities we have had this long.
		 */
		$age_join = '';

		if ( ! empty( $args['age'] ) ) {
			$bands = self::age_bands();
			$band  = (string) $args['age'];

			if ( isset( $bands[ $band ] ) ) {
				$having = sprintf( 'MIN(first_found) < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)', (int) $bands[ $band ]['from'] );

				if ( null !== $bands[ $band ]['to'] ) {
					$having .= sprintf( ' AND MIN(first_found) >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)', (int) $bands[ $band ]['to'] );
				}

				// Measured at 66 ms against 228,728 findings: the grouped
				// subquery runs once and the optimiser joins its ~11k rows.
				$age_join = " INNER JOIN ( SELECT vuln_id, severity FROM {$f}"
					. " WHERE state IN ('open','reopened') AND exception_id = 0"
					. " GROUP BY vuln_id, severity HAVING {$having} ) age"
					. " ON age.vuln_id = f.vuln_id AND age.severity = f.severity";
			}
		}
		if ( ! empty( $args['search'] ) ) {
			$like = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';

			/*
			 * Resolve the search against the two small tables first.
			 *
			 * The obvious form -- join findings to assets and vulns and put
			 * the LIKEs in the WHERE -- makes the optimiser drive off
			 * findings and do two primary-key lookups per row to evaluate
			 * them. Against 425,289 findings that measured 22.5 seconds for a
			 * single-word search. vulns holds 11,774 rows and assets 1,142,
			 * so scanning those and turning the answer into an id list is a
			 * rounding error, and f.vuln_id / f.asset_id are both indexed.
			 *
			 * search_set() decides which way round to express each side; see
			 * its own note for why an id list is not always the cheap answer.
			 */
			$v_set = self::search_set(
				"{$v} x", // phpcs:ignore
				'( x.title LIKE %s OR x.plugin_id LIKE %s OR x.cve_json LIKE %s )',
				array( $like, $like, $like ),
				(int) $wpdb->get_var( "SELECT COUNT(*) FROM {$v}" ) // phpcs:ignore
			);

			/*
			 * The asset side carries the Owner column with it.
			 *
			 * Hostname, FQDN, IP and owner are one set, not two, because they
			 * are one column-group on screen and because the complement trick
			 * below only works on a set that is already unioned: inverting two
			 * halves separately and OR-ing them gives back nearly everything.
			 *
			 * COALESCE because these are LEFT JOINs -- unassigned kit has no
			 * person row, and `NOT ( NULL LIKE ... )` is NULL, which would
			 * quietly drop every ownerless asset out of the complement.
			 */
			$v_set_a_from = "{$a} x" // phpcs:ignore
				. " LEFT JOIN " . vh_table( 'people' ) . " p ON p.id = x.owner_person_id" // phpcs:ignore
				. " LEFT JOIN " . vh_table( 'teams' ) . " t ON t.id = x.team_id"; // phpcs:ignore

			$a_set = self::search_set(
				$v_set_a_from,
				'( x.hostname LIKE %s OR x.fqdn LIKE %s OR x.ipv4 LIKE %s'
					. " OR COALESCE( p.display_name, '' ) LIKE %s"
					. " OR COALESCE( p.email, '' ) LIKE %s"
					. " OR COALESCE( p.upn, '' ) LIKE %s"
					. " OR COALESCE( t.name, '' ) LIKE %s )",
				array_fill( 0, 7, $like ),
				(int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a}" ) // phpcs:ignore
			);

			/*
			 * If every row of either small table matches, the OR below is true
			 * for every finding and the search excludes nothing. Say so rather
			 * than testing 232,441 rows against a list of all of them.
			 */
			if ( 'all' !== $v_set['mode'] && 'all' !== $a_set['mode'] ) {
				$clauses = array();

				foreach ( array( 'vuln_id' => $v_set, 'asset_id' => $a_set ) as $vh_col => $vh_set ) {
					if ( 'in' === $vh_set['mode'] ) {
						$clauses[] = "f.{$vh_col} IN (" . implode( ',', $vh_set['ids'] ) . ')';
					} elseif ( 'not_in' === $vh_set['mode'] ) {
						$clauses[] = "f.{$vh_col} NOT IN (" . implode( ',', $vh_set['ids'] ) . ')';
					}
				}

				$where[] = $clauses ? '( ' . implode( ' OR ', $clauses ) . ' )' : '1=0';
			}
		}

		/*
		 * Extension point for filters that live in another plugin.
		 *
		 * A filter has to be able to add a WHERE clause, its bound values, and
		 * whichever joins that clause needs -- all three, or it cannot be
		 * written safely. Clauses and their parameters are appended together at
		 * the end, which is what keeps the positional placeholders lined up
		 * with the ones the blocks above pushed.
		 *
		 * Used by vulnhub-threat for `route` and `poc`, so a lane on the
		 * attack-path widget lands on exactly the findings it counted.
		 */
		$ext = (array) apply_filters(
			'vulnhub_findings_query',
			array(
				'where'      => array(),
				'params'     => array(),
				'need_asset' => false,
				'need_vuln'  => false,
			),
			$args
		);

		foreach ( (array) ( $ext['where'] ?? array() ) as $ext_clause ) {
			$where[] = (string) $ext_clause;
		}
		foreach ( (array) ( $ext['params'] ?? array() ) as $ext_param ) {
			$params[] = $ext_param;
		}

		$need_a = $need_a || ! empty( $ext['need_asset'] );
		$need_v = $need_v || ! empty( $ext['need_vuln'] );

		$where_sql = implode( ' AND ', $where );

		$allowed = array(
			'risk_score'  => 'f.risk_score',
			'severity'    => 'v.severity_id',
			'last_found'  => 'f.last_found',
			'first_found' => 'f.first_found',
			'hostname'    => 'a.hostname',
			'due_at'      => 'f.due_at',
			'title'       => 'v.title',
		);
		$orderby = $allowed[ (string) ( $args['orderby'] ?? '' ) ] ?? 'f.risk_score';
		$order   = 'ASC' === strtoupper( (string) ( $args['order'] ?? 'DESC' ) ) ? 'ASC' : 'DESC';
		$limit   = max( 1, min( 500, (int) ( $args['limit'] ?? 50 ) ) );
		$offset  = max( 0, (int) ( $args['offset'] ?? 0 ) );

		// Ordering can pull in a table the filters did not need.
		if ( str_starts_with( $orderby, 'a.' ) ) {
			$need_a = true;
		}
		if ( str_starts_with( $orderby, 'v.' ) ) {
			$need_v = true;
		}

		$narrow = "FROM {$f} f"
			. $age_join
			. ( $need_a ? " INNER JOIN {$a} a ON a.id = f.asset_id" : '' )
			. ( $need_v ? " INNER JOIN {$v} v ON v.id = f.vuln_id" : '' )
			. " WHERE {$where_sql}";

		$total = (int) ( $params
			? $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) {$narrow}", ...$params ) ) // phpcs:ignore
			: $wpdb->get_var( "SELECT COUNT(*) {$narrow}" ) ); // phpcs:ignore

		if ( 0 === $total || $offset >= $total ) {
			return array(
				'rows'  => array(),
				'total' => $total,
			);
		}

		// Page over ids first. Sorting 354,000 rows that are already joined to
		// five tables took 14 seconds; sorting the narrow set and then
		// hydrating 50 primary keys takes milliseconds.
		$id_sql = "SELECT f.id {$narrow} ORDER BY {$orderby} {$order}, f.id DESC LIMIT %d OFFSET %d";
		$qp     = $params;
		$qp[]   = $limit;
		$qp[]   = $offset;

		$ids = array_map( 'intval', (array) $wpdb->get_col( $wpdb->prepare( $id_sql, ...$qp ) ) ); // phpcs:ignore

		if ( ! $ids ) {
			return array(
				'rows'  => array(),
				'total' => $total,
			);
		}

		$in = implode( ',', $ids );

		$rows = (array) $wpdb->get_results(
			"SELECT f.*,
			a.hostname, a.fqdn, a.ipv4, a.asset_type, a.operating_system, a.criticality,
			a.owner_person_id, a.team_id, a.location_id,
			v.title AS vuln_title, v.plugin_id, v.family, v.cve_json, v.cvss3_base, v.vpr_score,
			v.product, v.product_kind,
			v.solution, v.description, v.exploit_available, v.patch_publication_date,
			p.display_name AS owner_name, p.upn AS owner_upn, p.department AS owner_department,
			t.name AS team_name,
			l.name AS location_name,
			k.external_key AS ticket_key, k.url AS ticket_url, k.status AS ticket_status,
			k.status_category AS ticket_status_category
			FROM {$f} f
			INNER JOIN {$a} a ON a.id = f.asset_id
			INNER JOIN {$v} v ON v.id = f.vuln_id
			LEFT JOIN {$p} p  ON p.id = a.owner_person_id
			LEFT JOIN {$tm} t ON t.id = a.team_id
			LEFT JOIN {$lo} l ON l.id = a.location_id
			LEFT JOIN {$tk} k ON k.id = f.ticket_id
			WHERE f.id IN ({$in})
			ORDER BY {$orderby} {$order}, f.id DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}

	/**
	 * Headline counts for dashboards.
	 *
	 * @return array<string,int|float>
	 */
	public static function summary(): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$a = vh_table( 'assets' );

		/*
		 * Every figure here is a reported number, so every one of them carries
		 * the reporting scope -- the findings as well as the assets.
		 *
		 * The findings matter as much as the counts. Four critical and two
		 * high findings sit on quarantined machines on this estate, so an
		 * unscoped tile read four criticals above the list it linked to, and
		 * the only way to discover that was to count the rows by hand.
		 *
		 * Expressed as a subquery on `asset_id` rather than a join: there are
		 * 425,289 findings and joining the asset table to group them measured
		 * in whole seconds, while the id set is small and indexed.
		 */
		$scoped = "asset_id IN ( SELECT id FROM {$a} WHERE lifecycle_status IN (" . vh_reportable_sql() . ') )';

		$open = (array) $wpdb->get_results(
			"SELECT severity, COUNT(*) AS n FROM {$f}
			 WHERE state IN ('open','reopened') AND exception_id = 0 AND {$scoped}
			 GROUP BY severity", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		$out = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
			'info'     => 0,
		);
		foreach ( $open as $row ) {
			$out[ (string) $row['severity'] ] = (int) $row['n'];
		}

		$out['open_total']       = array_sum( array( $out['critical'], $out['high'], $out['medium'], $out['low'], $out['info'] ) );
		$rep                     = vh_reportable_sql();
		$out['assets_total']     = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE lifecycle_status IN ({$rep})" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$out['assets_at_risk']   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE lifecycle_status IN ({$rep}) AND (open_critical + open_high) > 0" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$out['assets_unowned']   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE lifecycle_status IN ({$rep}) AND owner_person_id = 0 AND team_id = 0" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$out['assets_owned']     = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE lifecycle_status IN ({$rep}) AND owner_person_id > 0" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$types                   = "'" . implode( "','", array_map( 'esc_sql', vh_user_bound_asset_types() ) ) . "'";
		/*
		 * The gap counters use the reporting scope, because they are reported
		 * numbers and they link to lists drawn at that scope.
		 *
		 * `not_in_service` below keeps the ownership scope, and deliberately.
		 * It is published as a metric called "Assets not in service", and a
		 * quarantined machine is in service by this platform's own vocabulary
		 * -- it is simply not somewhere a scanner or a patch can reach it.
		 * Moving it to the reporting scope would have kept the label and
		 * quietly changed the number from 44 to 142.
		 */
		$live                    = $rep;
		// Spares, stock and retired kit are *meant* to have no user; counting
		// them here would bury the real gaps.
		$out['users_missing']    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE asset_type IN ({$types}) AND owner_person_id = 0 AND lifecycle_status IN ({$live})" ); // phpcs:ignore
		$out['not_in_service']   = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $a . ' WHERE lifecycle_status NOT IN (' . vh_in_service_sql() . ')' ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		/*
		 * No site. Same shape as the missing-user rule and for the same
		 * reason: an asset nobody can place is an asset nobody can send an
		 * engineer to, and it is where coverage gaps go to hide -- the
		 * unplaced pile holds more of them than any named office. Retired
		 * and in-stock kit is excluded, as it is for owners.
		 */
		$out['sites_missing']    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE location_id = 0 AND lifecycle_status IN ({$live})" ); // phpcs:ignore
		$out['fixed_30d']        = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$f} WHERE state = 'fixed' AND last_fixed >= %s", gmdate( 'Y-m-d H:i:s', time() - 30 * DAY_IN_SECONDS ) ) );
		$out['overdue']          = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$f} WHERE state IN ('open','reopened') AND exception_id = 0 AND due_at IS NOT NULL AND due_at < %s", vh_now() ) );
		$out['excepted']         = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$f} WHERE exception_id > 0" );
		$out['tickets_open']     = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . " WHERE status_category <> 'done'" );
		$out['tickets_done']     = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . " WHERE status_category = 'done'" );
		$out['awaiting_verify']  = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . " WHERE verification_state = 'pending'" );
		$out['verify_failed']    = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . " WHERE verification_state = 'still_open'" );
		$out['exceptions_open']  = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'exceptions' ) . " WHERE status = 'pending'" );
		$out['exceptions_active'] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'exceptions' ) . " WHERE status = 'approved'" );

		return $out;
	}

	/**
	 * Trend series from the metrics table.
	 *
	 * @param string[] $keys Metric keys.
	 * @return array<string,array<string,float>>
	 */
	public static function trend( array $keys, int $days = 30 ): array {
		global $wpdb;

		$since = gmdate( 'Y-m-d', time() - $days * DAY_IN_SECONDS );
		$in    = "'" . implode( "','", array_map( 'esc_sql', $keys ) ) . "'";

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT snapshot_date, metric_key, value FROM ' . vh_table( 'metrics' ) . " WHERE metric_key IN ({$in}) AND snapshot_date >= %s ORDER BY snapshot_date ASC", // phpcs:ignore
				$since
			),
			ARRAY_A
		);

		$out = array();
		foreach ( $rows as $row ) {
			$out[ (string) $row['metric_key'] ][ (string) $row['snapshot_date'] ] = (float) $row['value'];
		}
		return $out;
	}

	/**
	 * Aggregate open findings by an asset dimension.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function breakdown( string $dimension = 'team', int $limit = 10 ): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$a = vh_table( 'assets' );

		switch ( $dimension ) {
			case 'team':
				$join  = 'LEFT JOIN ' . vh_table( 'teams' ) . ' d ON d.id = a.team_id';
				$label = 'COALESCE(d.name, "Unassigned")';
				$group = 'a.team_id';
				break;
			case 'location':
				$join  = 'LEFT JOIN ' . vh_table( 'locations' ) . ' d ON d.id = a.location_id';
				$label = 'COALESCE(d.name, "Unknown")';
				$group = 'a.location_id';
				break;
			case 'owner':
				$join  = 'LEFT JOIN ' . vh_table( 'people' ) . ' d ON d.id = a.owner_person_id';
				$label = 'COALESCE(d.display_name, "Unassigned")';
				$group = 'a.owner_person_id';
				break;
			case 'asset_type':
			default:
				$join  = '';
				$label = 'a.asset_type';
				$group = 'a.asset_type';
				break;
		}

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT {$label} AS label,
					COUNT(*) AS total,
					SUM(f.severity = 'critical') AS critical,
					SUM(f.severity = 'high') AS high,
					SUM(f.severity = 'medium') AS medium,
					SUM(f.severity = 'low') AS low
				 FROM {$f} f
				 INNER JOIN {$a} a ON a.id = f.asset_id
				 {$join}
				 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
				 GROUP BY {$group}
				 ORDER BY critical DESC, high DESC, total DESC
				 LIMIT %d", // phpcs:ignore
				$limit
			),
			ARRAY_A
		);
	}

	/**
	 * Top vulnerabilities by affected asset count.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function top_vulns( int $limit = 10 ): array {
		global $wpdb;

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT v.id, v.title, v.plugin_id, v.severity, v.cvss3_base, v.vpr_score, v.solution,
						COUNT(DISTINCT f.asset_id) AS asset_count, COUNT(*) AS finding_count
				 FROM ' . vh_table( 'findings' ) . ' f
				 INNER JOIN ' . vh_table( 'vulns' ) . " v ON v.id = f.vuln_id
				 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
				   AND v.severity IN ('critical','high','medium')
				 GROUP BY v.id
				 ORDER BY v.severity_id DESC, asset_count DESC
				 LIMIT %d",
				$limit
			),
			ARRAY_A
		);
	}
}

