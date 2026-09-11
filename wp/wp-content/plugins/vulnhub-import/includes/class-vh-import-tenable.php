<?php
/**
 * The Tenable importer: vulnerability rows and asset-only rows.
 *
 * A vulnerability export is one row per *finding*, so the same asset and the
 * same plugin definition arrive hundreds of times in a single file. Writing
 * both on every row would triple the query count of a 400,000-row import for
 * no benefit, so both are resolved once and cached for the life of the run —
 * while the actual finding still goes through `Repo::upsert_finding()` every
 * time, because that is what makes a re-import idempotent.
 *
 * The asset-only export is handled separately. In one real 912-row file it
 * carried nothing but `id`, `ipv4_addresses`, scan times, `sources` and `tags`
 * — no hostname, no serial, no MAC — so it shares no join key at all with a
 * CMDB export. Assets like that are matched on the Tenable UUID and are
 * expected to stay unmatched to anything else, and they are typed from the
 * customer's tag taxonomy rather than from an OS string that is not there.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Row-level import of Tenable exports.
 */
final class VulnHub_Import_Tenable {

	/** The source string written on every row this importer creates. */
	public const SOURCE = 'tenable';

	/** Cache ceiling, so a pathological file cannot grow these unbounded. */
	private const CACHE_LIMIT = 250000;

	/**
	 * Asset identity => asset id, for the life of one run.
	 *
	 * @var array<string,int>
	 */
	private array $assets = array();

	/**
	 * Asset id => criticality, used for the risk score.
	 *
	 * @var array<int,string>
	 */
	private array $criticality = array();

	/**
	 * Tenable plugin id => vuln id.
	 *
	 * @var array<string,int>
	 */
	private array $vulns = array();

	/**
	 * When this import run started, used as the last-seen fallback.
	 *
	 * Several Tenable exports -- the "vulnerabilities by group" one among
	 * them -- carry `first_observed` but no last-observed column at all.
	 * Leaving `last_found` null there is not neutral: scan coverage is
	 * derived from it, so an estate with a quarter of a million imported
	 * findings reports itself as never scanned. Every row in an export was
	 * live at the moment the export was taken, so the run time is the
	 * honest floor for "Tenable has seen this".
	 */
	private string $run_started = '';

	/**
	 * Import one row of a Tenable vulnerability export.
	 *
	 * @param array<string,string> $record   Mapped record.
	 * @param int                  $line     Row number in the file.
	 * @param array<string,mixed>  $counters Job counters, by reference.
	 * @return void
	 */
	public function import_vuln_row( array $record, int $line, array &$counters ): void {
		$plugin_id = self::digits( (string) ( $record['plugin_id'] ?? '' ) );

		if ( '' === $plugin_id ) {
			VulnHub_Import_Jobs::note_failure( $counters, $line, __( 'No plugin id, so the finding cannot be identified.', 'vulnhub' ) );
			return;
		}

		$asset_id = $this->resolve_asset( $record, $counters );

		if ( ! $asset_id ) {
			VulnHub_Import_Jobs::note_failure( $counters, $line, __( 'No asset UUID, IP address or hostname, so the finding cannot be attached to an asset.', 'vulnhub' ) );
			return;
		}

		$severity = self::severity( (string) ( $record['severity'] ?? '' ) );
		$vuln_id  = $this->resolve_vuln( $plugin_id, $severity, $record, $counters );

		if ( ! $vuln_id ) {
			VulnHub_Import_Jobs::note_failure( $counters, $line, __( 'The vulnerability definition could not be written.', 'vulnhub' ) );
			return;
		}

		$exploit = self::truthy( (string) ( $record['exploit_available'] ?? '' ) );
		$vpr     = self::number( (string) ( $record['vpr'] ?? '' ) );

		$result = Repo::upsert_finding(
			array(
				'asset_id'    => $asset_id,
				'vuln_id'     => $vuln_id,
				'source'      => self::SOURCE,
				'severity'    => $severity,
				'state'       => self::state( (string) ( $record['vuln_state'] ?? '' ), (string) ( $record['state'] ?? '' ) ),
				'port'        => (int) self::digits( (string) ( $record['port'] ?? '' ) ),
				'protocol'    => strtolower( substr( (string) ( $record['protocol'] ?? '' ), 0, 12 ) ),
				'service'     => substr( (string) ( $record['service'] ?? '' ), 0, 64 ),
				'output'      => mb_substr( (string) ( $record['plugin_output'] ?? '' ), 0, 8000 ),
				'risk_score'  => vh_risk_score( $severity, $this->criticality[ $asset_id ] ?? 'medium', $exploit, $vpr > 0 ? $vpr : null ),
				'first_found' => self::date( (string) ( $record['first_discovered'] ?? '' ) ),
				'last_found'  => self::date( (string) ( $record['last_observed'] ?? '' ) ) ?: $this->run_started(),
				'scan_uuid'   => substr( (string) ( $record['scan_uuid'] ?? '' ), 0, 64 ),
			)
		);

		if ( ! $result['id'] ) {
			VulnHub_Import_Jobs::note_failure( $counters, $line, __( 'The finding row could not be written.', 'vulnhub' ) );
			return;
		}

		if ( $result['created'] ) {
			++$counters['findings_created'];
		} else {
			++$counters['findings_updated'];
		}

		if ( $result['reopened'] ) {
			++$counters['findings_reopened'];
		}
	}

	/**
	 * Import one row of a Tenable asset-only export.
	 *
	 * @param array<string,string> $record   Mapped record.
	 * @param int                  $line     Row number in the file.
	 * @param array<string,mixed>  $counters Job counters, by reference.
	 * @return void
	 */
	public function import_asset_row( array $record, int $line, array &$counters ): void {
		/*
		 * Tenable's asset export is not a list of machines. Alongside hosts
		 * it enumerates the accounts, identities and groups it has
		 * discovered -- in one real 2,950-row export, 2,272 of them. Those
		 * rows carry no address, no OS and no hostname, and importing them
		 * would fill the inventory with entries that can never be scanned,
		 * owned or patched. Where the file says what kind of object a row
		 * is, only hosts are ours.
		 */
		$object_type = strtolower( trim( (string) ( $record['object_type'] ?? '' ) ) );

		if ( '' !== $object_type && ! str_contains( $object_type, 'host' ) ) {
			++$counters['rows_skipped'];
			return;
		}

		$payload = $this->asset_payload_from_asset_row( $record );

		if ( ! $payload ) {
			VulnHub_Import_Jobs::note_failure( $counters, $line, __( 'No asset UUID, address or hostname, so the row cannot be matched to an asset.', 'vulnhub' ) );
			return;
		}

		/*
		 * This shape enriches; it never invents. The export describes an
		 * estate the inventory is expected to already hold, so a row that
		 * matches nothing is a gap worth reporting -- an asset Tenable can
		 * see and the platform cannot -- rather than a new record to write.
		 */
		$payload['match_only'] = true;

		$result = Repo::upsert_asset( $payload );

		if ( empty( $result['matched'] ) ) {
			++$counters['assets_unmatched'];
			return;
		}

		if ( ! $result['id'] ) {
			VulnHub_Import_Jobs::note_failure( $counters, $line, __( 'The asset row could not be written.', 'vulnhub' ) );
			return;
		}

		if ( $result['created'] ) {
			++$counters['assets_created'];
		} else {
			++$counters['assets_updated'];
		}

		if ( '' !== (string) ( $payload['cloud_account_id'] ?? '' ) ) {
			++$counters['cloud_enriched'];
		}
		if ( '' !== (string) ( $payload['patch_group'] ?? '' ) ) {
			++$counters['patch_groups_set'];
		}
	}

	/**
	 * Describe what one vulnerability row would do, without writing anything.
	 *
	 * @param array<string,string> $record Mapped record.
	 * @return array<string,string>
	 */
	public static function describe_vuln_row( array $record ): array {
		return array(
			'plugin'   => self::digits( (string) ( $record['plugin_id'] ?? '' ) ),
			'name'     => vh_trim( (string) ( $record['plugin_name'] ?? '' ), 60 ),
			'severity' => self::severity( (string) ( $record['severity'] ?? '' ) ),
			'asset'    => self::identity_label( $record ),
			'port'     => (string) (int) self::digits( (string) ( $record['port'] ?? '' ) ),
			'protocol' => strtolower( (string) ( $record['protocol'] ?? '' ) ),
			'state'    => self::state( (string) ( $record['vuln_state'] ?? '' ), (string) ( $record['state'] ?? '' ) ),
		);
	}

	/* =================================================================
	 * Resolution and caching
	 * ============================================================== */

	/**
	 * Find or create the asset a vulnerability row belongs to.
	 *
	 * @param array<string,string> $record   Mapped record.
	 * @param array<string,mixed>  $counters Job counters, by reference.
	 * @return int Asset id, or 0.
	 */
	/**
	 * Enrichment pass: fill plugin output onto an already-imported finding.
	 *
	 * Deliberately conservative. It resolves the vulnerability and the asset by
	 * matching only -- it never creates either -- and writes nothing but the
	 * `output` column of the one finding they share. A row whose finding is not
	 * already present is counted and skipped, so a slim export can never
	 * duplicate a finding, invent an asset, or downgrade a severity. See
	 * Repo::enrich_finding_output().
	 *
	 * @param array<string,string> $record   One mapped row.
	 * @param int                  $line     1-based line, for messages.
	 * @param array<string,mixed>  $counters Running counters (by reference).
	 */
	public function enrich_vuln_row( array $record, int $line, array &$counters ): void {
		global $wpdb;

		$plugin_id = self::digits( (string) ( $record['plugin_id'] ?? '' ) );

		if ( '' === $plugin_id ) {
			VulnHub_Import_Jobs::note_failure( $counters, $line, __( 'No plugin id, so the finding cannot be identified.', 'vulnhub' ) );
			return;
		}

		$output = mb_substr( (string) ( $record['plugin_output'] ?? '' ), 0, 8000 );

		if ( '' === trim( $output ) ) {
			$counters['rows_skipped'] = (int) ( $counters['rows_skipped'] ?? 0 ) + 1;
			return;
		}

		// Match the vulnerability definition by plugin id -- never create it.
		$vuln_id = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare( 'SELECT id FROM ' . vh_table( 'vulns' ) . ' WHERE source = %s AND plugin_id = %s', self::SOURCE, $plugin_id )
		);

		if ( ! $vuln_id ) {
			$counters['unmatched_vuln'] = (int) ( $counters['unmatched_vuln'] ?? 0 ) + 1;
			return;
		}

		// Match the asset by UUID, IP or name -- never create it.
		$asset_id = $this->match_asset_only( $record );

		if ( ! $asset_id ) {
			$counters['unmatched_asset'] = (int) ( $counters['unmatched_asset'] ?? 0 ) + 1;
			return;
		}

		$port     = (int) self::digits( (string) ( $record['port'] ?? '' ) );
		$protocol = strtolower( substr( (string) ( $record['protocol'] ?? '' ), 0, 12 ) );

		$n = Repo::enrich_finding_output( $asset_id, $vuln_id, $port, $protocol, $output );

		if ( $n > 0 ) {
			$counters['findings_enriched'] = (int) ( $counters['findings_enriched'] ?? 0 ) + $n;
		} else {
			$counters['unmatched_finding'] = (int) ( $counters['unmatched_finding'] ?? 0 ) + 1;
		}
	}

	/**
	 * Resolve an asset from a vulnerability row by matching only, never creating.
	 *
	 * Mirrors the field mapping in asset_payload_from_vuln_row(), but hands the
	 * result to Repo::match_asset() so nothing is written -- an enrichment row
	 * must not resurrect or alter an asset.
	 */
	private function match_asset_only( array $record ): int {
		$uuid    = self::token( (string) ( $record['asset_uuid'] ?? '' ) );
		$dns     = strtolower( trim( (string) ( $record['dns_name'] ?? '' ) ) );
		$netbios = strtolower( trim( (string) ( $record['netbios_name'] ?? '' ) ) );

		if ( str_contains( $netbios, '\\' ) ) {
			$netbios = (string) substr( strrchr( $netbios, '\\' ) ?: '', 1 );
		}

		$hostname = '' !== $netbios ? $netbios : ( '' !== $dns ? (string) strtok( $dns, '.' ) : '' );
		$ip       = vh_clean_ip( (string) ( $record['ip_address'] ?? '' ) );

		if ( '' === $uuid && '' === $hostname && '' === $ip ) {
			return 0;
		}

		$row = Repo::match_asset(
			array(
				'tenable_uuid' => $uuid,
				'ipv4'         => $ip,
				'hostname'     => $hostname,
				'fqdn'         => ( '' !== $dns && str_contains( $dns, '.' ) ) ? $dns : '',
			)
		);

		return $row ? (int) $row['id'] : 0;
	}

	private function resolve_asset( array $record, array &$counters ): int {
		$identity = self::identity_key( $record );

		if ( '' === $identity ) {
			return 0;
		}

		if ( isset( $this->assets[ $identity ] ) ) {
			return $this->assets[ $identity ];
		}

		$payload = $this->asset_payload_from_vuln_row( $record );

		if ( ! $payload ) {
			return 0;
		}

		$result   = Repo::upsert_asset( $payload );
		$asset_id = (int) $result['id'];

		if ( ! $asset_id ) {
			return 0;
		}

		if ( $result['created'] ) {
			++$counters['assets_created'];
			$this->criticality[ $asset_id ] = 'medium';
		} else {
			++$counters['assets_updated'];

			// The risk score is weighted by how critical the asset is, and only
			// the stored row knows that. One query per distinct asset per run.
			$row                            = Repo::asset( $asset_id );
			$this->criticality[ $asset_id ] = (string) ( $row['criticality'] ?? '' ) ?: 'medium';
		}

		if ( count( $this->assets ) >= self::CACHE_LIMIT ) {
			$this->assets      = array();
			$this->criticality = array();
		}

		$this->assets[ $identity ] = $asset_id;

		return $asset_id;
	}

	/**
	 * Find or create the vulnerability definition for a plugin id.
	 *
	 * @param string               $plugin_id Tenable plugin id.
	 * @param string               $severity  Canonical severity.
	 * @param array<string,string> $record    Mapped record.
	 * @param array<string,mixed>  $counters  Job counters, by reference.
	 * @return int Vuln id, or 0.
	 */
	private function resolve_vuln( string $plugin_id, string $severity, array $record, array &$counters ): int {
		if ( isset( $this->vulns[ $plugin_id ] ) ) {
			return $this->vulns[ $plugin_id ];
		}

		global $wpdb;

		$table    = vh_table( 'vulns' );
		$existing = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT id FROM {$table} WHERE source = %s AND plugin_id = %s", self::SOURCE, $plugin_id ) // phpcs:ignore WordPress.DB
		);

		$description = (string) ( $record['description'] ?? '' );
		$synopsis    = (string) ( $record['synopsis'] ?? '' );

		$vuln_id = Repo::upsert_vuln(
			array(
				'source'                 => self::SOURCE,
				'plugin_id'              => $plugin_id,
				'title'                  => (string) ( $record['plugin_name'] ?? '' ),
				'family'                 => substr( (string) ( $record['family'] ?? '' ), 0, 100 ),
				'severity'               => $severity,
				'cve'                    => self::cve_list( (string) ( $record['cve'] ?? '' ) ),
				'cvss2_base'             => self::number( (string) ( $record['cvss2'] ?? '' ) ),
				'cvss3_base'             => self::number( (string) ( $record['cvss3'] ?? '' ) ),
				'vpr_score'              => self::number( (string) ( $record['vpr'] ?? '' ) ),
				'exploit_available'      => self::truthy( (string) ( $record['exploit_available'] ?? '' ) ),
				'description'            => mb_substr( '' !== $description ? $description : $synopsis, 0, 8000 ),
				'solution'               => mb_substr( (string) ( $record['solution'] ?? '' ), 0, 4000 ),
				'see_also'               => self::lines( (string) ( $record['see_also'] ?? '' ) ),
				'patch_publication_date' => self::date( (string) ( $record['patch_pub_date'] ?? '' ) ),
			)
		);

		if ( ! $vuln_id ) {
			return 0;
		}

		if ( $existing ) {
			++$counters['vulns_updated'];
		} else {
			++$counters['vulns_created'];
		}

		if ( count( $this->vulns ) >= self::CACHE_LIMIT ) {
			$this->vulns = array();
		}

		$this->vulns[ $plugin_id ] = $vuln_id;

		return $vuln_id;
	}

	/* =================================================================
	 * Payload building
	 * ============================================================== */

	/**
	 * Build the `Repo::upsert_asset()` payload from a vulnerability row.
	 *
	 * @param array<string,string> $record Mapped record.
	 * @return array<string,mixed> Empty when the row identifies nothing.
	 */
	private function asset_payload_from_vuln_row( array $record ): array {
		$uuid    = self::token( (string) ( $record['asset_uuid'] ?? '' ) );
		$dns     = strtolower( trim( (string) ( $record['dns_name'] ?? '' ) ) );
		$netbios = strtolower( trim( (string) ( $record['netbios_name'] ?? '' ) ) );
		$ip      = vh_clean_ip( (string) ( $record['ip_address'] ?? '' ) );
		$os      = (string) ( $record['operating_system'] ?? '' );
		$tags    = self::parse_tags( (string) ( $record['tags'] ?? '' ) );

		// A NetBIOS name arrives as DOMAIN\HOST on some exports.
		if ( str_contains( $netbios, '\\' ) ) {
			$netbios = (string) substr( strrchr( $netbios, '\\' ) ?: '', 1 );
		}

		$hostname = $netbios;

		if ( '' === $hostname && '' !== $dns ) {
			$hostname = (string) strtok( $dns, '.' );
		}

		if ( '' === $uuid && '' === $hostname && '' === $ip ) {
			return array();
		}

		$payload = array(
			'primary_source' => self::SOURCE,
			'hostname'       => $hostname,
		);

		$type = self::asset_type( $tags, $os, $hostname );

		// `unknown` is the absence of an answer, not an answer. Writing it
		// would let a thinly tagged Tenable row overwrite a type Intune or
		// the CMDB already established.
		if ( 'unknown' !== $type ) {
			$payload['asset_type'] = $type;
		}

		if ( '' !== $uuid ) {
			$payload['tenable_uuid'] = $uuid;
		}
		if ( '' !== $dns && str_contains( $dns, '.' ) ) {
			$payload['fqdn'] = $dns;
		}
		if ( '' !== $ip ) {
			$payload['ipv4'] = $ip;
		}
		if ( '' !== $os ) {
			$payload['operating_system'] = vh_trim( $os, 190 );
		}

		$mac = vh_clean_mac( (string) ( $record['mac_address'] ?? '' ) );
		if ( '' !== $mac ) {
			$payload['mac_address'] = $mac;
		}
		if ( $tags ) {
			$payload['tags'] = $tags;
		}

		$first = self::date( (string) ( $record['host_start'] ?? '' ) ) ?: self::date( (string) ( $record['first_discovered'] ?? '' ) );
		$last  = self::date( (string) ( $record['host_end'] ?? '' ) ) ?: self::date( (string) ( $record['last_observed'] ?? '' ) );

		if ( '' !== $first ) {
			$payload['first_seen'] = $first;
		}
		if ( '' !== $last ) {
			$payload['last_seen'] = $last;
		}

		return $payload;
	}

	/**
	 * Build the `Repo::upsert_asset()` payload from an asset-only row.
	 *
	 * @param array<string,string> $record Mapped record.
	 * @return array<string,mixed> Empty when the row identifies nothing.
	 */
	private function asset_payload_from_asset_row( array $record ): array {
		$uuid  = self::token( (string) ( $record['asset_uuid'] ?? '' ) );
		$ipv4s = self::split_list( (string) ( $record['ipv4s'] ?? '' ) );
		$fqdns = self::split_list( (string) ( $record['fqdn'] ?? '' ) );
		$names = self::split_list( (string) ( $record['hostname'] ?? '' ) );
		$macs  = self::split_list( (string) ( $record['mac_address'] ?? '' ) );
		$oses  = self::split_phrases( (string) ( $record['operating_system'] ?? '' ) );
		$tags  = self::parse_tags( (string) ( $record['tags'] ?? '' ) );

		$fqdn     = strtolower( (string) ( $fqdns[0] ?? '' ) );
		$hostname = strtolower( (string) ( $names[0] ?? '' ) );

		if ( str_contains( $hostname, '\\' ) ) {
			$hostname = (string) substr( strrchr( $hostname, '\\' ) ?: '', 1 );
		}
		if ( '' === $hostname && '' !== $fqdn ) {
			$hostname = (string) strtok( $fqdn, '.' );
		}

		$ipv4s = array_values( array_filter( array_map( 'vh_clean_ip', $ipv4s ) ) );

		if ( '' === $uuid && '' === $hostname && ! $ipv4s ) {
			return array();
		}

		$os      = (string) ( $oses[0] ?? '' );
		$payload = array(
			'primary_source' => self::SOURCE,
			'hostname'       => $hostname,
		);

		$type = self::asset_type( $tags, $os, $hostname, (string) ( $record['system_type'] ?? '' ) );

		if ( 'unknown' !== $type ) {
			$payload['asset_type'] = $type;
		}

		if ( '' !== $uuid ) {
			$payload['tenable_uuid'] = $uuid;
		}
		if ( '' !== $fqdn ) {
			$payload['fqdn'] = $fqdn;
		}
		if ( $ipv4s ) {
			$payload['ipv4s'] = $ipv4s;
			$payload['ipv4']  = $ipv4s[0];
		}
		if ( '' !== $os ) {
			$payload['operating_system'] = vh_trim( $os, 190 );
		}

		$mac = vh_clean_mac( (string) ( $macs[0] ?? '' ) );
		if ( '' !== $mac ) {
			$payload['mac_address'] = $mac;
		}
		$netbios = strtolower( trim( (string) ( $record['netbios_name'] ?? '' ) ) );

		if ( '' !== $netbios ) {
			$payload['netbios_name'] = $netbios;
		}

		/*
		 * AWS resource tags are the customer's own vocabulary -- Patch
		 * Group, owner, env, costgroup, server_role -- and are far richer
		 * than Tenable's own tag taxonomy. Merged into the same store, the
		 * ownership rules engine can act on `tag:owner` and `tag:Patch
		 * Group` with no further code.
		 */
		$cloud_tags = self::parse_resource_tags( (string) ( $record['cloud_resource_tags'] ?? '' ) );
		$tags       = array_merge( $tags, $cloud_tags );

		if ( $tags ) {
			$payload['tags'] = array_slice( $tags, 0, 60 );
		}

		$payload += self::cloud_payload( $record, $cloud_tags );

		$first = self::date( (string) ( $record['first_seen'] ?? '' ) );
		$last  = self::date( (string) ( $record['last_seen'] ?? '' ) );

		if ( '' !== $first ) {
			$payload['first_seen'] = $first;
		}
		if ( '' !== $last ) {
			$payload['last_seen'] = $last;
		}

		$sources = (string) ( $record['sources'] ?? '' );
		$cloud   = self::cloud_detail( $record );

		if ( '' !== $sources || '' !== (string) ( $record['agent_uuid'] ?? '' ) || $cloud ) {
			$payload['raw'] = array(
				'tenable' => array(
					'id'         => $uuid,
					'sources'    => self::split_list( $sources ),
					'agent_uuid' => (string) ( $record['agent_uuid'] ?? '' ),
				),
			);

			if ( $cloud ) {
				$payload['raw']['cloud'] = $cloud;
			}

			// A Nessus agent is named in `sources`, not in a column of its
			// own, in every export Tenable currently produces.
			$payload['has_agent'] = '' !== self::token( (string) ( $record['agent_uuid'] ?? '' ) )
				|| false !== stripos( $sources, 'agent' );
		}

		$software = self::split_phrases( (string) ( $record['installed_software'] ?? '' ) );

		if ( $software ) {
			$payload['software'] = array_slice( $software, 0, 400 );
		}

		return $payload;
	}

	/**
	 * Columns that belong in their own fields on the asset.
	 *
	 * `aws_owner_id` is the one worth being careful about: despite the name
	 * it is the twelve-digit AWS *account* the instance runs in, not a
	 * person. Letting it anywhere near ownership would attach a number to
	 * every cloud server and call the question answered, so it lands in
	 * `cloud_account_id` and nowhere else.
	 *
	 * @param array<string,string>            $record     Mapped record.
	 * @param array<int,array<string,string>> $cloud_tags Parsed resource tags.
	 * @return array<string,string>
	 */
	private static function cloud_payload( array $record, array $cloud_tags ): array {
		$out = array();

		$account = self::token( (string) ( $record['cloud_account_id'] ?? '' ) );
		$region  = trim( (string) ( $record['cloud_region'] ?? '' ) );
		$machine = self::token( (string) ( $record['cloud_instance_id'] ?? '' ) );

		if ( '' !== $account ) {
			$out['cloud_account_id'] = substr( $account, 0, 64 );
		}
		if ( '' !== $region ) {
			$out['cloud_region'] = substr( $region, 0, 64 );
		}
		if ( '' !== $machine ) {
			$out['aws_instance_id'] = substr( $machine, 0, 128 );
		}

		/*
		 * Tenable reports the provider as `unk` for everything it finds
		 * through cloud discovery, so the shape of the data has to say what
		 * the provider column will not: an `i-` instance id and a
		 * twelve-digit account are AWS.
		 */
		$provider = strtolower( trim( (string) ( $record['cloud_provider'] ?? '' ) ) );

		if ( '' === $provider || 'unk' === $provider || 'unknown' === $provider ) {
			$provider = '';

			if ( str_starts_with( $machine, 'i-' ) || 1 === preg_match( '/^\d{12}$/', $account ) ) {
				$provider = 'aws';
			}
		}

		if ( '' !== $provider ) {
			$out['cloud_provider'] = substr( $provider, 0, 32 );
		}

		foreach ( $cloud_tags as $tag ) {
			$key   = strtolower( str_replace( array( ' ', '_', '-' ), '', (string) ( $tag['key'] ?? '' ) ) );
			$value = trim( (string) ( $tag['value'] ?? '' ) );

			if ( '' === $value ) {
				continue;
			}

			if ( 'patchgroup' === $key && empty( $out['patch_group'] ) ) {
				$out['patch_group'] = substr( $value, 0, 96 );
			}

			// `env` is the AWS convention, `environment` the long form.
			if ( in_array( $key, array( 'env', 'environment' ), true ) && empty( $out['environment'] ) ) {
				$out['environment'] = substr( strtolower( $value ), 0, 32 );
			}
		}

		return $out;
	}

	/**
	 * The cloud columns worth keeping but not worth a column of their own.
	 *
	 * @param array<string,string> $record Mapped record.
	 * @return array<string,string>
	 */
	private static function cloud_detail( array $record ): array {
		$keys = array(
			'zone'          => 'cloud_zone',
			'instance_id'   => 'cloud_instance_id',
			'instance_type' => 'cloud_instance_type',
			'instance_name' => 'cloud_instance_name',
			'state'         => 'cloud_instance_state',
			'image_id'      => 'cloud_image_id',
			'vpc_id'        => 'cloud_vpc_id',
			'subnet_id'     => 'cloud_subnet_id',
			'resource_type' => 'cloud_resource_type',
		);

		$out = array();

		foreach ( $keys as $short => $field ) {
			$value = trim( (string) ( $record[ $field ] ?? '' ) );

			if ( '' !== $value ) {
				$out[ $short ] = vh_trim( $value, 190 );
			}
		}

		return $out;
	}

	/**
	 * Parse the cloud resource-tag column.
	 *
	 * Tenable renders these not as JSON but as a Java map dumped to string:
	 * `[{value=prod, key=environment}, {value=SRE, key=Patch Group}]`. A
	 * value may itself contain a comma, so the entries are matched as whole
	 * braces rather than split on punctuation.
	 *
	 * @param string $raw Raw column value.
	 * @return array<int,array<string,string>> Tag records, tag-store shaped.
	 */
	public static function parse_resource_tags( string $raw ): array {
		$raw = trim( $raw );

		if ( '' === $raw ) {
			return array();
		}

		// Newer exports may switch to real JSON; take it when offered.
		if ( str_starts_with( $raw, '[{"' ) ) {
			return self::parse_tags( $raw );
		}

		if ( ! preg_match_all( '/\{\s*value=(.*?),\s*key=(.*?)\s*\}/s', $raw, $matches, PREG_SET_ORDER ) ) {
			return array();
		}

		$tags = array();

		foreach ( $matches as $match ) {
			$value = trim( (string) $match[1] );
			$key   = trim( (string) $match[2] );

			// `aws:cloudformation:stack-id` and friends are machine
			// bookkeeping; they classify nothing and crowd out the rest.
			if ( '' === $key || str_starts_with( strtolower( $key ), 'aws:' ) || str_starts_with( strtolower( $key ), 'elasticbeanstalk:' ) ) {
				continue;
			}

			$tags[] = array(
				'key'      => vh_trim( $key, 64 ),
				'category' => vh_trim( $key, 64 ),
				'value'    => vh_trim( $value, 190 ),
			);
		}

		return array_slice( $tags, 0, 40 );
	}

	/* =================================================================
	 * Value normalisation
	 * ============================================================== */

	/**
	 * The stable identity of the asset a vulnerability row refers to.
	 *
	 * @param array<string,string> $record Mapped record.
	 * @return string
	 */
	public static function identity_key( array $record ): string {
		$uuid = self::token( (string) ( $record['asset_uuid'] ?? '' ) );

		if ( '' !== $uuid ) {
			return 'u:' . $uuid;
		}

		$netbios = strtolower( trim( (string) ( $record['netbios_name'] ?? '' ) ) );
		$dns     = strtolower( trim( (string) ( $record['dns_name'] ?? '' ) ) );

		if ( '' !== $netbios ) {
			return 'n:' . $netbios;
		}
		if ( '' !== $dns ) {
			return 'd:' . $dns;
		}

		$ip = vh_clean_ip( (string) ( $record['ip_address'] ?? '' ) );

		return '' === $ip ? '' : 'i:' . $ip;
	}

	/**
	 * A short label for the asset a row refers to, for the preview table.
	 *
	 * @param array<string,string> $record Mapped record.
	 * @return string
	 */
	public static function identity_label( array $record ): string {
		foreach ( array( 'netbios_name', 'dns_name', 'ip_address', 'asset_uuid' ) as $field ) {
			$value = trim( (string) ( $record[ $field ] ?? '' ) );

			if ( '' !== $value ) {
				return vh_trim( $value, 40 );
			}
		}

		return '';
	}

	/**
	 * Map a Tenable severity on to core's ladder.
	 *
	 * Exports carry either the word or the numeric id, and CSVs written by a
	 * spreadsheet sometimes carry both ("3 - High").
	 *
	 * @param string $raw Raw severity cell.
	 * @return string One of vh_severities().
	 */
	public static function severity( string $raw ): string {
		$needle = strtolower( trim( $raw ) );

		if ( '' === $needle ) {
			return 'info';
		}

		if ( array_key_exists( $needle, vh_severities() ) ) {
			return $needle;
		}

		foreach ( array( 'critical', 'high', 'medium', 'low' ) as $level ) {
			if ( str_contains( $needle, $level ) ) {
				return $level;
			}
		}

		if ( str_contains( $needle, 'info' ) || str_contains( $needle, 'none' ) ) {
			return 'info';
		}

		if ( preg_match( '/^\d$/', $needle ) ) {
			return vh_severity_from_id( (int) $needle );
		}

		return 'info';
	}

	/**
	 * Map Tenable's vulnerability state on to core's finding states.
	 *
	 * @param string $vuln_state `Vulnerability State` cell.
	 * @param string $state      `State` cell.
	 * @return string open|reopened|fixed
	 */
	public static function state( string $vuln_state, string $state ): string {
		$needle = strtolower( trim( $vuln_state . ' ' . $state ) );

		if ( preg_match( '/(fixed|closed|resolved|mitigated)/', $needle ) ) {
			return 'fixed';
		}
		if ( preg_match( '/(resurfaced|reopened)/', $needle ) ) {
			return 'reopened';
		}

		return 'open';
	}

	/**
	 * Decide an asset type, tag taxonomy first.
	 *
	 * Asset type usually lives in the customer's tags rather than in the OS
	 * string — in one real export 911 of 912 assets were typable only that way.
	 * Rollup tags classify nothing and are skipped.
	 *
	 * @param array<int,array<string,string>> $tags     Parsed tags.
	 * @param string                          $os       Operating system.
	 * @param string                          $hostname Hostname.
	 * @param string                          $declared An explicit type column.
	 * @return string One of vh_asset_types().
	 */
	public static function asset_type( array $tags, string $os = '', string $hostname = '', string $declared = '' ): string {
		$needles = array();

		foreach ( $tags as $tag ) {
			$category = strtolower( (string) ( $tag['category'] ?? '' ) );
			$value    = strtolower( (string) ( $tag['value'] ?? '' ) );

			if ( str_contains( $category, 'rollup' ) || str_contains( $value, 'all_licensed' ) || str_contains( $value, 'all licensed' ) ) {
				continue;
			}

			$needles[] = $category . ' ' . $value;
		}

		if ( '' !== trim( $declared ) ) {
			array_unshift( $needles, strtolower( $declared ) );
		}

		foreach ( $needles as $needle ) {
			$type = self::type_from_string( $needle );

			if ( '' !== $type ) {
				return $type;
			}
		}

		$needle = strtolower( trim( $os ) );

		if ( '' !== $needle ) {
			if ( str_contains( $needle, 'windows server' ) || preg_match( '/windows (2000|2003|2008|2012|2016|2019|2022|2025)/', $needle ) ) {
				return 'server';
			}
			// Network firmware is tested before mobile on purpose: a Catalyst
			// switch reports "Cisco IOS", and mobile is a user-bound type, so
			// mistyping one would send the platform hunting for a human owner
			// of a core switch.
			if ( preg_match( '/\b(ios-xe|ios xe|nx-os|pan-os|fortios|junos|aos-cx|arubaos|routeros|comware|big-ip)\b/', $needle ) ) {
				return 'network';
			}
			if ( preg_match( '/\b(cisco|juniper|palo alto|fortinet|aruba|mikrotik|ubiquiti|extreme networks|f5 networks)\b/', $needle ) ) {
				return 'network';
			}
			if ( preg_match( '/\b(ipados|iphone os|android)\b/', $needle ) || preg_match( '/\bios\b/', $needle ) ) {
				return 'mobile';
			}
			if ( preg_match( '/\b(linux|ubuntu|debian|centos|red hat|rhel|suse|rocky|almalinux|freebsd|solaris|aix|esxi)\b/', $needle ) ) {
				return 'server';
			}
			if ( preg_match( '/windows (11|10|8\.1|8|7)/', $needle ) || preg_match( '/\b(macos|mac os x|os x)\b/', $needle ) ) {
				return 'workstation';
			}
		}

		$host = strtolower( trim( $hostname ) );

		if ( '' !== $host ) {
			if ( preg_match( '/(^|[-_])(sw|fw|rtr|wlc|ap)([-_0-9]|$)/', $host ) ) {
				return 'network';
			}
			if ( preg_match( '/(^|[-_])(dc|sql|app|web|api|srv|svr|fs|bkp|k8s|prt|mon|vpn)[0-9]*$/', $host ) ) {
				return 'server';
			}
		}

		return 'unknown';
	}

	/**
	 * Map one free-text type/tag string on to core's asset types.
	 *
	 * @param string $needle Lowercased text.
	 * @return string Empty when nothing matched.
	 */
	private static function type_from_string( string $needle ): string {
		if ( '' === trim( $needle ) ) {
			return '';
		}
		if ( preg_match( '/(switch|router|firewall|wireless|access.?point|load.?balanc|network device|netgear)/', $needle ) ) {
			return 'network';
		}
		if ( preg_match( '/(aws|azure|gcp|ec2|cloud|virtual machine instance)/', $needle ) ) {
			return 'cloud';
		}
		if ( preg_match( '/(server|esx|hypervisor|domain controller|database)/', $needle ) ) {
			return 'server';
		}
		if ( preg_match( '/(workstation|desktop|laptop|notebook|endpoint|client pc)/', $needle ) ) {
			return 'workstation';
		}
		if ( preg_match( '/(mobile|phone|tablet|ipad|handheld)/', $needle ) ) {
			return 'mobile';
		}
		if ( preg_match( '/(printer|ups|appliance|camera|scanner|voip|kiosk|iot)/', $needle ) ) {
			return 'appliance';
		}

		return '';
	}

	/**
	 * Parse a tags cell into `{key, category, value}` triples.
	 *
	 * Tenable tags are `{category, value}` — reading only `key` matched nothing
	 * at all in production — so both spellings are emitted, which is what
	 * core's `Mapping::tag_map()` looks for. Three encodings are handled: the
	 * JSON array the asset export uses, a `category:value` list, and a bare
	 * comma-separated list of values.
	 *
	 * @param string $raw Raw tags cell.
	 * @return array<int,array<string,string>>
	 */
	public static function parse_tags( string $raw ): array {
		$raw = trim( $raw );

		if ( '' === $raw ) {
			return array();
		}

		$tags = array();

		if ( str_starts_with( $raw, '[' ) || str_starts_with( $raw, '{' ) ) {
			$decoded = json_decode( $raw, true );

			if ( is_array( $decoded ) ) {
				foreach ( $decoded as $entry ) {
					if ( ! is_array( $entry ) ) {
						continue;
					}

					$category = (string) ( $entry['category'] ?? $entry['category_name'] ?? $entry['key'] ?? '' );
					$value    = (string) ( $entry['value'] ?? '' );

					if ( '' === $category && '' === $value ) {
						continue;
					}

					$tags[] = array(
						'key'      => $category,
						'category' => $category,
						'value'    => $value,
					);
				}

				return array_slice( $tags, 0, 40 );
			}
		}

		foreach ( preg_split( '/\s*[,;]\s*/', $raw ) ?: array() as $piece ) {
			$piece = trim( (string) $piece );

			if ( '' === $piece ) {
				continue;
			}

			if ( str_contains( $piece, ':' ) ) {
				[ $category, $value ] = array_pad( explode( ':', $piece, 2 ), 2, '' );
			} else {
				$category = '';
				$value    = $piece;
			}

			$tags[] = array(
				'key'      => trim( $category ),
				'category' => trim( $category ),
				'value'    => trim( $value ),
			);
		}

		return array_slice( $tags, 0, 40 );
	}

	/**
	 * Split a multi-value cell (Tenable uses commas, spaces or pipes).
	 *
	 * @param string $raw Raw cell.
	 * @return array<int,string>
	 */
	public static function split_list( string $raw ): array {
		$raw = trim( $raw );

		if ( '' === $raw ) {
			return array();
		}

		if ( str_starts_with( $raw, '[' ) ) {
			$decoded = json_decode( $raw, true );

			if ( is_array( $decoded ) ) {
				return array_values( array_filter( array_map( 'strval', $decoded ) ) );
			}
		}

		$parts = preg_split( '/[\s,;|]+/', $raw ) ?: array();

		return array_values( array_filter( array_map( 'trim', array_map( 'strval', $parts ) ) ) );
	}

	/**
	 * Split a list whose members contain spaces.
	 *
	 * `split_list()` breaks on whitespace, which is right for IP addresses,
	 * hostnames and MACs and catastrophically wrong for anything written in
	 * English. Run through it, "Red Hat Enterprise Linux 9.3" became four
	 * entries and the first one -- "Red" -- was stored as the operating
	 * system of forty-eight servers. Same for installed software: "Microsoft
	 * Office Professional Plus 2019" became five products.
	 *
	 * This one splits only on the separators a vendor actually uses between
	 * list members, and leaves the members intact.
	 *
	 * @param string $raw Raw cell.
	 * @return string[]
	 */
	public static function split_phrases( string $raw ): array {
		$raw = trim( $raw );

		if ( '' === $raw ) {
			return array();
		}

		if ( str_starts_with( $raw, '[' ) ) {
			$decoded = json_decode( $raw, true );

			if ( is_array( $decoded ) ) {
				return array_values(
					array_filter( array_map( 'trim', array_map( 'strval', $decoded ) ) )
				);
			}
		}

		$parts = preg_split( '/\s*[,;|\r\n]+\s*/', $raw ) ?: array();

		return array_values( array_filter( array_map( 'trim', array_map( 'strval', $parts ) ) ) );
	}

	/**
	 * Extract a CVE list from a cell.
	 *
	 * @param string $raw Raw cell.
	 * @return array<int,string>
	 */
	public static function cve_list( string $raw ): array {
		if ( '' === trim( $raw ) ) {
			return array();
		}

		preg_match_all( '/CVE-\d{4}-\d{4,7}/i', $raw, $matches );

		return array_values( array_unique( array_map( 'strtoupper', (array) $matches[0] ) ) );
	}

	/**
	 * Split a "See also" cell into one reference per line.
	 *
	 * @param string $raw Raw cell.
	 * @return array<int,string>
	 */
	public static function lines( string $raw ): array {
		$parts = preg_split( '/[\s,;]+/', trim( $raw ) ) ?: array();

		return array_slice( array_values( array_filter( array_map( 'trim', array_map( 'strval', $parts ) ) ) ), 0, 20 );
	}

	/**
	 * Digits only — Tenable plugin ids and ports arrive with stray characters
	 * from spreadsheet round-trips.
	 *
	 * @param string $raw Raw cell.
	 * @return string
	 */
	public static function digits( string $raw ): string {
		return (string) preg_replace( '/[^0-9]/', '', $raw );
	}

	/**
	 * A safe identifier token (UUIDs, agent ids).
	 *
	 * @param string $raw Raw cell.
	 * @return string
	 */
	public static function token( string $raw ): string {
		$raw = trim( $raw );

		if ( '' === $raw || 1 !== preg_match( '/^[A-Za-z0-9._:-]{4,120}$/', $raw ) ) {
			return '';
		}

		return $raw;
	}

	/**
	 * A float from a score cell.
	 *
	 * @param string $raw Raw cell.
	 * @return float
	 */
	public static function number( string $raw ): float {
		$raw = trim( $raw );

		return is_numeric( $raw ) ? (float) $raw : 0.0;
	}

	/**
	 * Is this cell a yes?
	 *
	 * @param string $raw Raw cell.
	 * @return bool
	 */
	public static function truthy( string $raw ): bool {
		return in_array( strtolower( trim( $raw ) ), array( 'true', 'yes', 'y', '1', 'available' ), true );
	}

	/**
	 * Normalise a date cell to MySQL, tolerating epochs and vendor formats.
	 *
	 * @param string $raw Raw cell.
	 * @return string Empty when unparseable.
	 */
	public static function date( string $raw ): string {
		$raw = trim( $raw );

		if ( '' === $raw ) {
			return '';
		}

		$value = vh_to_mysql( $raw );

		return is_string( $value ) ? $value : '';
	}

	/**
	 * The moment this run began, as a UTC MySQL datetime.
	 *
	 * @return string
	 */
	private function run_started(): string {
		if ( '' === $this->run_started ) {
			$this->run_started = vh_now();
		}

		return $this->run_started;
	}
}

