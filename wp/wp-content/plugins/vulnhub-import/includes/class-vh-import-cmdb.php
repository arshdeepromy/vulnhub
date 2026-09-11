<?php
/**
 * The CMDB importer: a thin adapter on to the CMDB plugin's own vocabulary.
 *
 * None of the column mapping or the merge logic is reimplemented here. The
 * canonical field list, the header aliases, the value normalisation and the
 * merge rules all live in `VulnHub_Cmdb_Schema` and
 * `VulnHub_Cmdb_Connector::import_records()`, which already know things this
 * plugin has no business knowing — that a CMDB "Owner" column holding an email
 * address is a person and not a team, that `primary_source` must not be stolen
 * from Tenable, and that a support group must never replace a workstation's
 * individual owner.
 *
 * All this class does is stream rows into that code in bounded batches, and
 * say so politely when the CMDB plugin is not active rather than fatalling on
 * a missing class.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Bridge between the streaming reader and the CMDB connector.
 */
final class VulnHub_Import_Cmdb {

	/**
	 * Is the CMDB plugin active and usable?
	 *
	 * @return bool
	 */
	public static function available(): bool {
		if ( function_exists( 'vulnhub_cmdb_load' ) ) {
			vulnhub_cmdb_load();
		}

		return class_exists( 'VulnHub_Cmdb_Schema' ) && class_exists( 'VulnHub_Cmdb_Connector' );
	}

	/**
	 * Why the CMDB importer is unavailable, for the operator.
	 *
	 * @return string
	 */
	public static function unavailable_message(): string {
		return __( 'The VulnHub CMDB plugin is not active, so CMDB imports are unavailable. Activate it to map an asset inventory, or import a Tenable export instead.', 'vulnhub' );
	}

	/**
	 * The connector instance to merge through.
	 *
	 * @return \VulnHub\Core\Connector|null
	 */
	public static function connector(): ?object {
		if ( ! self::available() || ! function_exists( 'vulnhub' ) ) {
			return null;
		}

		$connector = vulnhub()->connectors->get( 'cmdb' );

		if ( $connector instanceof \VulnHub\Core\Connector ) {
			return $connector;
		}

		return new VulnHub_Cmdb_Connector();
	}

	/**
	 * Canonical CMDB fields, or a minimal stand-in when the plugin is absent
	 * so the mapping table can still be rendered and explained.
	 *
	 * @return array<string,string>
	 */
	public static function fields(): array {
		if ( self::available() ) {
			return VulnHub_Cmdb_Schema::fields();
		}

		return array(
			'cmdb_id'       => __( 'CI identifier', 'vulnhub' ),
			'hostname'      => __( 'Hostname', 'vulnhub' ),
			'serial_number' => __( 'Serial number', 'vulnhub' ),
		);
	}

	/**
	 * Header aliases used to auto-detect a mapping.
	 *
	 * @return array<string,array<int,string>>
	 */
	public static function aliases(): array {
		if ( self::available() ) {
			return VulnHub_Cmdb_Schema::aliases();
		}

		return array(
			'cmdb_id'       => array( 'cmdbid', 'ciid', 'key', 'sysid' ),
			'hostname'      => array( 'hostname', 'ciname', 'devicename', 'name' ),
			'serial_number' => array( 'serialnumber', 'serial', 'servicetag' ),
		);
	}

	/**
	 * Turn one raw row into a canonical CMDB record.
	 *
	 * @param array<string,string> $row Raw row keyed by header.
	 * @param array<string,string> $map canonical field => header.
	 * @return array<string,string>
	 */
	public static function map_row( array $row, array $map ): array {
		if ( ! self::available() ) {
			return array();
		}

		return VulnHub_Cmdb_Schema::apply_mapping( $row, $map );
	}

	/**
	 * Is this record worth sending to the connector?
	 *
	 * @param array<string,string> $record Canonical record.
	 * @return string Empty when usable, otherwise the reason.
	 */
	public static function validate( array $record ): string {
		if ( ! self::available() ) {
			return self::unavailable_message();
		}

		return VulnHub_Cmdb_Schema::validate( $record );
	}

	/**
	 * Merge a batch of canonical records into the asset inventory.
	 *
	 * Idempotence comes for free: the connector matches on cmdb_id, then serial
	 * number, then hostname before writing, and `Repo::upsert_asset()` applies
	 * the same chain again, so re-importing the same file updates rows instead
	 * of creating them.
	 *
	 * @param array<int,array<string,string>> $records  Canonical records.
	 * @param array<int,int>                  $lines    Parallel array of file row numbers.
	 * @param array<string,mixed>             $counters Job counters, by reference.
	 * @return void
	 */
	public static function import( array $records, array $lines, array &$counters ): void {
		$connector = self::connector();

		if ( ! $connector || ! method_exists( $connector, 'import_records' ) ) {
			foreach ( $lines as $line ) {
				VulnHub_Import_Jobs::note_failure( $counters, (int) $line, self::unavailable_message() );
			}
			return;
		}

		$outcomes = (array) $connector->import_records( array_values( $records ) );

		foreach ( $outcomes as $index => $outcome ) {
			$action = (string) ( $outcome['action'] ?? '' );
			$line   = (int) ( $lines[ $index ] ?? 0 );

			switch ( $action ) {
				case 'create':
					++$counters['assets_created'];
					break;
				case 'update':
					++$counters['assets_updated'];
					break;
				case 'unchanged':
					++$counters['assets_updated'];
					break;
				case 'skipped':
					++$counters['rows_skipped'];

					// Worth its own number: "166 skipped" invites the question
					// this answers, which is that they are spares and stock.
					if ( 'unissued' === (string) ( $outcome['reason'] ?? '' ) ) {
						$counters['assets_unissued'] = (int) ( $counters['assets_unissued'] ?? 0 ) + 1;
					}
					break;
				default:
					VulnHub_Import_Jobs::note_failure(
						$counters,
						$line,
						(string) ( $outcome['detail'] ?? __( 'The row could not be written.', 'vulnhub' ) )
					);
					break;
			}
		}
	}
}

