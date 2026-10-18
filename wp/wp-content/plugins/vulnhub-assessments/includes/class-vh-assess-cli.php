<?php
/**
 * `wp vulnhub assessments` -- load a register from a JSON file, list it.
 *
 * The import file is the operator's, kept outside the repository: it names
 * suppliers, people and tickets. Shape:
 *
 *   {
 *     "meta":      { "inherited_label": "...", "inherited_as_at": "YYYY-MM-DD",
 *                    "inherited_summary": { "approved": 12, "rejected": 2 },
 *                    "notes": [ "..." ] },
 *     "records":   [ { "kind": "supplier", "subject": "...", "source": "inherited",
 *                      "outcome": "approved", "jira_keys": "KEY-1", ... } ],
 *     "exceptions": [ { "title": "...", "status": "approved", "approver_name": "...",
 *                       "decided_at": "YYYY-MM-DD", "justification": "...", "jira_key": "KEY-3" } ],
 *     "dismissed": { "KEY-2": "Test ticket" }
 *   }
 *
 * Records are matched to existing rows by kind + subject, so running the same
 * file twice updates rather than duplicates. `--replace` empties the register
 * first.
 *
 * @package VulnHub\Assessments
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VH_Assess_CLI {

	/**
	 * Import a register file.
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : Path to the JSON file.
	 *
	 * [--replace]
	 * : Empty the register (rows only) before importing.
	 *
	 * [--dry-run]
	 * : Report what would change, write nothing.
	 *
	 * @param array<int,string>    $args  Positional.
	 * @param array<string,string> $assoc Flags.
	 */
	public function import( array $args, array $assoc ): void {
		$file = (string) ( $args[0] ?? '' );
		$raw  = is_readable( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$data = json_decode( $raw, true );

		if ( ! is_array( $data ) ) {
			WP_CLI::error( 'Could not read a JSON object from ' . $file );
		}

		VH_Assess_Repo::maybe_install();

		$dry = isset( $assoc['dry-run'] );

		if ( isset( $assoc['replace'] ) && ! $dry ) {
			VH_Assess_Repo::truncate();
		}

		$existing = array();
		foreach ( VH_Assess_Repo::rows() as $r ) {
			$existing[ $r['kind'] . '|' . mb_strtolower( (string) $r['subject'] ) ] = (int) $r['id'];
		}

		$added   = 0;
		$updated = 0;
		$failed  = 0;

		foreach ( (array) ( $data['records'] ?? array() ) as $rec ) {
			if ( ! is_array( $rec ) ) {
				continue;
			}
			$kind  = (string) ( $rec['kind'] ?? 'supplier' );
			$match = $existing[ $kind . '|' . mb_strtolower( trim( (string) ( $rec['subject'] ?? '' ) ) ) ] ?? 0;

			if ( $dry ) {
				$match ? ++$updated : ++$added;
				continue;
			}

			$id = VH_Assess_Repo::save( $rec, $match );
			if ( ! $id ) {
				++$failed;
				WP_CLI::warning( 'Not saved: ' . (string) ( $rec['subject'] ?? '(no name)' ) );
				continue;
			}
			$match ? ++$updated : ++$added;
			$existing[ $kind . '|' . mb_strtolower( trim( (string) ( $rec['subject'] ?? '' ) ) ) ] = $id;
		}

		// Security exceptions go to the core Exception register, matched on
		// their Jira key so a re-run corrects rather than duplicates.
		$exc = array( 'added' => 0, 'updated' => 0, 'failed' => 0 );
		if ( ! empty( $data['exceptions'] ) && ! class_exists( '\\VulnHub\\Core\\Exceptions' ) ) {
			WP_CLI::warning( 'The import has security exceptions but the core plugin cannot record them; skipped.' );
		} elseif ( ! empty( $data['exceptions'] ) ) {
			foreach ( (array) $data['exceptions'] as $e ) {
				if ( ! is_array( $e ) ) {
					continue;
				}
				$keys  = VH_Assess_Repo::split_keys( (string) ( $e['jira_key'] ?? '' ) );
				$match = 0;
				if ( $keys ) {
					$found = \VulnHub\Core\Exceptions::query( array( 'scope' => 'policy', 'jira_key' => $keys[0], 'limit' => 1 ) );
					$match = (int) ( $found['rows'][0]['id'] ?? 0 );
				}
				if ( $dry ) {
					$match ? ++$exc['updated'] : ++$exc['added'];
					continue;
				}
				$res = \VulnHub\Core\Exceptions::record( $e, $match );
				if ( empty( $res['ok'] ) ) {
					++$exc['failed'];
					WP_CLI::warning( 'Exception not saved: ' . (string) ( $e['title'] ?? '(no title)' ) . ' — ' . (string) $res['message'] );
					continue;
				}
				$match ? ++$exc['updated'] : ++$exc['added'];
			}
		}

		$dismissed = 0;
		foreach ( (array) ( $data['dismissed'] ?? array() ) as $key => $reason ) {
			if ( ! $dry ) {
				VH_Assess_Repo::dismiss( (string) $key, (string) $reason );
			}
			++$dismissed;
		}

		if ( isset( $data['meta'] ) && is_array( $data['meta'] ) && ! $dry ) {
			VH_Assess_Repo::set_meta( $data['meta'] );
		}

		if ( ! $dry ) {
			vulnhub()->logger->audit( 'assessment.import', sprintf( 'Imported register: %d added, %d updated, %d set aside', $added, $updated, $dismissed ), 'assessment', '', array( 'replace' => isset( $assoc['replace'] ) ) );
		}

		WP_CLI::success( sprintf( '%sAssessments: %d added, %d updated, %d failed. Security exceptions: %d added, %d updated, %d failed. %d tickets set aside.', $dry ? '(dry run) ' : '', $added, $updated, $failed, $exc['added'], $exc['updated'], $exc['failed'], $dismissed ) );
	}

	/**
	 * List the register.
	 *
	 * ## OPTIONS
	 *
	 * [--kind=<kind>]
	 * : supplier or exception.
	 *
	 * [--format=<format>]
	 * : table, csv or json.
	 * ---
	 * default: table
	 * ---
	 *
	 * @param array<int,string>    $args  Positional.
	 * @param array<string,string> $assoc Flags.
	 */
	public function list( array $args, array $assoc ): void {
		$rows = VH_Assess_Repo::rows( array( 'kind' => (string) ( $assoc['kind'] ?? '' ) ) );

		WP_CLI\Utils\format_items(
			(string) ( $assoc['format'] ?? 'table' ),
			array_map(
				static fn( array $r ): array => array(
					'id'       => $r['id'],
					'kind'     => $r['kind'],
					'subject'  => $r['subject'],
					'source'   => $r['source'],
					'outcome'  => $r['outcome'],
					'approver' => $r['approver'],
					'decided'  => $r['decided_on'],
					'jira'     => $r['jira_keys'],
				),
				$rows
			),
			array( 'id', 'kind', 'subject', 'source', 'outcome', 'approver', 'decided', 'jira' )
		);
	}

	/**
	 * Show the tickets not yet in the register, with suggested decisions.
	 *
	 * @param array<int,string>    $args  Positional.
	 * @param array<string,string> $assoc Flags.
	 */
	public function missing( array $args, array $assoc ): void {
		WP_CLI\Utils\format_items(
			'table',
			array_map(
				static fn( array $r ): array => array(
					'key'     => $r['key'],
					'summary' => mb_substr( (string) $r['summary'], 0, 70 ),
					'status'  => $r['status'],
					'hint'    => $r['hint'] ? $r['hint']['outcome'] . ' by ' . $r['hint']['by'] : '',
				),
				VH_Assess_Jira::unregistered()
			),
			array( 'key', 'summary', 'status', 'hint' )
		);
	}
}

