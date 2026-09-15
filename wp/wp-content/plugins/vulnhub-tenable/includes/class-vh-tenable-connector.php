<?php
/**
 * Tenable Vulnerability Management connector.
 *
 * Imports the asset inventory and the vulnerability findings that hang off it,
 * classifies each asset so the ownership engine can decide whether it needs an
 * individual owner, and computes SLA due dates and risk scores.
 *
 * The live path and the mock path share every normalisation method below —
 * mock mode only swaps where the Tenable-shaped payloads come from.
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The `tenable` connector.
 */
final class VulnHub_Tenable_Connector extends \VulnHub\Core\Connector {

	/**
	 * Severity ladder, ascending. Index order is what the "minimum severity"
	 * setting slices.
	 */
	private const LADDER = array( 'info', 'low', 'medium', 'high', 'critical' );

	/**
	 * Fallback remediation SLA in days, used when an asset has no team yet —
	 * which is normal on a first sync, because ownership mapping only runs
	 * after the import completes.
	 */
	private const DEFAULT_SLA_DAYS = array(
		'critical' => 7,
		'high'     => 30,
		'medium'   => 90,
		'low'      => 180,
		'info'     => 180,
	);

	/**
	 * Assets touched this run: tenable uuid => row summary.
	 *
	 * @var array<string,array{id:int,criticality:string,team_id:int,hostname:string,asset_type:string}>
	 */
	private array $asset_cache = array();

	/**
	 * Vulnerability definition ids resolved this run: plugin id => vuln id.
	 *
	 * @var array<string,int>
	 */
	private array $vuln_cache = array();

	/**
	 * Team SLA lookups: team id => severity => days.
	 *
	 * @var array<int,array<string,int>>
	 */
	private array $sla_cache = array();

	/**
	 * Per-run tallies surfaced on the Tenable admin screen.
	 *
	 * @var array<string,int>
	 */
	private array $counts = array();

	/**
	 * Export jobs executed this run.
	 *
	 * @var array<int,array<string,mixed>>
	 */
	private array $jobs = array();

	/* =================================================================
	 * Identity
	 * ============================================================== */

	/**
	 * Machine id.
	 */
	public function id(): string {
		return 'tenable';
	}

	/**
	 * Human label.
	 */
	public function label(): string {
		return __( 'Tenable Vulnerability Management', 'vulnhub' );
	}

	/**
	 * One-line description for the Integrations card.
	 */
	public function description(): string {
		return __( 'Imports assets and vulnerability findings from Tenable Vulnerability Management, and re-checks closed tickets against fresh scan data.', 'vulnhub' );
	}

	/**
	 * Dashicon slug.
	 */
	public function icon(): string {
		return 'dashicons-shield';
	}

	/**
	 * Connector category.
	 */
	public function category(): string {
		return 'vulnerability';
	}

	/**
	 * Default schedule. Tenable scan data does not change minute to minute and
	 * exports are relatively expensive, so four-hourly is the sane default.
	 */
	public function default_interval(): string {
		return 'vh_4hours';
	}

	/* =================================================================
	 * Settings
	 * ============================================================== */

	/**
	 * Settings field definitions.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array(
			array(
				'key'         => 'base_url',
				'label'       => __( 'API base URL', 'vulnhub' ),
				'type'        => 'url',
				'required'    => true,
				'default'     => 'https://cloud.tenable.com',
				'placeholder' => 'https://cloud.tenable.com',
				'help'        => __( 'Change only for a regional or FedRAMP instance.', 'vulnhub' ),
			),
			array(
				'key'      => 'access_key',
				'label'    => __( 'Access key', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'Generated per user in Tenable under Settings → My Account → API Keys. Give the integration its own service account so rate limits are tracked separately.', 'vulnhub' ),
			),
			array(
				'key'      => 'secret_key',
				'label'    => __( 'Secret key', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'Stored encrypted. Leave blank when editing to keep the existing key.', 'vulnhub' ),
			),
			array(
				'key'     => 'severity_floor',
				'label'   => __( 'Minimum severity to import', 'vulnhub' ),
				'type'    => 'select',
				'default' => 'low',
				'options' => array(
					'info'   => __( 'Info and above (everything)', 'vulnhub' ),
					'low'    => __( 'Low and above', 'vulnhub' ),
					'medium' => __( 'Medium and above', 'vulnhub' ),
					'high'   => __( 'High and above', 'vulnhub' ),
				),
				'help'    => __( 'Sent to Tenable as the export severity filter, so lower severities never leave their platform.', 'vulnhub' ),
			),
			array(
				'key'     => 'asset_days',
				'label'   => __( 'Only import assets seen in the last N days', 'vulnhub' ),
				'type'    => 'number',
				'default' => 90,
				'help'    => __( 'Applied as the last_assessed filter on the asset export, and as the since filter on the vulnerability export. Keeps decommissioned kit out of the inventory.', 'vulnhub' ),
			),
			array(
				'key'     => 'chunk_size',
				'label'   => __( 'Export chunk size', 'vulnhub' ),
				'type'    => 'number',
				'default' => 1000,
				'help'    => __( 'Assets per asset-export chunk (Tenable allows 100–10000; above 5000 is not recommended). Also used as the assets-per-chunk value for the vulnerability export, clamped to Tenable\'s 50–5000 range.', 'vulnhub' ),
			),
			array(
				'key'            => 'import_info',
				'label'          => __( 'Informational findings', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 0,
				'checkbox_label' => __( 'Import informational findings as well', 'vulnhub' ),
				'help'           => __( 'Off. Informational plugins describe what is on a machine rather than what is wrong with it -- file listings, execution history, service detection -- and they arrive in enough volume to dominate any total they enter: 82,383 of 323,595 findings before this was turned off. Turning it back on imports them, but they still land suppressed and stay outside every count until vulnhub_suppressed_severities is emptied too.', 'vulnhub' ),
			),
			array(
				'key'            => 'include_plugin_output',
				'label'          => __( 'Plugin diagnostic output', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 1,
				'checkbox_label' => __( 'Include full plugin output text on every finding', 'vulnhub' ),
				'help'           => __( 'The install path of the vulnerable file, the installed version and the fixed version all live in this text and are parsed back out of it, so with this off the Install path and App columns are empty on every finding. It does make the export substantially larger and slower, which is why it is a switch at all - leave it on unless an export is failing to produce chunks.', 'vulnhub' ),
			),
		);
	}

	/**
	 * Severity slugs this connector should import, honouring the floor and the
	 * informational-findings switch.
	 *
	 * @return array<int,string>
	 */
	public function severity_slugs(): array {
		$floor = (string) $this->get( 'severity_floor', 'low' );
		$index = array_search( $floor, self::LADDER, true );
		$slugs = array_slice( self::LADDER, false === $index ? 1 : (int) $index );

		if ( $this->settings->get_bool( $this->id(), 'import_info', false ) ) {
			if ( ! in_array( 'info', $slugs, true ) ) {
				array_unshift( $slugs, 'info' );
			}
		} else {
			$slugs = array_values( array_diff( $slugs, array( 'info' ) ) );
		}

		return array_values( $slugs );
	}

	/**
	 * Freshness window in days.
	 */
	private function asset_days(): int {
		return max( 1, min( 3650, $this->settings->get_int( $this->id(), 'asset_days', 90 ) ) );
	}

	/**
	 * Asset export chunk size, clamped to Tenable's documented 100–10000 range.
	 */
	private function asset_chunk_size(): int {
		return max( 100, min( 10000, $this->settings->get_int( $this->id(), 'chunk_size', 1000 ) ) );
	}

	/**
	 * Vulnerability export `num_assets`, clamped to Tenable's 50–5000 range.
	 *
	 * Deliberately NOT the same setting as asset_chunk_size() any more.
	 * Confirmed in production: with num_assets=1000 on a 643-asset account,
	 * Tenable computed the whole vuln export as a SINGLE chunk
	 * (total_chunks=1) and it sat in PROCESSING with zero chunks_available
	 * for 25+ minutes straight -- there is nothing to "produce in parallel"
	 * (see run_export()'s own doc comment) when there is only one chunk to
	 * produce in the first place. A smaller, independent default forces
	 * multiple chunks even on modest accounts, so Tenable can stream
	 * results back incrementally instead of blocking on one monolithic
	 * chunk. This is intentionally decoupled from the 'chunk_size' setting
	 * (which legitimately wants to be larger for the asset export, and
	 * inflating it was silently inflating this too).
	 */
	private function vuln_num_assets(): int {
		/*
		 * 50 (Tenable's documented floor), not 100. This sizes the *decode*,
		 * not just the export: a chunk arrives as one JSON document that has
		 * to be json_decode()'d whole, and at 100 assets/chunk this account
		 * produced chunks of 22k-45k nested records costing ~1.3GB each to
		 * decode. Measured curve at 100: 1.06GB -> 2.11GB -> 3.40GB -> OOM,
		 * with the baseline ratcheting up as PHP's allocator held freed
		 * blocks. Halving assets per chunk halves both the per-chunk spike
		 * and the ratchet it leaves behind.
		 */
		return max( 50, min( 5000, $this->settings->get_int( $this->id(), 'vuln_chunk_size', 50 ) ) );
	}

	/**
	 * Build an API client from the stored credentials.
	 */
	public function client(): VulnHub_Tenable_Client {
		return new VulnHub_Tenable_Client(
			(string) $this->get( 'base_url', 'https://cloud.tenable.com' ),
			$this->secret( 'access_key' ),
			$this->secret( 'secret_key' ),
			$this->http,
			array( $this, 'log' )
		);
	}

	/* =================================================================
	 * Connection test
	 * ============================================================== */

	/**
	 * Verify credentials against a cheap authenticated endpoint.
	 *
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	/**
	 * A live Tenable sync downloads and processes a large export, far too long
	 * to hold a browser request open for, so it runs in the background. Mock
	 * mode is small and stays inline.
	 */
	public function async_sync(): bool {
		return ! $this->is_mock();
	}

	/**
	 * A run is resumable when the store holds a state whose phase is neither
	 * finished nor failed -- i.e. a download or process that was interrupted.
	 */
	public function resumable_sync(): bool {
		if ( $this->is_mock() ) {
			return false;
		}
		$phase = (string) ( VH_Tenable_Store::read_state( $this->id() )['phase'] ?? '' );
		return in_array( $phase, array( 'download', 'process', 'finalize' ), true );
	}

	public function test_connection(): array {
		if ( $this->is_mock() ) {
			$devices = count( \VulnHub\Core\Mock::devices() );

			return array(
				'ok'      => true,
				'message' => sprintf(
					/* translators: %d: number of mock devices. */
					__( 'Mock mode: no Tenable call was made. Syncs will run against %d generated assets from the shared sample fleet.', 'vulnhub' ),
					$devices
				),
				'detail'  => array(
					'mode'    => 'mock',
					'devices' => $devices,
				),
			);
		}

		$client = $this->client();

		if ( ! $client->has_credentials() ) {
			return array(
				'ok'      => false,
				'message' => __( 'Add both a Tenable access key and secret key first.', 'vulnhub' ),
			);
		}

		$result = $client->whoami();

		if ( ! empty( $result['ok'] ) ) {
			$tags  = $client->tag_values( 200 );
			$cats  = array();
			foreach ( $tags as $tag ) {
				$name = (string) ( $tag['category_name'] ?? '' );
				if ( '' !== $name ) {
					$cats[ $name ] = true;
				}
			}

			if ( $cats ) {
				$result['message'] .= ' ' . sprintf(
					/* translators: %s: comma separated tag category names. */
					__( 'Tag categories available for ownership mapping: %s.', 'vulnhub' ),
					vh_trim( implode( ', ', array_keys( $cats ) ), 160 )
				);
			}

			$result['detail']['tag_categories'] = array_keys( $cats );
		}

		return $result;
	}

	/* =================================================================
	 * Sync
	 * ============================================================== */

	/**
	 * Import assets, then vulnerabilities, then roll up.
	 *
	 * @param array<string,mixed> $args Sync options.
	 * @return array{ok:bool,message:string}
	 */
	/** Zero the per-run caches and counters. Shared by both sync paths. */
	private function reset_counts(): void {
		$this->asset_cache = array();
		$this->vuln_cache  = array();
		$this->sla_cache   = array();
		$this->jobs        = array();
		$this->counts      = array(
			'assets'            => 0,
			'assets_created'    => 0,
			'assets_updated'    => 0,
			'assets_skipped'    => 0,
			'vulns'             => 0,
			'findings'          => 0,
			'findings_created'  => 0,
			'findings_fixed'    => 0,
			'findings_reopened' => 0,
			'findings_skipped'  => 0,
			'sev_critical'      => 0,
			'sev_high'          => 0,
			'sev_medium'        => 0,
			'sev_low'           => 0,
			'sev_info'          => 0,
		);
	}

	/* =================================================================
	 * Staged sync: download to disk, then process off disk, resumably.
	 * ============================================================== */

	/**
	 * The `since` (unix seconds) for this run. From the watermark of the last
	 * fully successful sync, minus a 24h overlap so a change near the boundary
	 * cannot slip through; on the very first run, a deep lookback so the whole
	 * history is captured. Tenable applies `since` to last_found for open
	 * findings and to last_fixed for fixed ones, so this window catches new
	 * detections and resolutions alike.
	 */
	private function since_for_run(): int {
		$watermark = (int) $this->settings->get( $this->id(), 'sync_watermark', 0 );

		if ( $watermark > 0 ) {
			return max( 0, $watermark - DAY_IN_SECONDS );
		}

		$first_days = (int) $this->settings->get( $this->id(), 'first_sync_days', 3650 );

		return time() - max( 1, $first_days ) * DAY_IN_SECONDS;
	}

	/**
	 * Advance the watermark to when THIS run started -- only ever called after
	 * a run has fully finished importing. A run that is interrupted or whose
	 * export did not complete leaves the watermark untouched, so the next run
	 * re-covers the same window rather than skipping over it. That is the rule
	 * that keeps an incremental sync from ever leaving a gap.
	 *
	 * @param array<string,mixed> $state Run state.
	 */
	private function advance_watermark( array $state ): void {
		$start = strtotime( (string) ( $state['started'] ?? vh_now() ) . ' UTC' ) ?: time();
		$this->settings->set( $this->id(), 'sync_watermark', $start );
	}

	/**
	 * Mirror the two-phase progress onto the run row, so the poller can draw a
	 * download bar and a processing bar. The resume checkpoint lives in the
	 * store's state.json; this is only what the UI reads.
	 *
	 * @param array<string,mixed> $state Run state.
	 */
	private function report_stage( array $state ): void {
		if ( ! $this->run_id ) {
			return;
		}

		$this->logger->stage_progress(
			$this->run_id,
			array(
				'phase'    => (string) ( $state['phase'] ?? '' ),
				'is_full'  => (bool) ( $state['is_full'] ?? false ),
				'download' => (array) ( $state['download'] ?? array() ),
				'process'  => (array) ( $state['process'] ?? array() ),
			)
		);
	}

	/**
	 * @param array<string,mixed> $args Sync options.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync_staged( array $args = array() ): array {
		unset( $args );

		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- cron/CLI, no page waiting.
		}

		$conn  = $this->id();
		$state = VH_Tenable_Store::read_state( $conn );

		$phase = (string) ( $state['phase'] ?? '' );

		// Fresh run when there is no state, or the last one is finished.
		if ( ! $state || in_array( $phase, array( '', 'done', 'failed' ), true ) ) {
			VH_Tenable_Store::clear( $conn );
			$since = $this->since_for_run();
			$state = array(
				'phase'    => 'download',
				'started'  => vh_now(),
				'since'    => $since,
				'is_full'  => ( $since <= time() - 200 * DAY_IN_SECONDS ),
				'download' => array( 'assets_chunks' => 0, 'vuln_chunks' => 0, 'bytes' => 0, 'status' => 'downloading' ),
				'process'  => array( 'stage' => 'assets', 'chunk' => 1, 'records_done' => 0, 'records_total' => 0 ),
			);
			VH_Tenable_Store::write_state( $conn, $state );
			$this->log( sprintf( 'Staged sync: fresh run, since %s.', gmdate( 'Y-m-d H:i', (int) $state['since'] ) ) );
		} else {
			$this->log( sprintf( 'Staged sync: resuming at phase "%s".', $phase ) );
		}

		$this->reset_counts();

		if ( 'download' === $state['phase'] ) {
			$state = $this->download_to_disk( $state );
			VH_Tenable_Store::write_state( $conn, $state );

			if ( 'download' === $state['phase'] ) {
				return array(
					'ok'      => false,
					'message' => __( 'The Tenable export did not finish downloading. It will be retried; no data was changed.', 'vulnhub' ),
				);
			}
		}

		if ( 'process' === $state['phase'] ) {
			$state = $this->process_from_disk( $state );
			VH_Tenable_Store::write_state( $conn, $state );
		}

		if ( 'finalize' === $state['phase'] ) {
			$this->finalize_sync( $state );
			$state['phase'] = 'done';
			VH_Tenable_Store::write_state( $conn, $state );
			$this->report_stage( $state );
			$this->advance_watermark( $state );
			VH_Tenable_Store::clear( $conn );

			return array( 'ok' => true, 'message' => $this->summary_message() );
		}

		return array( 'ok' => true, 'message' => $this->summary_message() );
	}

	/**
	 * Phase 1: stream the raw export to disk, chunk by chunk. No database
	 * writes happen here, so it is fast and cannot half-import anything -- it
	 * either lands the whole export on disk or it does not, and only a
	 * complete download advances to processing.
	 *
	 * @param array<string,mixed> $state Run state.
	 * @return array<string,mixed> Updated state.
	 */
	private function download_to_disk( array $state ): array {
		$conn  = $this->id();
		$since = (int) $state['since'];

		// Start clean: a resumed download re-fetches, because a Tenable export
		// job is short-lived and its chunk numbering does not survive a fresh
		// request anyway. Only the chunk files are cleared -- state.json stays,
		// so an interrupted download is still visible to the resume sweep and
		// its leftover chunks get cleared here on the next attempt rather than
		// sitting on disk. Processing, not downloading, is the expensive phase
		// worth resuming mid-way.
		VH_Tenable_Store::clear_chunks( $conn );
		$this->report_stage( $state );

		/* --- assets --- */
		$this->log( 'Downloading Tenable asset export to disk…' );
		$a_saved = 0;
		$a_recs  = 0;
		$assets_job = $this->client()->run_export(
			VulnHub_Tenable_Client::KIND_ASSETS,
			array(
				'chunk_size' => $this->asset_chunk_size(),
				'filters'    => array(
					'last_assessed' => $since,
					'is_licensed'   => true,
					'is_deleted'    => false,
					'is_terminated' => false,
				),
			),
			function ( array $chunk, int $chunk_id ) use ( $conn, &$a_saved, &$a_recs, &$state ) {
				$bytes = VH_Tenable_Store::save_chunk( $conn, 'assets', $chunk_id, (string) wp_json_encode( $chunk ) );
				++$a_saved;
				$a_recs += count( $chunk );
				$state['download']['assets_chunks'] = $a_saved;
				$state['download']['bytes']        += $bytes;
				$this->report_stage( $state );
			},
			function () use ( &$state ) {
				$this->report_stage( $state ); // heartbeat between chunks
			}
		);

		if ( 'FINISHED' !== (string) ( $assets_job['status'] ?? '' ) ) {
			$this->log( sprintf( 'Asset export did not finish (%s); will retry.', (string) ( $assets_job['status'] ?? 'no response' ) ) );
			return $state; // still 'download'
		}

		/* --- vulns --- */
		$this->log( 'Downloading Tenable vulnerability export to disk…' );
		$v_saved = 0;
		$v_recs  = 0;
		$vulns_job = $this->client()->run_export(
			VulnHub_Tenable_Client::KIND_VULNS,
			array(
				'num_assets'            => $this->vuln_num_assets(),
				'include_unlicensed'    => false,
				'include_plugin_output' => $this->settings->get_bool( $this->id(), 'include_plugin_output', true ),
				'filters'               => array(
					'severity' => array_values( $this->severity_slugs() ),
					'state'    => array( 'OPEN', 'REOPENED', 'FIXED' ),
					'since'    => $since,
				),
			),
			function ( array $chunk, int $chunk_id ) use ( $conn, &$v_saved, &$v_recs, &$state ) {
				$bytes = VH_Tenable_Store::save_chunk( $conn, 'vulns', $chunk_id, (string) wp_json_encode( $chunk ) );
				++$v_saved;
				$v_recs += count( $chunk );
				$state['download']['vuln_chunks'] = $v_saved;
				$state['download']['bytes']      += $bytes;
				$this->report_stage( $state );
			},
			function () use ( &$state ) {
				$this->report_stage( $state ); // heartbeat between chunks
			}
		);

		if ( 'FINISHED' !== (string) ( $vulns_job['status'] ?? '' ) ) {
			$this->log( sprintf( 'Vulnerability export did not finish (%s); will retry.', (string) ( $vulns_job['status'] ?? 'no response' ) ) );
			return $state; // still 'download'
		}

		// Whole export is on disk. Hand over to processing. Remember this
		// download's size so the NEXT run's progress bar has a scale to show
		// "X MB of ~Y MB" against, kept per size class (a full first run and a
		// small incremental are wildly different, so they must not overwrite
		// each other's estimate).
		$est_key = ( (int) $state['since'] <= time() - 200 * DAY_IN_SECONDS ) ? 'dl_est_full' : 'dl_est_incr';
		update_option( 'vulnhub_' . $est_key . '_' . $this->id(), (int) $state['download']['bytes'], false );

		$state['download']['status']         = 'done';
		$state['process']['records_total']   = $a_recs + $v_recs;
		$state['process']['asset_chunks']    = $a_saved;
		$state['process']['vuln_chunks']     = $v_saved;
		$state['phase']                      = 'process';
		$this->log( sprintf( 'Download complete: %d asset chunk(s), %d vuln chunk(s), %d records on disk.', $a_saved, $v_saved, $a_recs + $v_recs ) );
		$this->report_stage( $state );

		return $state;
	}

	/**
	 * Phase 2: import the downloaded chunks one at a time, checkpointing after
	 * each so an interruption resumes from the next chunk rather than the
	 * start. Memory stays bounded to a single chunk, which is what keeps a
	 * quarter-million-row import from being OOM-killed.
	 *
	 * @param array<string,mixed> $state Run state.
	 * @return array<string,mixed> Updated state.
	 */
	private function process_from_disk( array $state ): array {
		$conn         = $this->id();
		$asset_chunks = (int) ( $state['process']['asset_chunks'] ?? 0 );
		$vuln_chunks  = (int) ( $state['process']['vuln_chunks'] ?? 0 );

		// Assets first, so findings can attach to them.
		if ( 'assets' === ( $state['process']['stage'] ?? 'assets' ) ) {
			for ( $i = (int) $state['process']['chunk']; $i <= $asset_chunks; $i++ ) {
				$records = VH_Tenable_Store::read_chunk( $conn, 'assets', $i );
				$this->import_asset_chunk( $records, $i );
				unset( $records );

				// Checkpoint past this chunk, THEN free its file. The order
				// matters: the checkpoint is on disk before the data is gone,
				// so a crash in between leaves a resumable state, never a hole.
				$state['process']['chunk']         = $i + 1;
				$state['process']['records_done'] += 0; // asset rows are not the headline count
				VH_Tenable_Store::write_state( $conn, $state );
				VH_Tenable_Store::delete_chunk( $conn, 'assets', $i );
				$this->report_stage( $state );
			}

			$state['process']['stage'] = 'vulns';
			$state['process']['chunk'] = 1;
			VH_Tenable_Store::write_state( $conn, $state );
		}

		// Findings.
		for ( $i = (int) $state['process']['chunk']; $i <= $vuln_chunks; $i++ ) {
			$records = VH_Tenable_Store::read_chunk( $conn, 'vulns', $i );

			foreach ( $records as $record ) {
				$this->import_finding( $record );
				++$state['process']['records_done'];
			}
			unset( $records );

			// Checkpoint first, then free the chunk's disk (see the note in the
			// asset loop): the resume point is durable before the bytes go.
			$state['process']['chunk'] = $i + 1;
			VH_Tenable_Store::write_state( $conn, $state );
			VH_Tenable_Store::delete_chunk( $conn, 'vulns', $i );
			$this->report_stage( $state );

			// Keep the working set small across a long run.
			if ( function_exists( 'gc_collect_cycles' ) ) {
				gc_collect_cycles();
			}
		}

		$state['phase'] = 'finalize';

		return $state;
	}

	/**
	 * Phase 3: the once-per-run work that must happen after every finding is
	 * in -- roll up per-asset counters, and reconcile the asset inventory so
	 * anything Tenable has dropped is retired. Strictly Tenable-scoped: assets
	 * owned by other connectors are never touched.
	 *
	 * @param array<string,mixed> $state Run state.
	 */
	private function finalize_sync( array $state ): void {
		/*
		 * Prune Tenable-dropped assets -- but only on a FULL run, whose asset
		 * export is the whole inventory. On an incremental run the asset
		 * export is just the recently-assessed hosts, so absence means "not
		 * scanned lately", not "gone", and pruning on it would be wrong. The
		 * asset chunks are still on disk here (the store is cleared after
		 * finalize), so the seen set is read straight from them. Tenable-scoped
		 * and safeguarded inside retire_absent_tenable().
		 */
		if ( ! empty( $state['is_full'] ) && $this->settings->get_bool( $this->id(), 'prune_absent', true ) ) {
			$seen = array();
			$chunks = (int) ( $state['process']['asset_chunks'] ?? 0 );
			for ( $i = 1; $i <= $chunks; $i++ ) {
				foreach ( VH_Tenable_Store::read_chunk( $this->id(), 'assets', $i ) as $rec ) {
					$uuid = (string) ( $rec['id'] ?? $rec['uuid'] ?? '' );
					if ( '' !== $uuid ) {
						$seen[ $uuid ] = true;
					}
				}
			}

			$result = \VulnHub\Core\Repo::retire_absent_tenable( array_keys( $seen ) );

			if ( ! empty( $result['aborted'] ) ) {
				$this->log( sprintf(
					'Prune skipped: %d of %d Tenable assets looked absent (over the 15%% safety limit) -- the asset export was likely incomplete, so nothing was retired.',
					(int) $result['retired'],
					(int) $result['candidates']
				) );
			} elseif ( (int) $result['retired'] > 0 ) {
				$this->log( sprintf( 'Retired %d asset(s) Tenable no longer reports (Tenable-only, reversible).', (int) $result['retired'] ) );
			}
		}

		$this->log( 'Recalculating asset roll-ups…' );
		\VulnHub\Core\Repo::recalculate_asset_rollups();
		$this->persist_run_summary();
	}

	private function summary_message(): string {
		return sprintf(
			/* translators: 1: assets, 2: vulnerability definitions, 3: findings, 4: fixed findings, 5: reopened findings. */
			__( 'Imported %1$d assets, %2$d vulnerability definitions and %3$d findings (%4$d already remediated, %5$d reopened).', 'vulnhub' ),
			(int) $this->counts['assets'],
			(int) $this->counts['vulns'],
			(int) $this->counts['findings'],
			(int) $this->counts['findings_fixed'],
			(int) $this->counts['findings_reopened']
		);
	}

	/**
	 * Entry point. Mock stays on the old one-pass path (it is small and
	 * deterministic); a live sync goes through the staged download-then-process
	 * pipeline so it can survive an interruption and show two progress bars.
	 *
	 * @param array<string,mixed> $args Sync options.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		if ( $this->is_mock() ) {
			return $this->do_sync_direct( $args );
		}

		return $this->do_sync_staged( $args );
	}

	protected function do_sync_direct( array $args = array() ): array {
		unset( $args );

		// A live vulnerability export can legitimately run well past PHP's
		// default 300s web request ceiling (the client's own poll ceiling is
		// now 1500s). Without this, an interactive "Sync now" click gets
		// killed by PHP mid-poll with no response ever reaching the browser
		// -- the button spins and then nothing, because the request that
		// was supposed to resolve it is simply gone. A WP-Cron-driven
		// scheduled run already has no such ceiling (WP-CLI), so this only
		// matters for the interactive path, but is harmless either way.
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 1800 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		$this->reset_counts();

		$severities = $this->severity_slugs();
		$days       = $this->asset_days();

		$this->log(
			sprintf(
				'Importing severities [%s], assets assessed within %d days, chunk size %d.',
				implode( ', ', $severities ),
				$days,
				$this->asset_chunk_size()
			)
		);

		$this->progress( __( 'Starting sync', 'vulnhub' ), 0 );

		/* --- 1. Assets ------------------------------------------------ */
		$this->sync_assets( $days );

		/* --- 2/3. Vulnerabilities and findings ------------------------ */
		$this->sync_vulns( $days, $severities );

		/* --- 5. Roll the per-asset counters up ------------------------ */
		$this->log( 'Recalculating asset roll-ups…' );
		\VulnHub\Core\Repo::recalculate_asset_rollups();

		$this->persist_run_summary();

		$message = sprintf(
			/* translators: 1: assets, 2: vulnerability definitions, 3: findings, 4: fixed findings, 5: reopened findings. */
			__( 'Imported %1$d assets, %2$d vulnerability definitions and %3$d findings (%4$d already remediated, %5$d reopened).', 'vulnhub' ),
			$this->counts['assets'],
			$this->counts['vulns'],
			$this->counts['findings'],
			$this->counts['findings_fixed'],
			$this->counts['findings_reopened']
		);

		// An export that never reached FINISHED (TIMEOUT, ERROR, CANCELLED,
		// or the empty status left behind when a poll request itself failed)
		// must not be reported as a clean success -- that is exactly how a
		// live vuln export timing out silently imported zero findings while
		// every dashboard kept showing a green "success" for the sync.
		$incomplete = array_values( array_filter(
			$this->jobs,
			static fn( array $job ): bool => 'FINISHED' !== (string) ( $job['status'] ?? '' )
		) );

		if ( $incomplete ) {
			$bad = implode(
				', ',
				array_map(
					static fn( array $job ): string => sprintf( '%s export: %s', $job['kind'], $job['status'] ?: 'no response' ),
					$incomplete
				)
			);

			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: partial import summary, 2: which export(s) did not finish. */
					__( '%1$s This sync did not fully complete (%2$s) -- the counts above are partial. Try again; a live vulnerability export can take a long time on a first run.', 'vulnhub' ),
					$message,
					$bad
				),
			);
		}

		return array(
			'ok'      => true,
			'message' => $message,
		);
	}

	/**
	 * Step 1: export and import the asset inventory.
	 *
	 * @param int $days Freshness window.
	 */
	private function sync_assets( int $days ): void {
		$this->log( 'Requesting Tenable asset export…' );

		if ( $this->is_mock() ) {
			$chunks = VulnHub_Tenable_Mock::asset_chunks( $this->asset_chunk_size(), $days );
			$job    = $this->replay_mock_export( VulnHub_Tenable_Client::KIND_ASSETS, $chunks, array( $this, 'import_asset_chunk' ) );
		} else {
			$job = $this->client()->run_export(
				VulnHub_Tenable_Client::KIND_ASSETS,
				array(
					/*
					 * Documented asset-export request body: chunk_size plus an
					 * optional filters object. `last_assessed` is a unix
					 * timestamp — assets last scanned after it are returned.
					 */
					'chunk_size' => $this->asset_chunk_size(),
					'filters'    => array(
						'last_assessed' => time() - $days * DAY_IN_SECONDS,
						'is_licensed'   => true,
						'is_deleted'    => false,
						'is_terminated' => false,
					),
				),
				array( $this, 'import_asset_chunk' )
			);
		}

		$this->record_job( VulnHub_Tenable_Client::KIND_ASSETS, $job );

		$this->log(
			sprintf(
				'Assets: %d imported (%d new, %d updated, %d skipped).',
				$this->counts['assets'],
				$this->counts['assets_created'],
				$this->counts['assets_updated'],
				$this->counts['assets_skipped']
			)
		);
	}

	/**
	 * Steps 3 and 4: export vulnerabilities, upsert definitions and findings,
	 * and compute SLA due dates and risk scores.
	 *
	 * @param int               $days       Freshness window.
	 * @param array<int,string> $severities Severity slugs to import.
	 */
	private function sync_vulns( int $days, array $severities ): void {
		$this->log( 'Requesting Tenable vulnerability export…' );
		$this->progress( __( 'Requesting vulnerability export from Tenable', 'vulnhub' ), (int) $this->counts['findings'] );

		if ( $this->is_mock() ) {
			$chunks = VulnHub_Tenable_Mock::vuln_chunks( $this->vuln_num_assets(), $severities, $days );
			$job    = $this->replay_mock_export( VulnHub_Tenable_Client::KIND_VULNS, $chunks, array( $this, 'import_vuln_chunk' ) );
		} else {
			$job = $this->client()->run_export(
				VulnHub_Tenable_Client::KIND_VULNS,
				array(
					'num_assets'          => $this->vuln_num_assets(),
					'include_unlicensed'  => false,
					'include_plugin_output' => $this->settings->get_bool( $this->id(), 'include_plugin_output', true ),
					'filters'             => array(
						/*
						 * `severity` takes the lowercase slugs; `state` takes
						 * the uppercase OPEN / REOPENED / FIXED values. Without
						 * a time filter Tenable only returns the last 30 days,
						 * so `since` (unix seconds) is always supplied.
						 */
						'severity' => array_values( $severities ),
						'state'    => array( 'OPEN', 'REOPENED', 'FIXED' ),
						'since'    => time() - $days * DAY_IN_SECONDS,
					),
				),
				array( $this, 'import_vuln_chunk' )
			);
		}

		$this->record_job( VulnHub_Tenable_Client::KIND_VULNS, $job );

		$this->log(
			sprintf(
				'Findings: %d imported (%d new, %d fixed, %d reopened, %d skipped) across %d vulnerability definitions.',
				$this->counts['findings'],
				$this->counts['findings_created'],
				$this->counts['findings_fixed'],
				$this->counts['findings_reopened'],
				$this->counts['findings_skipped'],
				$this->counts['vulns']
			)
		);
		$this->log(
			sprintf(
				'Severity distribution — critical %d, high %d, medium %d, low %d, info %d.',
				$this->counts['sev_critical'],
				$this->counts['sev_high'],
				$this->counts['sev_medium'],
				$this->counts['sev_low'],
				$this->counts['sev_info']
			)
		);
	}

	/**
	 * Feed pre-built mock chunks through the same handler the live export uses.
	 *
	 * @param string                                            $kind     Export kind.
	 * @param array<int,array<int,array<string,mixed>>>         $chunks   Mock chunks.
	 * @param callable(array<int,array<string,mixed>>,int):void $on_chunk Chunk handler.
	 * @return array{uuid:string,status:string,chunks:int,records:int,seconds:float}
	 */
	private function replay_mock_export( string $kind, array $chunks, callable $on_chunk ): array {
		$started = microtime( true );
		$uuid    = VulnHub_Tenable_Mock::uuid( $kind . gmdate( 'Y-m-d-H' ) );
		$records = 0;

		$this->log( sprintf( 'Queued %s export %s (mock)', $kind, $uuid ) );

		foreach ( $chunks as $index => $chunk ) {
			$records += count( $chunk );
			$on_chunk( $chunk, (int) $index + 1 );
		}

		$seconds = round( microtime( true ) - $started, 2 );

		$this->log(
			sprintf(
				'%s export %s finished as FINISHED — %d chunk(s), %d record(s) in %.2fs (mock)',
				ucfirst( $kind ),
				$uuid,
				count( $chunks ),
				$records,
				$seconds
			)
		);

		return array(
			'uuid'    => $uuid,
			'status'  => 'FINISHED',
			'chunks'  => count( $chunks ),
			'records' => $records,
			'seconds' => (float) $seconds,
		);
	}

	/**
	 * Remember an export job for the admin screen.
	 *
	 * @param string              $kind Export kind.
	 * @param array<string,mixed> $job  Job summary from the client.
	 */
	private function record_job( string $kind, array $job ): void {
		$this->jobs[] = array(
			'kind'     => $kind,
			'uuid'     => (string) ( $job['uuid'] ?? '' ),
			'status'   => (string) ( $job['status'] ?? '' ),
			'chunks'   => (int) ( $job['chunks'] ?? 0 ),
			'records'  => (int) ( $job['records'] ?? 0 ),
			'seconds'  => (float) ( $job['seconds'] ?? 0 ),
			'mock'     => $this->is_mock(),
			'finished' => vh_now(),
		);
	}

	/**
	 * Persist run tallies and export job history for the Tenable admin screen.
	 */
	private function persist_run_summary(): void {
		$history = (array) $this->get( 'export_jobs', array() );
		$history = array_merge( $this->jobs, is_array( $history ) ? $history : array() );
		$history = array_slice( array_values( $history ), 0, 12 );

		$this->settings->update(
			$this->id(),
			array(
				'last_import'      => $this->counts,
				'last_import_at'   => vh_now(),
				'last_import_mode' => $this->is_mock() ? 'mock' : 'live',
				'export_jobs'      => $history,
			)
		);
	}

	/* =================================================================
	 * Asset normalisation
	 * ============================================================== */

	/**
	 * Import one chunk of the asset export.
	 *
	 * @param array<int,array<string,mixed>> $records  Asset records.
	 * @param int                            $chunk_id Chunk number.
	 */
	public function import_asset_chunk( array $records, int $chunk_id ): void {
		foreach ( $records as $record ) {
			$this->bump( 'processed' );

			$data = $this->normalise_asset( $record );

			if ( '' === (string) $data['tenable_uuid'] ) {
				$this->bump( 'skipped' );
				++$this->counts['assets_skipped'];
				continue;
			}

			$result = \VulnHub\Core\Repo::upsert_asset( $data );

			if ( ! $result['id'] ) {
				$this->bump( 'failed' );
				++$this->counts['assets_skipped'];
				continue;
			}

			++$this->counts['assets'];

			if ( $result['created'] ) {
				$this->bump( 'created' );
				++$this->counts['assets_created'];
			} else {
				$this->bump( 'updated' );
				++$this->counts['assets_updated'];
			}

			$this->asset_cache[ (string) $data['tenable_uuid'] ] = array(
				'id'          => (int) $result['id'],
				'criticality' => (string) $data['criticality'],
				'team_id'     => 0,
				'hostname'    => (string) $data['hostname'],
				'asset_type'  => (string) $data['asset_type'],
			);
		}

		$this->log( sprintf( 'Asset chunk %d: %d record(s) processed.', $chunk_id, count( $records ) ) );
	}

	/**
	 * Map a Tenable asset export record onto Repo::upsert_asset() fields.
	 *
	 * @param array<string,mixed> $record Tenable asset record.
	 * @return array<string,mixed>
	 */
	public function normalise_asset( array $record ): array {
		$hostnames = $this->strings( $record['hostnames'] ?? array() );
		$fqdns     = $this->strings( $record['fqdns'] ?? array() );
		$ipv4s     = $this->strings( $record['ipv4s'] ?? array() );
		$macs      = $this->strings( $record['mac_addresses'] ?? array() );
		$oses      = $this->strings( $record['operating_systems'] ?? array() );
		$netbios   = (string) ( $record['netbios_name'] ?? '' );

		/*
		 * Tenable never guarantees a hostname. Fall back down the identity
		 * ladder — hostname, the short form of the FQDN, then NetBIOS — so an
		 * asset always has something a human can recognise.
		 */
		$hostname = $hostnames[0] ?? '';
		if ( '' === $hostname && $fqdns ) {
			$hostname = (string) strtok( $fqdns[0], '.' );
		}
		if ( '' === $hostname ) {
			$hostname = $netbios;
		}

		$operating_system = $oses[0] ?? '';
		$tags             = $this->normalise_tags( $record['tags'] ?? array() );

		return array(
			'primary_source'     => $this->id(),
			'tenable_uuid'       => (string) ( $record['id'] ?? $record['uuid'] ?? '' ),
			'hostname'           => $hostname,
			'fqdn'               => $fqdns[0] ?? '',
			'netbios_name'       => $netbios,
			'ipv4'               => $ipv4s[0] ?? '',
			'ipv4s'              => $ipv4s,
			'mac_address'        => $macs[0] ?? '',
			'asset_type'         => $this->classify_asset_type( $record ),
			'operating_system'   => vh_trim( $operating_system, 190 ),
			'os_version'         => $this->os_version( $operating_system ),
			'has_agent'          => ! empty( $record['has_agent'] ),
			'criticality'        => $this->criticality_from( $record, $tags ),
			'environment'        => $this->tag_value( $tags, 'Environment' ),
			'business_service'   => $this->tag_value( $tags, 'Business Service' ),
			/*
			 * Deliberately NOT mapped to azure_ad_device_id: that column is the
			 * Entra ID *device* id that Intune writes, and Tenable's
			 * azure_vm_id is the Azure VM instance id — a different identifier
			 * entirely. Writing one into the other would poison the asset
			 * match key. Both Azure identifiers are preserved in raw below,
			 * where reporting can reach them without risking a false merge.
			 */
			'first_seen'         => (string) ( $record['first_seen'] ?? $record['created_at'] ?? '' ),
			'last_seen'          => (string) ( $record['last_seen'] ?? $record['updated_at'] ?? '' ),
			'tags'               => $tags,
			'raw'                => array(
				'tenable' => array(
					'id'                => (string) ( $record['id'] ?? '' ),
					'system_types'      => $this->strings( $record['system_types'] ?? array() ),
					'operating_systems' => $oses,
					'sources'           => $record['sources'] ?? array(),
					'acr_score'         => $record['acr_score'] ?? null,
					'exposure_score'    => $record['exposure_score'] ?? null,
					'network_name'      => (string) ( $record['network_name'] ?? '' ),
					'agent_uuid'        => (string) ( $record['agent_uuid'] ?? '' ),
					'azure_vm_id'       => (string) ( $record['azure_vm_id'] ?? '' ),
					'azure_resource_id' => (string) ( $record['azure_resource_id'] ?? '' ),
					'aws_ec2_instance_id' => (string) ( $record['aws_ec2_instance_id'] ?? '' ),
				),
			),
		);
	}

	/**
	 * Decide what kind of thing this asset is.
	 *
	 * This matters more than it looks. The ownership engine treats
	 * `workstation` and `mobile` as user-bound: those assets MUST resolve to a
	 * named individual, and anything mis-typed as a server silently falls back
	 * to a team and never gets chased. So the classifier is deliberately
	 * ordered from the most reliable signal to the weakest:
	 *
	 *   1. `system_types` — Tenable's own device classification. When it says
	 *      router/switch/firewall/AP, that is authoritative network gear.
	 *   2. Mobile operating systems — iOS/iPadOS/Android are never servers.
	 *   3. Server operating systems — "Windows Server", any Linux/BSD/ESXi
	 *      build string. Checked BEFORE desktop Windows, because
	 *      "Microsoft Windows Server 2022" also contains "Windows".
	 *   4. Desktop operating systems — Windows 10/11/8/7, macOS.
	 *   5. Network/appliance firmware strings for kit that reports no
	 *      `system_types` (IOS, IOS-XE, NX-OS, PAN-OS, FortiOS, AOS-CX…).
	 *   6. Hostname conventions, the weakest signal, used only when the OS is
	 *      unknown — an unauthenticated scan often yields nothing else.
	 *   7. Otherwise `unknown`, which the portal surfaces for triage rather
	 *      than guessing wrong.
	 *
	 * @param array<string,mixed> $record Tenable asset record.
	 * @return string One of vh_asset_types().
	 */
	/**
	 * Derive an asset type from the customer's Tenable tag taxonomy.
	 *
	 * Tenable tags are (category, value) pairs and organisations overwhelmingly
	 * encode device class in them — a "WORKSTATIONS" or "SERVERS" category, or
	 * a value like "Windows Workstations" / "AWS". Both the category and the
	 * value are inspected, because either half may carry the meaning.
	 *
	 * A tag that names a rollup ("All_Licensed_Assets") is deliberately ignored:
	 * it classifies nothing.
	 *
	 * @param mixed $tags Tag array from an export record.
	 */
	public function asset_type_from_tags( mixed $tags ): string {
		if ( ! is_array( $tags ) ) {
			return '';
		}

		$ignore = array( 'data_rollup', 'datarollup', 'rollup', 'all_licensed_assets', 'licensed' );

		foreach ( $tags as $tag ) {
			if ( ! is_array( $tag ) ) {
				continue;
			}

			$category = strtolower( trim( (string) ( $tag['category'] ?? $tag['category_name'] ?? $tag['key'] ?? '' ) ) );
			$value    = strtolower( trim( (string) ( $tag['value'] ?? '' ) ) );

			if ( in_array( $category, $ignore, true ) || in_array( $value, $ignore, true ) ) {
				continue;
			}

			foreach ( array( $category, $value ) as $needle ) {
				if ( '' === $needle ) {
					continue;
				}
				if ( preg_match( '/(workstation|laptop|desktop|endpoint|pc|client)/', $needle ) ) {
					return 'workstation';
				}
				if ( preg_match( '/(server|aws|azure|gcp|ec2|vm|instance|database|appserver)/', $needle ) ) {
					// A cloud tag still describes a server workload; the
					// environment is captured separately.
					return in_array( $needle, array( 'aws', 'azure', 'gcp' ), true ) ? 'cloud' : 'server';
				}
				if ( preg_match( '/(mobile|phone|ios|android|tablet|ipad)/', $needle ) ) {
					return 'mobile';
				}
				if ( preg_match( '/(network|router|switch|firewall|wireless)/', $needle ) ) {
					return 'network';
				}
				if ( preg_match( '/(printer|appliance|camera|iot|ot|scada)/', $needle ) ) {
					return 'appliance';
				}
			}
		}

		return '';
	}

	public function classify_asset_type( array $record ): string {
		$system_types = array_map( 'strtolower', $this->strings( $record['system_types'] ?? array() ) );
		$oses         = $this->strings( $record['operating_systems'] ?? array() );
		$os           = strtolower( implode( ' ', $oses ) );
		$hostname     = strtolower( (string) ( $this->strings( $record['hostnames'] ?? array() )[0] ?? '' ) );

		// 0. The customer's own tag taxonomy is the strongest signal there is,
		// and in practice often the ONLY one: a Tenable asset export can carry
		// no hostname, no OS and no system_types at all — just a UUID, some IP
		// addresses and tags. In one real 912-asset export, 911 were typed
		// purely by tag category (WORKSTATIONS / SERVERS), and nothing else in
		// the file could have classified them.
		$type_from_tag = $this->asset_type_from_tags( $record['tags'] ?? array() );
		if ( '' !== $type_from_tag ) {
			return $type_from_tag;
		}

		// 1. Tenable's own device classification.
		foreach ( $system_types as $type ) {
			if ( preg_match( '/(router|switch|firewall|network|wireless-access-point|wap|load-balancer|vpn)/', $type ) ) {
				return 'network';
			}
			if ( preg_match( '/(printer|scanner|voip|camera|embedded|scada|medical)/', $type ) ) {
				return 'appliance';
			}
			if ( 'hypervisor' === $type ) {
				return 'server';
			}
		}

		// 2. Mobile platforms.
		if ( preg_match( '/\b(ios|ipados|iphone os|android|windows phone|blackberry)\b/', $os ) ) {
			return 'mobile';
		}

		// 3. Server operating systems. "Windows Server" must be tested before
		// the generic Windows desktop match below.
		if ( str_contains( $os, 'windows server' ) || preg_match( '/windows (2000|2003|2008|2012|2016|2019|2022|2025)/', $os ) ) {
			return 'server';
		}
		if ( preg_match( '/\b(linux|ubuntu|debian|centos|red hat|rhel|suse|oracle linux|amazon linux|rocky|almalinux|freebsd|openbsd|solaris|aix|esxi|vmware vcenter)\b/', $os ) ) {
			return 'server';
		}

		// 4. General-purpose desktop operating systems.
		if ( preg_match( '/windows (11|10|8\.1|8|7|xp|vista)/', $os ) || preg_match( '/\b(macos|mac os x|os x)\b/', $os ) ) {
			return 'workstation';
		}

		// 5. Network firmware that reports no system_types.
		if ( preg_match( '/\b(ios-xe|ios xe|nx-os|pan-os|fortios|junos|aos-cx|arubaos|screenos|routeros|comware|big-ip)\b/', $os ) ) {
			return 'network';
		}
		if ( preg_match( '/\b(cisco|juniper|palo alto|fortinet|aruba|mikrotik|ubiquiti|f5 networks)\b/', $os ) ) {
			return 'network';
		}

		// 6. Hostname conventions — last resort, when the scan learned no OS.
		if ( '' !== $hostname ) {
			if ( preg_match( '/^(nzws|ws|wks|lt|lap|desktop|dt|mac)[-_0-9]/', $hostname ) ) {
				return 'workstation';
			}
			if ( preg_match( '/^(mob|mbl|iphone|ipad|android)[-_0-9]/', $hostname ) ) {
				return 'mobile';
			}
			if ( preg_match( '/(^|[-_])(sw|fw|rtr|wlc|ap|switch|firewall|router)([-_0-9]|$)/', $hostname ) ) {
				return 'network';
			}
			if ( preg_match( '/(^|[-_])(dc|sql|app|web|api|srv|svr|fs|bkp|k8s|prt|mon|vpn|dev|leg)[0-9]*$/', $hostname ) ) {
				return 'server';
			}
		}

		// 7. A general-purpose box we could not place. Do not guess.
		return 'unknown';
	}

	/**
	 * Extract a version-looking token from a Tenable OS product string.
	 *
	 * Tenable reports Linux hosts as "Linux Kernel 5.15.0-105-generic on
	 * Ubuntu 22.04.4 LTS" — the distribution release after "on" is the useful
	 * half, so prefer it over the kernel build.
	 */
	private function os_version( string $operating_system ): string {
		$subject = $operating_system;
		$parts   = preg_split( '/\bon\b/i', $operating_system );

		if ( is_array( $parts ) && count( $parts ) > 1 ) {
			$subject = (string) end( $parts );
		}

		foreach ( array( $subject, $operating_system ) as $candidate ) {
			if ( preg_match( '/(\d+(?:\.\d+){1,3})/', $candidate, $matches ) ) {
				return vh_trim( $matches[1], 90 );
			}
		}

		return '';
	}

	/**
	 * Normalise Tenable's tag objects to the platform's `key`/`value` pairs,
	 * which is exactly what the ownership mapping engine reads.
	 *
	 * @param mixed $tags Raw tags value from the export record.
	 * @return array<int,array{key:string,value:string}>
	 */
	private function normalise_tags( mixed $tags ): array {
		if ( ! is_array( $tags ) ) {
			return array();
		}

		$out = array();

		foreach ( $tags as $tag ) {
			if ( ! is_array( $tag ) ) {
				continue;
			}

			// Export chunks use `key`; some endpoints use `category_name`.
			$key   = (string) ( $tag['key'] ?? $tag['category_name'] ?? '' );
			$value = (string) ( $tag['value'] ?? '' );

			if ( '' === trim( $key ) ) {
				continue;
			}

			$out[] = array(
				'key'   => $key,
				'value' => $value,
			);
		}

		return $out;
	}

	/**
	 * Read a tag value by category name.
	 *
	 * @param array<int,array{key:string,value:string}> $tags Normalised tags.
	 * @param string                                    $key  Category name.
	 */
	private function tag_value( array $tags, string $key ): string {
		foreach ( $tags as $tag ) {
			if ( 0 === strcasecmp( $tag['key'], $key ) ) {
				return $tag['value'];
			}
		}

		return '';
	}

	/**
	 * Derive business criticality from a Criticality tag, otherwise from
	 * Tenable's Asset Criticality Rating (ACR, 1–10).
	 *
	 * @param array<string,mixed>                       $record Asset record.
	 * @param array<int,array{key:string,value:string}> $tags   Normalised tags.
	 */
	private function criticality_from( array $record, array $tags ): string {
		$tagged = strtolower( $this->tag_value( $tags, 'Criticality' ) );

		if ( in_array( $tagged, array( 'critical', 'high', 'medium', 'low' ), true ) ) {
			return $tagged;
		}

		$acr = (int) ( $record['acr_score'] ?? 0 );

		return match ( true ) {
			$acr >= 9 => 'critical',
			$acr >= 7 => 'high',
			$acr >= 4 => 'medium',
			$acr >= 1 => 'low',
			default   => 'medium',
		};
	}

	/**
	 * Coerce a value to a clean list of non-empty strings.
	 *
	 * @param mixed $value Raw value.
	 * @return array<int,string>
	 */
	private function strings( mixed $value ): array {
		if ( is_string( $value ) ) {
			$value = array( $value );
		}
		if ( ! is_array( $value ) ) {
			return array();
		}

		$out = array();

		foreach ( $value as $item ) {
			if ( ! is_scalar( $item ) ) {
				continue;
			}
			$item = trim( (string) $item );
			if ( '' !== $item ) {
				$out[] = $item;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/* =================================================================
	 * Vulnerability + finding normalisation
	 * ============================================================== */

	/**
	 * Import one chunk of the vulnerability export.
	 *
	 * @param array<int,array<string,mixed>> $records  Vulnerability records.
	 * @param int                            $chunk_id Chunk number.
	 */
	public function import_vuln_chunk( array $records, int $chunk_id ): void {
		foreach ( $records as $record ) {
			$this->bump( 'processed' );
			$this->import_finding( $record );
		}

		$this->log( sprintf( 'Vulnerability chunk %d: %d record(s) processed.', $chunk_id, count( $records ) ) );
	}

	/**
	 * Import a single Tenable vulnerability record.
	 *
	 * @param array<string,mixed> $record Vulnerability export record.
	 */
	private function import_finding( array $record ): void {
		$asset_uuid = (string) ( $record['asset']['uuid'] ?? $record['asset']['id'] ?? '' );
		$asset      = $this->asset_for( $asset_uuid, (string) ( $record['asset']['hostname'] ?? '' ) );

		if ( ! $asset ) {
			$this->bump( 'skipped' );
			++$this->counts['findings_skipped'];
			return;
		}

		$plugin = is_array( $record['plugin'] ?? null ) ? $record['plugin'] : array();

		/*
		 * Tenable's numeric severity id is the canonical value (4 critical …
		 * 0 info) and maps 1:1 onto our ladder; the string is a display label.
		 */
		$severity = isset( $record['severity_id'] )
			? vh_severity_from_id( (int) $record['severity_id'] )
			: strtolower( (string) ( $record['severity'] ?? 'info' ) );

		if ( ! array_key_exists( $severity, vh_severities() ) ) {
			$severity = 'info';
		}

		$vuln_id = $this->vuln_id_for( $plugin, $severity );

		if ( ! $vuln_id ) {
			$this->bump( 'skipped' );
			++$this->counts['findings_skipped'];
			return;
		}

		$port     = is_array( $record['port'] ?? null ) ? $record['port'] : array();
		$state    = $this->map_state( (string) ( $record['state'] ?? 'OPEN' ) );
		$exploit  = ! empty( $plugin['exploit_available'] );
		$vpr      = isset( $plugin['vpr']['score'] ) ? (float) $plugin['vpr']['score'] : null;
		$first    = (string) ( $record['first_found'] ?? '' );
		$due      = 'fixed' === $state ? '' : $this->due_at( $first, $severity, (int) $asset['team_id'] );

		$result = \VulnHub\Core\Repo::upsert_finding(
			array(
				'asset_id'    => (int) $asset['id'],
				'vuln_id'     => $vuln_id,
				'source'      => $this->id(),
				'severity'    => $severity,
				'state'       => $state,
				'port'        => (int) ( $port['port'] ?? 0 ),
				'protocol'    => strtolower( (string) ( $port['protocol'] ?? '' ) ),
				'service'     => strtolower( (string) ( $port['service'] ?? '' ) ),
				'output'      => (string) ( $record['output'] ?? '' ),
				'risk_score'  => vh_risk_score( $severity, (string) $asset['criticality'], $exploit, $vpr ),
				'first_found' => $first,
				'last_found'  => (string) ( $record['last_found'] ?? '' ),
				'last_fixed'  => (string) ( $record['last_fixed'] ?? '' ),
				'due_at'      => $due,
				'scan_uuid'   => (string) ( $record['scan']['uuid'] ?? '' ),
			)
		);

		if ( ! $result['id'] ) {
			$this->bump( 'failed' );
			++$this->counts['findings_skipped'];
			return;
		}

		++$this->counts['findings'];
		++$this->counts[ 'sev_' . $severity ];

		if ( 'fixed' === $state ) {
			++$this->counts['findings_fixed'];
		}

		if ( $result['created'] ) {
			$this->bump( 'created' );
			++$this->counts['findings_created'];
		} else {
			$this->bump( 'updated' );
		}

		if ( $result['reopened'] ) {
			++$this->counts['findings_reopened'];
			$this->log(
				sprintf(
					'REOPENED: %s on %s (plugin %s) was fixed and has been detected again.',
					vh_trim( (string) ( $plugin['name'] ?? '' ), 80 ),
					$asset['hostname'],
					(string) ( $plugin['id'] ?? '' )
				)
			);
		}
	}

	/**
	 * Upsert the vulnerability definition for a Tenable `plugin` object.
	 *
	 * @param array<string,mixed> $plugin   Plugin object.
	 * @param string              $severity Severity slug for this finding.
	 * @return int Vulnerability row id, or 0.
	 */
	private function vuln_id_for( array $plugin, string $severity ): int {
		$plugin_id = (string) ( $plugin['id'] ?? '' );

		if ( '' === $plugin_id ) {
			return 0;
		}
		if ( isset( $this->vuln_cache[ $plugin_id ] ) ) {
			return $this->vuln_cache[ $plugin_id ];
		}

		$see_also = $plugin['see_also'] ?? array();
		if ( is_string( $see_also ) ) {
			$see_also = preg_split( '/\r\n|\r|\n/', $see_also ) ?: array();
		}

		$vuln_id = \VulnHub\Core\Repo::upsert_vuln(
			array(
				'source'                 => $this->id(),
				'plugin_id'              => $plugin_id,
				'title'                  => (string) ( $plugin['name'] ?? '' ),
				'family'                 => (string) ( $plugin['family'] ?? '' ),
				'severity'               => $severity,
				'cve'                    => $this->strings( $plugin['cve'] ?? array() ),
				'cvss2_base'             => (float) ( $plugin['cvss_base_score'] ?? 0 ),
				'cvss3_base'             => (float) ( $plugin['cvss3_base_score'] ?? 0 ),
				'vpr_score'              => (float) ( $plugin['vpr']['score'] ?? 0 ),
				'exploit_available'      => ! empty( $plugin['exploit_available'] ),
				'description'            => (string) ( $plugin['description'] ?? '' ),
				'solution'               => (string) ( $plugin['solution'] ?? '' ),
				'see_also'               => $this->strings( $see_also ),
				'patch_publication_date' => (string) ( $plugin['patch_publication_date'] ?? '' ),
			)
		);

		if ( $vuln_id ) {
			$this->vuln_cache[ $plugin_id ] = $vuln_id;
			++$this->counts['vulns'];
		}

		return $vuln_id;
	}

	/**
	 * Map Tenable's finding state onto our lowercase lifecycle states.
	 *
	 * Tenable's API exposes OPEN, REOPENED and FIXED (the UI's "new", "active"
	 * and "resurfaced" all collapse into OPEN/REOPENED).
	 */
	private function map_state( string $state ): string {
		return match ( strtoupper( trim( $state ) ) ) {
			'FIXED'      => 'fixed',
			'REOPENED',
			'RESURFACED' => 'reopened',
			default      => 'open',
		};
	}

	/**
	 * Resolve an asset row for a vulnerability record, caching as we go.
	 *
	 * @param string $uuid     Tenable asset uuid.
	 * @param string $hostname Hostname, used only for logging.
	 * @return array{id:int,criticality:string,team_id:int,hostname:string,asset_type:string}|null
	 */
	private function asset_for( string $uuid, string $hostname ): ?array {
		global $wpdb;

		if ( '' === $uuid ) {
			return null;
		}
		if ( isset( $this->asset_cache[ $uuid ] ) ) {
			return $this->asset_cache[ $uuid ];
		}

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT id, criticality, team_id, hostname, asset_type FROM ' . vh_table( 'assets' ) . ' WHERE tenable_uuid = %s LIMIT 1',
				$uuid
			),
			ARRAY_A
		);

		if ( ! $row ) {
			$this->log(
				sprintf(
					'Skipped a finding for unknown asset %s (%s) — it was not in the asset export window.',
					$uuid,
					$hostname ?: __( 'no hostname', 'vulnhub' )
				)
			);
			return null;
		}

		$this->asset_cache[ $uuid ] = array(
			'id'          => (int) $row['id'],
			'criticality' => (string) $row['criticality'],
			'team_id'     => (int) $row['team_id'],
			'hostname'    => (string) $row['hostname'],
			'asset_type'  => (string) $row['asset_type'],
		);

		return $this->asset_cache[ $uuid ];
	}

	/**
	 * Remediation deadline: first detection plus the owning team's SLA for
	 * that severity.
	 *
	 * On a first sync nothing is owned yet — ownership mapping runs after the
	 * import — so we fall back to the platform defaults of 7 / 30 / 90 / 180
	 * days. Subsequent syncs pick up the real team SLA.
	 *
	 * @param string $first_found Tenable first_found timestamp.
	 * @param string $severity    Severity slug.
	 * @param int    $team_id     Owning team id, 0 when unowned.
	 * @return string MySQL datetime, or '' when we cannot date the finding.
	 */
	private function due_at( string $first_found, string $severity, int $team_id ): string {
		$anchor = vh_to_mysql( $first_found ) ?? vh_now();
		$start  = strtotime( $anchor . ' UTC' );

		if ( false === $start ) {
			return '';
		}

		return gmdate( 'Y-m-d H:i:s', $start + $this->sla_days( $team_id, $severity ) * DAY_IN_SECONDS );
	}

	/**
	 * SLA days for a team and severity, cached per run.
	 *
	 * @param int    $team_id  Team id, 0 for unowned.
	 * @param string $severity Severity slug.
	 */
	private function sla_days( int $team_id, string $severity ): int {
		if ( ! isset( $this->sla_cache[ $team_id ] ) ) {
			$defaults = self::DEFAULT_SLA_DAYS;
			$team     = $team_id ? \VulnHub\Core\Repo::team( $team_id ) : null;

			if ( $team ) {
				$defaults = array(
					'critical' => max( 1, (int) ( $team['sla_critical_days'] ?? $defaults['critical'] ) ),
					'high'     => max( 1, (int) ( $team['sla_high_days'] ?? $defaults['high'] ) ),
					'medium'   => max( 1, (int) ( $team['sla_medium_days'] ?? $defaults['medium'] ) ),
					'low'      => max( 1, (int) ( $team['sla_low_days'] ?? $defaults['low'] ) ),
					'info'     => max( 1, (int) ( $team['sla_low_days'] ?? $defaults['info'] ) ),
				);
			}

			$this->sla_cache[ $team_id ] = $defaults;
		}

		return (int) ( $this->sla_cache[ $team_id ][ $severity ] ?? self::DEFAULT_SLA_DAYS['medium'] );
	}

	/* =================================================================
	 * Closure verification support
	 * ============================================================== */

	/**
	 * Fetch the current Tenable state of a specific set of findings.
	 *
	 * Used by the closure-verification responder, which needs to know whether
	 * the exact (asset, plugin) pairs a ticket covered are still detected.
	 *
	 * Note: the vulnerability export filters do not accept a list of asset
	 * uuids, so the export is narrowed with `plugin_id` (which is supported)
	 * and the asset match is applied to the returned records.
	 *
	 * @param array<int,string> $asset_uuids Tenable asset uuids of interest.
	 * @param array<int,string> $plugin_ids  Tenable plugin ids of interest.
	 * @param int               $since       Unix timestamp horizon.
	 * @return array<string,array{state:string,last_found:string,last_fixed:string,scan_uuid:string}>
	 *         Keyed by "<asset uuid>|<plugin id>".
	 */
	public function current_finding_states( array $asset_uuids, array $plugin_ids, int $since ): array {
		$asset_uuids = array_values( array_unique( array_filter( array_map( 'strval', $asset_uuids ) ) ) );
		$plugin_ids  = array_values( array_unique( array_filter( array_map( 'strval', $plugin_ids ) ) ) );

		if ( ! $asset_uuids || ! $plugin_ids ) {
			return array();
		}

		$wanted = array_flip( $asset_uuids );
		$states = array();

		$collect = static function ( array $records ) use ( &$states, $wanted ): void {
			foreach ( $records as $record ) {
				$uuid   = (string) ( $record['asset']['uuid'] ?? '' );
				$plugin = (string) ( $record['plugin']['id'] ?? '' );

				if ( '' === $uuid || '' === $plugin || ! isset( $wanted[ $uuid ] ) ) {
					continue;
				}

				$key      = $uuid . '|' . $plugin;
				$existing = $states[ $key ] ?? null;
				$found    = (string) ( $record['last_found'] ?? '' );

				// Keep the most recently observed record for the pair.
				if ( $existing && strtotime( (string) $existing['last_found'] ) >= strtotime( $found ) ) {
					continue;
				}

				$states[ $key ] = array(
					'state'      => strtoupper( (string) ( $record['state'] ?? 'OPEN' ) ),
					'last_found' => $found,
					'last_fixed' => (string) ( $record['last_fixed'] ?? '' ),
					'scan_uuid'  => (string) ( $record['scan']['uuid'] ?? '' ),
				);
			}
		};

		if ( $this->is_mock() ) {
			$by_uuid = array();

			foreach ( \VulnHub\Core\Mock::devices() as $device ) {
				$by_uuid[ (string) $device['tenable_uuid'] ] = $device;
			}

			foreach ( $asset_uuids as $uuid ) {
				if ( ! isset( $by_uuid[ $uuid ] ) ) {
					continue;
				}

				$records = VulnHub_Tenable_Mock::vuln_records_for_device( $by_uuid[ $uuid ] );
				$collect( array_values( array_filter(
					$records,
					static fn( array $record ): bool => in_array( (string) ( $record['plugin']['id'] ?? '' ), $plugin_ids, true )
				) ) );
			}

			return $states;
		}

		$this->client()->run_export(
			VulnHub_Tenable_Client::KIND_VULNS,
			array(
				'num_assets' => 50,
				'filters'    => array(
					'plugin_id' => array_map( 'intval', $plugin_ids ),
					'state'     => array( 'OPEN', 'REOPENED', 'FIXED' ),
					'since'     => $since,
				),
			),
			static function ( array $records, int $chunk_id ) use ( $collect ): void {
				unset( $chunk_id );
				$collect( $records );
			}
		);

		return $states;
	}
}

