<?php
/**
 * Portal admin section: Imports.
 *
 * Rendered inside the portal's admin shell by the `vulnhub_render_portal_section`
 * action — this screen never appears in wp-admin.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! current_user_can( 'vulnhub_manage' ) ) {
	return;
}

$vh_import_jobs       = VulnHub_Import_Jobs::recent( 20 );
$vh_import_statuses   = VulnHub_Import_Jobs::statuses();
$vh_import_cmdb_ready = VulnHub_Import_Cmdb::available();
$vh_import_active     = null;

foreach ( $vh_import_jobs as $vh_import_job ) {
	if ( in_array( (string) $vh_import_job['status'], array( VulnHub_Import_Jobs::RUNNING, VulnHub_Import_Jobs::PENDING ), true ) ) {
		$vh_import_active = VulnHub_Import_Rest::summarise( $vh_import_job );
		break;
	}
}

$vh_import_chip = static function ( string $status ): string {
	return match ( $status ) {
		VulnHub_Import_Jobs::DONE    => 'vh-chip--good',
		VulnHub_Import_Jobs::RUNNING => 'vh-chip--warn',
		VulnHub_Import_Jobs::FAILED  => 'vh-chip--bad',
		default                      => '',
	};
};
?>

<div class="vh-import" data-vh-import
	data-active="<?php echo esc_attr( $vh_import_active ? (string) wp_json_encode( $vh_import_active ) : '' ); ?>">

	<noscript>
		<p class="vh-warn-note">
			<?php esc_html_e( 'The importer slices large files in the browser before uploading them, so it needs JavaScript enabled.', 'vulnhub' ); ?>
		</p>
	</noscript>

	<?php if ( ! $vh_import_cmdb_ready ) : ?>
		<p class="vh-warn-note"><?php echo esc_html( VulnHub_Import_Cmdb::unavailable_message() ); ?></p>
	<?php endif; ?>

	<!-- ---------------------------------------------------------- upload -->
	<section class="vh-panel">
		<div class="vh-panel__head">
			<h2><?php esc_html_e( 'Import a CSV export', 'vulnhub' ); ?></h2>
			<p class="vh-sub">
				<?php
				$vh_headroom = VulnHub_Import_Storage::disk_headroom();
				$vh_ceiling  = $vh_headroom > 0
					? min( VulnHub_Import_Storage::max_bytes(), $vh_headroom )
					: VulnHub_Import_Storage::max_bytes();

				printf(
					/* translators: %s: largest file the importer accepts. */
					esc_html__( 'Files up to %s. A 500 MB Tenable or CMDB export is expected, not exceptional.', 'vulnhub' ),
					esc_html( size_format( $vh_ceiling ) )
				);
				?>
			</p>
			<p class="vh-sub vh-muted">
				<?php
				printf(
					/* translators: 1: starting slice size, 2: single-request limit. */
					esc_html__( 'The file never travels as one request: the browser slices it (starting at %1$s and adapting to your connection, never above the %2$s this server takes in one go), the slices are appended here, and the result is streamed row by row. Nothing is held in memory whole, and a dropped connection costs one slice rather than the upload.', 'vulnhub' ),
					esc_html( size_format( VulnHub_Import_Storage::chunk_size() ) ),
					esc_html( size_format( (int) wp_max_upload_size() ) )
				);
				?>
			</p>
		</div>

		<form class="vh-import__form" method="post" data-vh-import-form>
			<?php wp_nonce_field( VulnHub_Import_Rest::NONCE, 'vh_import_nonce' ); ?>

			<div class="vh-drop" data-vh-drop tabindex="0" role="button"
				aria-label="<?php esc_attr_e( 'Choose a CSV file, or drop one here', 'vulnhub' ); ?>">
				<svg viewBox="0 0 24 24" aria-hidden="true" class="vh-drop__icon">
					<path d="M12 16V4M7 9l5-5 5 5M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"
						fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>
				<p class="vh-drop__lead"><?php esc_html_e( 'Drop a CSV here, or choose a file', 'vulnhub' ); ?></p>
				<p class="vh-sub"><?php esc_html_e( '.csv, .tsv or .txt — Tenable vulnerability exports, Tenable asset exports and CMDB inventories are recognised automatically.', 'vulnhub' ); ?></p>
				<input type="file" accept=".csv,.tsv,.txt,text/csv,text/plain" data-vh-file hidden>
				<button type="button" class="vh-btn vh-btn--primary" data-vh-pick><?php esc_html_e( 'Choose file', 'vulnhub' ); ?></button>
			</div>

			<div class="vh-import__upload" data-vh-upload hidden>
				<div class="vh-meterblock">
					<div class="vh-meterblock__head">
						<span data-vh-upload-label><?php esc_html_e( 'Uploading', 'vulnhub' ); ?></span>
						<strong data-vh-upload-pct>0%</strong>
					</div>
					<div class="vh-meterblock__track">
						<span class="vh-meterblock__fill" style="width:0%" data-vh-upload-bar></span>
					</div>
					<p class="vh-meterblock__meta" data-vh-upload-meta></p>
				</div>
			</div>

			<p class="vh-warn-note" data-vh-error hidden></p>
		</form>
	</section>

	<!-- --------------------------------------------------------- mapping -->
	<section class="vh-panel" data-vh-mapping hidden>
		<div class="vh-panel__head">
			<h2><?php esc_html_e( 'Check the column mapping', 'vulnhub' ); ?></h2>
			<p class="vh-sub"><?php esc_html_e( 'Detected from the header row. Correct anything that is wrong before you start — nothing has been written yet.', 'vulnhub' ); ?></p>
		</div>

		<p class="vh-warn-note" data-vh-duplicate hidden></p>

		<div class="vh-filters">
			<label>
				<?php esc_html_e( 'File', 'vulnhub' ); ?>
				<span class="vh-mono" data-vh-file-label></span>
			</label>
			<label>
				<?php esc_html_e( 'Detected shape', 'vulnhub' ); ?>
				<select data-vh-shape></select>
			</label>
			<label>
				<?php esc_html_e( 'Estimated rows', 'vulnhub' ); ?>
				<span class="vh-mono" data-vh-estimate></span>
			</label>
			<button type="button" class="vh-btn vh-btn--sm" data-vh-redetect><?php esc_html_e( 'Auto-detect again', 'vulnhub' ); ?></button>
		</div>

		<div class="vh-warn-note" style="margin-bottom:12px">
			<strong><?php esc_html_e( 'Minimum columns to avoid duplicates', 'vulnhub' ); ?></strong>
			<p class="vh-sub" style="margin:6px 0 0">
				<?php
				esc_html_e(
					'A finding is matched on the asset plus the plugin (and port/protocol if present). To update existing findings instead of creating new ones, a vulnerability export needs at least: Plugin ID, one asset key (Asset UUID is safest; Hostname / DNS name also work), and Severity. Include Port and Protocol if your scans use them. Omitting the asset key, or spelling the hostname differently from what is stored, creates a second asset and duplicate findings.',
					'vulnhub'
				);
				?>
			</p>
			<p class="vh-sub" style="margin:6px 0 0">
				<?php
				esc_html_e(
					'To only backfill plugin output (for example, the vulnerable file path) onto findings that already exist, choose the "Tenable enrichment" shape above. That mode never creates assets or findings and never changes severity, state or risk — it writes plugin output only — so a slim export of Plugin ID, an asset key and Plugin output is safe.',
					'vulnhub'
				);
				?>
			</p>
		</div>

		<div class="vh-tablewrap">
			<table class="vh-table">
				<caption class="vh-sub"><?php esc_html_e( 'Canonical field to source column', 'vulnhub' ); ?></caption>
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'VulnHub field', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Column in your file', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'First value', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody data-vh-map-body></tbody>
			</table>
		</div>
	</section>

	<!-- --------------------------------------------------------- preview -->
	<section class="vh-panel" data-vh-preview-panel hidden>
		<div class="vh-panel__head">
			<h2><?php esc_html_e( 'Dry run: the first rows, as they will be imported', 'vulnhub' ); ?></h2>
			<p class="vh-sub"><?php esc_html_e( 'Mapped and normalised, but not written. If these look wrong, fix the mapping above.', 'vulnhub' ); ?></p>
		</div>

		<div class="vh-tablewrap">
			<table class="vh-table">
				<thead data-vh-preview-head></thead>
				<tbody data-vh-preview-body></tbody>
			</table>
		</div>

		<p class="vh-sub vh-sub--foot">
			<button type="button" class="vh-btn vh-btn--primary" data-vh-start><?php esc_html_e( 'Start import', 'vulnhub' ); ?></button>
			<button type="button" class="vh-btn vh-btn--ghost" data-vh-discard><?php esc_html_e( 'Discard', 'vulnhub' ); ?></button>
		</p>
	</section>

	<!-- -------------------------------------------------------- progress -->
	<section class="vh-panel" data-vh-progress hidden>
		<div class="vh-panel__head">
			<h2><?php esc_html_e( 'Import in progress', 'vulnhub' ); ?></h2>
			<p class="vh-sub" data-vh-progress-file></p>
		</div>

		<div class="vh-meterblock">
			<div class="vh-meterblock__head">
				<span data-vh-progress-label></span>
				<strong data-vh-progress-pct>0%</strong>
			</div>
			<div class="vh-meterblock__track">
				<span class="vh-meterblock__fill" style="width:0%" data-vh-progress-bar></span>
			</div>
			<p class="vh-meterblock__meta" data-vh-progress-meta></p>
		</div>

		<div class="vh-import__counters" data-vh-counters></div>

		<p class="vh-sub vh-sub--foot">
			<button type="button" class="vh-btn" data-vh-cancel><?php esc_html_e( 'Cancel import', 'vulnhub' ); ?></button>
		</p>

		<div class="vh-tablewrap" data-vh-failures-wrap hidden>
			<table class="vh-table">
				<caption class="vh-sub"><?php esc_html_e( 'Rows that failed (first 100)', 'vulnhub' ); ?></caption>
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Row', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Reason', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody data-vh-failures></tbody>
			</table>
		</div>
	</section>

	<!-- --------------------------------------------------------- history -->
	<section class="vh-panel">
		<div class="vh-panel__head">
			<h2><?php esc_html_e( 'Import history', 'vulnhub' ); ?></h2>
			<p class="vh-sub"><?php esc_html_e( 'Every job, with the counters it produced. A finished job can be run again by uploading the same file — its mapping is reused.', 'vulnhub' ); ?></p>
		</div>

		<?php if ( ! $vh_import_jobs ) : ?>
			<p class="vh-sub"><?php esc_html_e( 'Nothing has been imported yet.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<div class="vh-tablewrap">
				<table class="vh-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'File', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Shape', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Rows', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Assets', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Findings', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Failed', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'When', 'vulnhub' ); ?></th>
							<th scope="col" class="vh-col-act"><?php esc_html_e( 'Actions', 'vulnhub' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $vh_import_jobs as $vh_job ) : ?>
							<?php
							$vh_c      = (array) $vh_job['counters_arr'];
							$vh_status = (string) $vh_job['status'];
							$vh_map    = (array) ( $vh_job['column_map_arr']['map'] ?? array() );
							?>
							<tr>
								<td>
									<span class="vh-mono"><?php echo esc_html( (string) $vh_job['filename'] ); ?></span>
									<span class="vh-meta"><?php echo esc_html( size_format( (int) $vh_job['size_bytes'], 1 ) ); ?></span>
								</td>
								<td><?php echo esc_html( (string) ( VulnHub_Import_Schema::shapes()[ (string) $vh_job['shape'] ] ?? $vh_job['shape'] ) ); ?></td>
								<td>
									<span class="vh-chip <?php echo esc_attr( $vh_import_chip( $vh_status ) ); ?>">
										<?php echo esc_html( (string) ( $vh_import_statuses[ $vh_status ] ?? $vh_status ) ); ?>
									</span>
									<?php if ( '' !== (string) $vh_job['error'] ) : ?>
										<span class="vh-meta"><?php echo esc_html( vh_trim( (string) $vh_job['error'], 80 ) ); ?></span>
									<?php endif; ?>
								</td>
								<td class="vh-mono"><?php echo esc_html( number_format_i18n( (int) $vh_job['rows_done'] ) ); ?></td>
								<td class="vh-mono">
									<?php
									printf(
										/* translators: 1: assets created, 2: assets updated. */
										esc_html__( '%1$s new / %2$s seen', 'vulnhub' ),
										esc_html( number_format_i18n( (int) $vh_c['assets_created'] ) ),
										esc_html( number_format_i18n( (int) $vh_c['assets_updated'] ) )
									);
									?>
								</td>
								<td class="vh-mono">
									<?php
									printf(
										/* translators: 1: findings created, 2: findings updated. */
										esc_html__( '%1$s new / %2$s seen', 'vulnhub' ),
										esc_html( number_format_i18n( (int) $vh_c['findings_created'] ) ),
										esc_html( number_format_i18n( (int) $vh_c['findings_updated'] ) )
									);
									?>
								</td>
								<td class="vh-mono"><?php echo esc_html( number_format_i18n( (int) $vh_c['rows_failed'] ) ); ?></td>
								<td>
									<span title="<?php echo esc_attr( vh_date( (string) $vh_job['created_at'] ) ); ?>">
										<?php echo esc_html( vh_ago( (string) $vh_job['created_at'] ) ); ?>
									</span>
								</td>
								<td class="vh-col-act">
									<?php if ( in_array( $vh_status, array( VulnHub_Import_Jobs::RUNNING, VulnHub_Import_Jobs::PENDING ), true ) ) : ?>
										<button type="button" class="vh-btn vh-btn--sm" data-vh-watch="<?php echo esc_attr( (string) $vh_job['id'] ); ?>">
											<?php esc_html_e( 'Watch', 'vulnhub' ); ?>
										</button>
										<button type="button" class="vh-btn vh-btn--sm" data-vh-stop="<?php echo esc_attr( (string) $vh_job['id'] ); ?>">
											<?php esc_html_e( 'Cancel', 'vulnhub' ); ?>
										</button>
									<?php else : ?>
										<button type="button" class="vh-btn vh-btn--sm"
											data-vh-rerun="<?php echo esc_attr( (string) $vh_job['id'] ); ?>"
											data-vh-shape="<?php echo esc_attr( (string) $vh_job['shape'] ); ?>"
											data-vh-map="<?php echo esc_attr( (string) wp_json_encode( $vh_map ) ); ?>">
											<?php esc_html_e( 'Run again', 'vulnhub' ); ?>
										</button>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</section>
</div>

