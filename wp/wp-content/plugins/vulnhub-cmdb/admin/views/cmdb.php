<?php
/**
 * CMDB integration screen.
 *
 * Rendered by core via the `vulnhub_render_admin_page` action, inside the
 * standard `.vulnhub-wrap` shell, so it reuses core's CSS classes throughout.
 *
 * Four tabs: where the data comes from, the CSV importer with its dry run,
 * the column mapping, and the coverage report — which is the number this
 * integration exists to move.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! current_user_can( 'vulnhub_view' ) ) {
	wp_die( esc_html__( 'You do not have permission to view this screen.', 'vulnhub' ) );
}

require_once VULNHUB_CMDB_DIR . 'includes/class-vh-cmdb-admin.php';

$vh_cmdb_can_manage = current_user_can( 'vulnhub_manage' );
$vh_cmdb_settings   = vulnhub()->settings;
$vh_cmdb_connector  = vulnhub()->connectors->get( 'cmdb' );
$vh_cmdb_admin      = new VulnHub_Cmdb_Admin();

$vh_cmdb_health = $vh_cmdb_connector ? $vh_cmdb_connector->health() : array(
	'state'  => 'off',
	'label'  => __( 'Not registered', 'vulnhub' ),
	'detail' => '',
);

$vh_cmdb_source   = $vh_cmdb_connector ? $vh_cmdb_connector->source() : 'csv';
$vh_cmdb_last     = (array) $vh_cmdb_settings->get( 'cmdb', 'last_import', array() );
$vh_cmdb_when     = (string) $vh_cmdb_settings->get( 'cmdb', 'last_import_at', '' );
$vh_cmdb_mode     = (string) $vh_cmdb_settings->get( 'cmdb', 'last_import_mode', '' );
$vh_cmdb_notes    = (array) $vh_cmdb_settings->get( 'cmdb', 'last_notes', array() );
$vh_cmdb_csv_meta = (array) $vh_cmdb_settings->get( 'cmdb', 'csv_meta', array() );
$vh_cmdb_coverage = VulnHub_Cmdb_Connector::coverage();
$vh_cmdb_fields   = VulnHub_Cmdb_Schema::fields();
$vh_cmdb_map      = $vh_cmdb_connector ? $vh_cmdb_connector->column_map() : array();

$vh_cmdb_source_labels = array(
	'servicenow' => __( 'ServiceNow Table API', 'vulnhub' ),
	'assets'     => __( 'Jira Assets (AQL)', 'vulnhub' ),
	'confluence' => __( 'Confluence page', 'vulnhub' ),
	'csv'        => __( 'CSV upload', 'vulnhub' ),
);

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only navigation.
$vh_cmdb_tab   = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'status';
$vh_cmdb_token = isset( $_GET['preview'] ) ? sanitize_key( wp_unslash( $_GET['preview'] ) ) : '';
$vh_cmdb_gap   = isset( $_GET['gap'] ) ? sanitize_key( wp_unslash( $_GET['gap'] ) ) : 'any';
// phpcs:enable WordPress.Security.NonceVerification.Recommended

$vh_cmdb_tabs = array(
	'status'   => __( 'Source status', 'vulnhub' ),
	'csv'      => __( 'CSV import', 'vulnhub' ),
	'assets'   => __( 'Jira Assets', 'vulnhub' ),
	'mapping'  => __( 'Column mapping', 'vulnhub' ),
	'coverage' => __( 'Coverage', 'vulnhub' ),
);

if ( ! isset( $vh_cmdb_tabs[ $vh_cmdb_tab ] ) ) {
	$vh_cmdb_tab = 'status';
}

$vh_cmdb_notice  = VulnHub_Cmdb_Admin::take_notice();
$vh_cmdb_percent = static fn( int $part, int $whole ): string => $whole > 0 ? number_format_i18n( round( ( $part / $whole ) * 100 ) ) . '%' : '—';
?>

<?php if ( $vh_cmdb_notice ) : ?>
	<div class="notice notice-<?php echo esc_attr( 'error' === $vh_cmdb_notice['type'] ? 'error' : 'success' ); ?> is-dismissible">
		<p><?php echo esc_html( $vh_cmdb_notice['message'] ); ?></p>
	</div>
<?php endif; ?>

<nav class="vh-tabs">
	<?php foreach ( $vh_cmdb_tabs as $vh_cmdb_key => $vh_cmdb_label ) : ?>
		<a class="<?php echo $vh_cmdb_tab === $vh_cmdb_key ? 'is-active' : ''; ?>"
			href="<?php echo esc_url( vh_admin_url( 'vulnhub-cmdb', array( 'tab' => $vh_cmdb_key ) ) ); ?>">
			<?php echo esc_html( $vh_cmdb_label ); ?>
		</a>
	<?php endforeach; ?>
</nav>

<?php if ( 'status' === $vh_cmdb_tab ) : ?>

	<div class="vh-grid vh-grid--4">
		<div class="vh-card">
			<h2><?php esc_html_e( 'Active source', 'vulnhub' ); ?></h2>
			<p class="vh-card__value" style="font-size:20px">
				<?php echo esc_html( (string) ( $vh_cmdb_source_labels[ $vh_cmdb_source ] ?? $vh_cmdb_source ) ); ?>
			</p>
			<p class="vh-card__meta">
				<?php
				echo $vh_cmdb_connector && $vh_cmdb_connector->is_mock()
					? esc_html__( 'running against the shared sample fleet', 'vulnhub' )
					: esc_html__( 'running against live data', 'vulnhub' );
				?>
			</p>
		</div>

		<div class="vh-card <?php echo esc_attr( in_array( (string) $vh_cmdb_health['state'], array( 'ok', 'mock' ), true ) ? 'vh-card--ok' : 'vh-card--warn' ); ?>">
			<h2><?php esc_html_e( 'Connector health', 'vulnhub' ); ?></h2>
			<p class="vh-card__value" style="font-size:20px"><?php echo esc_html( (string) $vh_cmdb_health['label'] ); ?></p>
			<p class="vh-card__meta"><?php echo esc_html( vh_trim( (string) $vh_cmdb_health['detail'], 120 ) ); ?></p>
		</div>

		<div class="vh-card">
			<h2><?php esc_html_e( 'CIs read last run', 'vulnhub' ); ?></h2>
			<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) ( $vh_cmdb_last['records'] ?? 0 ) ) ); ?></p>
			<p class="vh-card__meta">
				<?php
				if ( '' !== $vh_cmdb_when ) {
					printf(
						/* translators: 1: relative time, 2: mock or live. */
						esc_html__( '%1$s, %2$s data', 'vulnhub' ),
						esc_html( vh_ago( $vh_cmdb_when ) ),
						esc_html( $vh_cmdb_mode ?: 'live' )
					);
				} else {
					esc_html_e( 'never run', 'vulnhub' );
				}
				?>
			</p>
		</div>

		<div class="vh-card">
			<h2><?php esc_html_e( 'Fully described assets', 'vulnhub' ); ?></h2>
			<p class="vh-card__value"><?php echo esc_html( $vh_cmdb_percent( $vh_cmdb_coverage['complete'], $vh_cmdb_coverage['total'] ) ); ?></p>
			<p class="vh-card__meta">
				<?php
				printf(
					/* translators: 1: assets with all three attributes, 2: total assets. */
					esc_html__( '%1$s of %2$s have a service, a team and a site', 'vulnhub' ),
					esc_html( number_format_i18n( $vh_cmdb_coverage['complete'] ) ),
					esc_html( number_format_i18n( $vh_cmdb_coverage['total'] ) )
				);
				?>
			</p>
		</div>
	</div>

	<div class="vh-grid vh-grid--2">
		<div class="vh-card">
			<h2><?php esc_html_e( 'What this connector supplies', 'vulnhub' ); ?></h2>
			<p style="margin:0 0 10px;line-height:1.6">
				<?php esc_html_e( 'A server, a switch or a cloud resource has no Intune primary user, so nothing else in the platform can say who owns it. This connector fills that gap: it resolves the owning team, the business service, the environment and the site, and it merges those on to assets Tenable and Intune already imported rather than creating a second copy of them.', 'vulnhub' ); ?>
			</p>
			<p style="margin:0;line-height:1.6" class="vh-muted">
				<?php esc_html_e( 'Assets are matched on CI identifier, then serial number, then hostname. Ownership answers are also written as tags, so the rules on the Ownership screen can use, override or ignore them.', 'vulnhub' ); ?>
			</p>
			<p style="margin:14px 0 0">
				<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations', array( 'connector' => 'cmdb' ) ) ); ?>">
					<?php esc_html_e( 'Configure credentials and schedule', 'vulnhub' ); ?>
				</a>
			</p>
		</div>

		<div class="vh-card">
			<h2><?php esc_html_e( 'Last run', 'vulnhub' ); ?></h2>

			<?php if ( ! $vh_cmdb_last ) : ?>
				<div class="vh-empty">
					<p><?php esc_html_e( 'Nothing imported yet. Mock mode needs no credentials — enable the connector and run a sync.', 'vulnhub' ); ?></p>
					<a class="button button-primary" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations', array( 'connector' => 'cmdb' ) ) ); ?>">
						<?php esc_html_e( 'Go to Integrations', 'vulnhub' ); ?>
					</a>
				</div>
			<?php else : ?>
				<div class="vh-table-wrap">
					<table class="wp-list-table widefat striped">
						<tbody>
							<?php
							$vh_cmdb_rows = array(
								'records'        => __( 'Configuration items read', 'vulnhub' ),
								'created'        => __( 'Assets created', 'vulnhub' ),
								'updated'        => __( 'Assets updated', 'vulnhub' ),
								'unchanged'      => __( 'Already current', 'vulnhub' ),
								'skipped'        => __( 'Skipped (no matching asset)', 'vulnhub' ),
								'invalid'        => __( 'Rejected rows', 'vulnhub' ),
								'teams_set'      => __( 'Assets given an owning team', 'vulnhub' ),
								'teams_made'     => __( 'Teams created', 'vulnhub' ),
								'locations_set'  => __( 'Assets given a site', 'vulnhub' ),
								'locations_made' => __( 'Locations created', 'vulnhub' ),
								'owners_set'     => __( 'Assets given a named owner', 'vulnhub' ),
								'services_set'   => __( 'Assets given a business service', 'vulnhub' ),
								'type_conflicts' => __( 'Asset-type disagreements kept as enrolled', 'vulnhub' ),
								'team_conflicts' => __( 'Team disagreements left to the ownership rules', 'vulnhub' ),
							);
							foreach ( $vh_cmdb_rows as $vh_cmdb_key => $vh_cmdb_label ) :
								?>
								<tr>
									<td><?php echo esc_html( $vh_cmdb_label ); ?></td>
									<td class="vh-nowrap"><strong><?php echo esc_html( number_format_i18n( (int) ( $vh_cmdb_last[ $vh_cmdb_key ] ?? 0 ) ) ); ?></strong></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</div>
			<?php endif; ?>
		</div>
	</div>

	<?php if ( $vh_cmdb_notes ) : ?>
		<div class="vh-card">
			<h2><?php esc_html_e( 'Things the last run could not resolve', 'vulnhub' ); ?></h2>
			<div class="vh-log">
				<?php foreach ( $vh_cmdb_notes as $vh_cmdb_note ) : ?>
					<div><?php echo esc_html( (string) $vh_cmdb_note ); ?></div>
				<?php endforeach; ?>
			</div>
		</div>
	<?php endif; ?>

<?php elseif ( 'csv' === $vh_cmdb_tab || 'assets' === $vh_cmdb_tab ) : ?>

	<?php
	/*
	 * Both importers share this block. A staged preview is a staged preview
	 * whatever produced it, and the point of flattening Assets objects into
	 * rows was precisely so that the mapping form, the dry run and the problem
	 * list would not have to be written twice.
	 */
	$vh_cmdb_staged = $vh_cmdb_admin->staged( $vh_cmdb_token );
	$vh_cmdb_rows   = $vh_cmdb_connector ? $vh_cmdb_connector->stored_rows() : array();
	?>

	<?php if ( $vh_cmdb_staged && $vh_cmdb_connector && (string) ( $vh_cmdb_staged['tab'] ?? 'csv' ) === $vh_cmdb_tab ) : ?>

		<?php
		$vh_cmdb_records = $vh_cmdb_admin->records_from( $vh_cmdb_staged );
		$vh_cmdb_dry     = $vh_cmdb_connector->preview( $vh_cmdb_records );
		$vh_cmdb_headers = (array) $vh_cmdb_staged['headers'];
		$vh_cmdb_active  = (array) $vh_cmdb_staged['map'];
		$vh_cmdb_counts  = $vh_cmdb_dry['counts'];
		?>

		<div class="vh-grid vh-grid--4">
			<div class="vh-card">
				<h2><?php echo esc_html( 'assets' === $vh_cmdb_tab ? __( 'Objects read', 'vulnhub' ) : __( 'Rows parsed', 'vulnhub' ) ); ?></h2>
				<p class="vh-card__value"><?php echo esc_html( number_format_i18n( count( $vh_cmdb_records ) ) ); ?></p>
				<p class="vh-card__meta"><?php echo esc_html( vh_trim( (string) $vh_cmdb_staged['file'], 40 ) ); ?></p>
			</div>
			<div class="vh-card vh-card--ok">
				<h2><?php esc_html_e( 'Would create', 'vulnhub' ); ?></h2>
				<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_cmdb_counts['created'] ) ); ?></p>
				<p class="vh-card__meta"><?php esc_html_e( 'assets not already in the inventory', 'vulnhub' ); ?></p>
			</div>
			<div class="vh-card">
				<h2><?php esc_html_e( 'Would update', 'vulnhub' ); ?></h2>
				<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_cmdb_counts['updated'] ) ); ?></p>
				<p class="vh-card__meta">
					<?php
					printf(
						/* translators: %s: number of unchanged rows. */
						esc_html__( '%s already current', 'vulnhub' ),
						esc_html( number_format_i18n( (int) $vh_cmdb_counts['unchanged'] ) )
					);
					?>
				</p>
			</div>
			<div class="vh-card <?php echo (int) $vh_cmdb_counts['invalid'] > 0 ? 'vh-card--warn' : ''; ?>">
				<h2><?php esc_html_e( 'Rejected', 'vulnhub' ); ?></h2>
				<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_cmdb_counts['invalid'] + (int) $vh_cmdb_counts['skipped'] ) ); ?></p>
				<p class="vh-card__meta"><?php esc_html_e( 'unusable or skipped rows', 'vulnhub' ); ?></p>
			</div>
		</div>

		<div class="vh-card">
			<h2>
				<?php
				echo esc_html(
					'assets' === $vh_cmdb_tab
						? __( 'Attribute mapping for this workspace', 'vulnhub' )
						: __( 'Column mapping for this file', 'vulnhub' )
				);
				?>
			</h2>
			<p class="vh-muted" style="margin:0 0 12px">
				<?php
				echo esc_html(
					'assets' === $vh_cmdb_tab
						? __( 'Detected from the attribute names this workspace actually returned. Correct anything that is wrong and the preview below updates; nothing is written until you press Import.', 'vulnhub' )
						: __( 'Detected from the headings. Correct anything that is wrong and the preview below updates; nothing is written until you press Import.', 'vulnhub' )
				);
				?>
			</p>

			<?php if ( $vh_cmdb_can_manage ) : ?>
				<form class="vh-form" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'vulnhub_cmdb_remap' ); ?>
					<input type="hidden" name="action" value="vulnhub_cmdb_remap">
					<input type="hidden" name="vh_cmdb_token" value="<?php echo esc_attr( $vh_cmdb_token ); ?>">

					<div class="vh-grid vh-grid--3">
						<?php foreach ( $vh_cmdb_fields as $vh_cmdb_field => $vh_cmdb_label ) : ?>
							<p>
								<label for="vh-cmdb-map-<?php echo esc_attr( $vh_cmdb_field ); ?>">
									<strong><?php echo esc_html( $vh_cmdb_label ); ?></strong>
									<?php if ( in_array( $vh_cmdb_field, VulnHub_Cmdb_Schema::required_fields(), true ) ) : ?>
										<span class="vh-pill vh-sev-high"><?php esc_html_e( 'required', 'vulnhub' ); ?></span>
									<?php endif; ?>
								</label>
								<select id="vh-cmdb-map-<?php echo esc_attr( $vh_cmdb_field ); ?>" name="vh_cmdb_map[<?php echo esc_attr( $vh_cmdb_field ); ?>]">
									<option value="">
										<?php
										echo esc_html(
											'assets' === $vh_cmdb_tab
												? __( '— not in this workspace —', 'vulnhub' )
												: __( '— not in this file —', 'vulnhub' )
										);
										?>
									</option>
									<?php foreach ( $vh_cmdb_headers as $vh_cmdb_header ) : ?>
										<option value="<?php echo esc_attr( (string) $vh_cmdb_header ); ?>"
											<?php selected( (string) ( $vh_cmdb_active[ $vh_cmdb_field ] ?? '' ), (string) $vh_cmdb_header ); ?>>
											<?php echo esc_html( (string) $vh_cmdb_header ); ?>
										</option>
									<?php endforeach; ?>
								</select>
							</p>
						<?php endforeach; ?>
					</div>

					<p>
						<button type="submit" class="button"><?php esc_html_e( 'Update preview', 'vulnhub' ); ?></button>
						<button type="submit" class="button" name="vh_cmdb_save_mapping" value="1">
							<?php esc_html_e( 'Update and save as default', 'vulnhub' ); ?>
						</button>
					</p>
				</form>
			<?php endif; ?>
		</div>

		<?php if ( ! empty( $vh_cmdb_staged['errors'] ) || (int) $vh_cmdb_counts['invalid'] > 0 ) : ?>
			<div class="vh-card vh-card--warn">
				<h2><?php esc_html_e( 'Problem rows', 'vulnhub' ); ?></h2>
				<div class="vh-table-wrap">
					<table class="wp-list-table widefat striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Line', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Hostname', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Problem', 'vulnhub' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( (array) $vh_cmdb_staged['errors'] as $vh_cmdb_error ) : ?>
								<tr>
									<td class="vh-mono"><?php echo esc_html( (string) $vh_cmdb_error['line'] ); ?></td>
									<td>—</td>
									<td><?php echo esc_html( (string) $vh_cmdb_error['message'] ); ?></td>
								</tr>
							<?php endforeach; ?>
							<?php
							foreach ( $vh_cmdb_dry['outcomes'] as $vh_cmdb_outcome ) :
								if ( ! in_array( (string) $vh_cmdb_outcome['action'], array( 'invalid', 'skipped' ), true ) ) {
									continue;
								}
								$vh_cmdb_index = (int) $vh_cmdb_outcome['row'] - 1;
								$vh_cmdb_line  = (string) ( $vh_cmdb_records[ $vh_cmdb_index ]['source_line'] ?? '' );
								?>
								<tr>
									<td class="vh-mono"><?php echo esc_html( '' !== $vh_cmdb_line ? $vh_cmdb_line : (string) $vh_cmdb_outcome['row'] ); ?></td>
									<td class="vh-mono"><?php echo esc_html( (string) $vh_cmdb_outcome['hostname'] ?: '—' ); ?></td>
									<td><?php echo esc_html( (string) $vh_cmdb_outcome['detail'] ); ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</div>
			</div>
		<?php endif; ?>

		<div class="vh-card">
			<h2>
				<?php
				echo esc_html(
					'assets' === $vh_cmdb_tab
						? __( 'Dry run — what importing these objects would do', 'vulnhub' )
						: __( 'Dry run — what importing this file would do', 'vulnhub' )
				);
				?>
			</h2>
			<div class="vh-table-wrap">
				<table class="wp-list-table widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Hostname', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Action', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Team', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Business service', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Site', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Changes', 'vulnhub' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php
						$vh_cmdb_shown = 0;
						foreach ( $vh_cmdb_dry['outcomes'] as $vh_cmdb_outcome ) :
							if ( $vh_cmdb_shown >= 60 ) {
								break;
							}
							++$vh_cmdb_shown;
							$vh_cmdb_record = $vh_cmdb_records[ (int) $vh_cmdb_outcome['row'] - 1 ] ?? array();
							$vh_cmdb_state  = match ( (string) $vh_cmdb_outcome['action'] ) {
								'create'   => 'vh-state vh-state--open',
								'update'   => 'vh-state vh-state--pending',
								'invalid'  => 'vh-state vh-state--rejected',
								'skipped'  => 'vh-state vh-state--expired',
								default    => 'vh-state vh-state--done',
							};
							?>
							<tr>
								<td class="vh-mono"><?php echo esc_html( (string) $vh_cmdb_outcome['hostname'] ?: '—' ); ?></td>
								<td><span class="<?php echo esc_attr( $vh_cmdb_state ); ?>"><?php echo esc_html( (string) $vh_cmdb_outcome['action'] ); ?></span></td>
								<td><?php echo esc_html( (string) ( $vh_cmdb_record['team'] ?? '' ) ?: '—' ); ?></td>
								<td><?php echo esc_html( (string) ( $vh_cmdb_record['business_service'] ?? '' ) ?: '—' ); ?></td>
								<td><?php echo esc_html( (string) ( $vh_cmdb_record['location'] ?? '' ) ?: '—' ); ?></td>
								<td class="vh-muted">
									<?php
									$vh_cmdb_changes = (array) $vh_cmdb_outcome['changes'];
									if ( ! $vh_cmdb_changes ) {
										echo esc_html( (string) $vh_cmdb_outcome['detail'] ?: '—' );
									} else {
										$vh_cmdb_bits = array();
										foreach ( $vh_cmdb_changes as $vh_cmdb_column => $vh_cmdb_change ) {
											$vh_cmdb_bits[] = sprintf(
												'%s: %s → %s',
												$vh_cmdb_column,
												'' === $vh_cmdb_change['from'] ? '∅' : vh_trim( $vh_cmdb_change['from'], 24 ),
												'' === $vh_cmdb_change['to'] ? '∅' : vh_trim( $vh_cmdb_change['to'], 24 )
											);
										}
										echo esc_html( vh_trim( implode( ', ', $vh_cmdb_bits ), 160 ) );
									}
									?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>

			<?php if ( count( $vh_cmdb_dry['outcomes'] ) > 60 ) : ?>
				<p class="vh-muted">
					<?php
					printf(
						/* translators: %s: number of additional rows. */
						esc_html__( 'and %s more row(s) not shown.', 'vulnhub' ),
						esc_html( number_format_i18n( count( $vh_cmdb_dry['outcomes'] ) - 60 ) )
					);
					?>
				</p>
			<?php endif; ?>

			<?php if ( $vh_cmdb_can_manage ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:12px">
					<?php wp_nonce_field( 'vulnhub_cmdb_import' ); ?>
					<input type="hidden" name="action" value="vulnhub_cmdb_import">
					<input type="hidden" name="vh_cmdb_token" value="<?php echo esc_attr( $vh_cmdb_token ); ?>">
					<button type="submit" class="button button-primary">
						<?php
						echo esc_html(
							'assets' === $vh_cmdb_tab
								? __( 'Import these objects', 'vulnhub' )
								: __( 'Import these rows', 'vulnhub' )
						);
						?>
					</button>
					<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-cmdb', array( 'tab' => $vh_cmdb_tab ) ) ); ?>">
						<?php esc_html_e( 'Cancel', 'vulnhub' ); ?>
					</a>
				</form>
			<?php endif; ?>
		</div>

	<?php elseif ( 'assets' === $vh_cmdb_tab ) : ?>

		<?php
		$vh_cmdb_as_ready = $vh_cmdb_connector && 'assets' === $vh_cmdb_source && $vh_cmdb_connector->is_configured();
		$vh_cmdb_as_aql   = $vh_cmdb_connector ? $vh_cmdb_connector->assets_aql() : '';
		$vh_cmdb_as_map   = $vh_cmdb_connector ? $vh_cmdb_connector->assets_map() : array();
		?>

		<div class="vh-grid vh-grid--2">
			<div class="vh-card">
				<h2><?php esc_html_e( 'Read from Jira Assets', 'vulnhub' ); ?></h2>
				<p style="margin:0 0 10px;line-height:1.6">
					<?php esc_html_e( 'Runs one AQL object search against the configured schema and pages through every match, 50 objects at a time. Each object is flattened to its attribute names and then goes through exactly the same mapping, normalisation and identity matching a CSV import does — so a server that Tenable already knows about is enriched, not duplicated.', 'vulnhub' ); ?>
				</p>
				<p class="vh-muted" style="margin:0 0 12px;line-height:1.6">
					<?php esc_html_e( 'Read only. The token carries the five Assets read scopes and nothing in this connector issues a write of any kind.', 'vulnhub' ); ?>
				</p>

				<div class="vh-table-wrap">
					<table class="wp-list-table widefat striped">
						<tbody>
							<tr>
								<td><?php esc_html_e( 'Active source', 'vulnhub' ); ?></td>
								<td><?php echo esc_html( (string) ( $vh_cmdb_source_labels[ $vh_cmdb_source ] ?? $vh_cmdb_source ) ); ?></td>
							</tr>
							<tr>
								<td><?php esc_html_e( 'Credentials', 'vulnhub' ); ?></td>
								<td>
									<?php
									echo $vh_cmdb_as_ready
										? esc_html__( 'complete', 'vulnhub' )
										: esc_html__( 'incomplete — set them on the Integrations screen', 'vulnhub' );
									?>
								</td>
							</tr>
							<tr>
								<td><?php esc_html_e( 'AQL', 'vulnhub' ); ?></td>
								<td class="vh-mono"><?php echo esc_html( $vh_cmdb_as_aql ); ?></td>
							</tr>
							<tr>
								<td><?php esc_html_e( 'Saved attribute mapping', 'vulnhub' ); ?></td>
								<td>
									<?php
									echo $vh_cmdb_as_map
										? esc_html(
											sprintf(
												/* translators: %d: number of mapped fields. */
												_n( '%d field pinned by hand', '%d fields pinned by hand', count( $vh_cmdb_as_map ), 'vulnhub' ),
												count( $vh_cmdb_as_map )
											)
										)
										: esc_html__( 'none — detected from the attribute names each run', 'vulnhub' );
									?>
								</td>
							</tr>
						</tbody>
					</table>
				</div>

				<?php if ( $vh_cmdb_can_manage ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:14px">
						<?php wp_nonce_field( 'vulnhub_cmdb_assets_preview' ); ?>
						<input type="hidden" name="action" value="vulnhub_cmdb_assets_preview">
						<button type="submit" class="button button-primary" <?php disabled( ! $vh_cmdb_as_ready && ! ( $vh_cmdb_connector && $vh_cmdb_connector->is_mock() ) ); ?>>
							<?php esc_html_e( 'Fetch and preview', 'vulnhub' ); ?>
						</button>
						<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations', array( 'connector' => 'cmdb' ) ) ); ?>">
							<?php esc_html_e( 'Credentials and schedule', 'vulnhub' ); ?>
						</a>
					</form>
				<?php else : ?>
					<p class="vh-muted"><?php esc_html_e( 'You need the manage capability to run an import.', 'vulnhub' ); ?></p>
				<?php endif; ?>
			</div>

			<div class="vh-card">
				<h2><?php esc_html_e( 'What to expect the first time', 'vulnhub' ); ?></h2>
				<p style="margin:0 0 10px;line-height:1.6">
					<?php esc_html_e( 'Attribute names belong to whoever built the workspace, so the first fetch is as much a discovery step as an import. The preview lists every attribute name it saw and which VulnHub field it bound each one to; correct anything that is wrong, save it as the default, and scheduled syncs will use the corrected mapping from then on.', 'vulnhub' ); ?>
				</p>
				<p class="vh-muted" style="margin:0;line-height:1.6">
					<?php esc_html_e( 'A 401 with an otherwise correct token almost always means the token is missing read:cmdb-attribute:jira. This connector never drops the attribute request to work around it: an import of a thousand objects with nothing on them but a name would look like a success and leave the inventory worse than before.', 'vulnhub' ); ?>
				</p>
			</div>
		</div>

	<?php else : ?>

		<div class="vh-grid vh-grid--2">
			<div class="vh-card">
				<h2><?php esc_html_e( 'Upload a CSV', 'vulnhub' ); ?></h2>
				<p style="margin:0 0 10px;line-height:1.6">
					<?php esc_html_e( 'The first non-empty line must name the columns. Comma, semicolon, tab and pipe separators are all detected, as is the byte-order mark Excel writes. Up to 2 MB and 5000 rows.', 'vulnhub' ); ?>
				</p>
				<p class="vh-muted" style="margin:0 0 12px;line-height:1.6">
					<?php esc_html_e( 'The file is parsed in place and never stored on this server: only the parsed rows are kept, and only so a scheduled sync can replay them.', 'vulnhub' ); ?>
				</p>

				<?php if ( $vh_cmdb_can_manage ) : ?>
					<form class="vh-form" method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<?php wp_nonce_field( 'vulnhub_cmdb_upload' ); ?>
						<input type="hidden" name="action" value="vulnhub_cmdb_upload">
						<input type="hidden" name="MAX_FILE_SIZE" value="<?php echo esc_attr( (string) VulnHub_Cmdb_Csv::MAX_BYTES ); ?>">
						<p>
							<label for="vh-cmdb-file"><strong><?php esc_html_e( 'CSV file', 'vulnhub' ); ?></strong></label>
							<input type="file" id="vh-cmdb-file" name="vh_cmdb_file" accept=".csv,.tsv,.txt,text/csv,text/plain" required>
						</p>
						<p>
							<button type="submit" class="button button-primary"><?php esc_html_e( 'Upload and preview', 'vulnhub' ); ?></button>
						</p>
					</form>
				<?php else : ?>
					<p class="vh-muted"><?php esc_html_e( 'You need the manage capability to import a CSV.', 'vulnhub' ); ?></p>
				<?php endif; ?>
			</div>

			<div class="vh-card">
				<h2><?php esc_html_e( 'Staged rows', 'vulnhub' ); ?></h2>

				<?php if ( ! $vh_cmdb_rows ) : ?>
					<div class="vh-empty">
						<p><?php esc_html_e( 'Nothing staged. A sample file describing the servers and network devices in the demonstration fleet ships with the plugin, at data/sample-cmdb.csv — upload it to see the whole path end to end.', 'vulnhub' ); ?></p>
					</div>
				<?php else : ?>
					<p class="vh-card__value"><?php echo esc_html( number_format_i18n( count( $vh_cmdb_rows ) ) ); ?></p>
					<p class="vh-card__meta">
						<?php
						printf(
							/* translators: 1: file name, 2: relative time. */
							esc_html__( 'from %1$s, %2$s', 'vulnhub' ),
							esc_html( (string) ( $vh_cmdb_csv_meta['file'] ?? __( 'an uploaded file', 'vulnhub' ) ) ),
							esc_html( vh_ago( (string) ( $vh_cmdb_csv_meta['at'] ?? '' ) ) )
						);
						?>
					</p>
					<p class="vh-muted" style="line-height:1.6">
						<?php esc_html_e( 'These rows are replayed whenever the connector syncs on its schedule, so the CSV keeps working without another upload.', 'vulnhub' ); ?>
					</p>

					<?php if ( $vh_cmdb_can_manage ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<?php wp_nonce_field( 'vulnhub_cmdb_discard' ); ?>
							<input type="hidden" name="action" value="vulnhub_cmdb_discard">
							<button type="submit" class="button"><?php esc_html_e( 'Discard staged rows', 'vulnhub' ); ?></button>
						</form>
					<?php endif; ?>
				<?php endif; ?>
			</div>
		</div>

	<?php endif; ?>

<?php elseif ( 'mapping' === $vh_cmdb_tab ) : ?>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Default column mapping', 'vulnhub' ); ?></h2>
		<p style="margin:0 0 10px;line-height:1.6;max-width:840px">
			<?php esc_html_e( 'Applied to Confluence tables and to CSV uploads whose headings match. Leave a field blank to let the importer detect it from the headings, which works for most sheets — this screen is for the ones where it does not, such as a column called "L2 Queue" that is really the support group.', 'vulnhub' ); ?>
		</p>
		<p class="vh-muted" style="margin:0 0 16px;line-height:1.6;max-width:840px">
			<?php esc_html_e( 'Enter the heading exactly as it appears in the source, including capitals and spaces.', 'vulnhub' ); ?>
		</p>
		<p class="vh-muted" style="margin:0 0 16px;line-height:1.6;max-width:840px">
			<?php esc_html_e( 'Jira Assets keeps its own mapping, because its columns are attribute names rather than spreadsheet headings and the two vocabularies would overwrite each other. Set that one from the preview on the Jira Assets tab.', 'vulnhub' ); ?>
		</p>

		<?php if ( $vh_cmdb_can_manage ) : ?>
			<form class="vh-form" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'vulnhub_cmdb_mapping' ); ?>
				<input type="hidden" name="action" value="vulnhub_cmdb_mapping">

				<div class="vh-table-wrap">
					<table class="wp-list-table widefat striped">
						<thead>
							<tr>
								<th style="width:24%"><?php esc_html_e( 'VulnHub field', 'vulnhub' ); ?></th>
								<th style="width:28%"><?php esc_html_e( 'Source column heading', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Detected automatically from', 'vulnhub' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $vh_cmdb_fields as $vh_cmdb_field => $vh_cmdb_label ) : ?>
								<tr>
									<td>
										<label for="vh-cmdb-default-<?php echo esc_attr( $vh_cmdb_field ); ?>">
											<strong><?php echo esc_html( $vh_cmdb_label ); ?></strong>
										</label>
										<?php if ( in_array( $vh_cmdb_field, VulnHub_Cmdb_Schema::required_fields(), true ) ) : ?>
											<br><span class="vh-pill vh-sev-high"><?php esc_html_e( 'required', 'vulnhub' ); ?></span>
										<?php endif; ?>
									</td>
									<td>
										<input type="text"
											id="vh-cmdb-default-<?php echo esc_attr( $vh_cmdb_field ); ?>"
											name="vh_cmdb_map[<?php echo esc_attr( $vh_cmdb_field ); ?>]"
											class="regular-text"
											value="<?php echo esc_attr( (string) ( $vh_cmdb_map[ $vh_cmdb_field ] ?? '' ) ); ?>">
									</td>
									<td class="vh-muted vh-mono">
										<?php echo esc_html( vh_trim( implode( ', ', VulnHub_Cmdb_Schema::aliases()[ $vh_cmdb_field ] ?? array() ), 140 ) ); ?>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</div>

				<p style="margin-top:14px">
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Save mapping', 'vulnhub' ); ?></button>
				</p>
			</form>
		<?php else : ?>
			<p class="vh-muted"><?php esc_html_e( 'You need the manage capability to change the mapping.', 'vulnhub' ); ?></p>
		<?php endif; ?>
	</div>

<?php else : ?>

	<?php
	$vh_cmdb_gaps = VulnHub_Cmdb_Connector::gaps( $vh_cmdb_gap, 200 );
	$vh_cmdb_teams = array();
	foreach ( \VulnHub\Core\Repo::teams() as $vh_cmdb_team ) {
		$vh_cmdb_teams[ (int) $vh_cmdb_team['id'] ] = (string) $vh_cmdb_team['name'];
	}
	$vh_cmdb_locations = array();
	foreach ( \VulnHub\Core\Repo::locations() as $vh_cmdb_location ) {
		$vh_cmdb_locations[ (int) $vh_cmdb_location['id'] ] = (string) $vh_cmdb_location['name'];
	}
	$vh_cmdb_gap_labels = array(
		'any'      => __( 'Missing anything', 'vulnhub' ),
		'team'     => __( 'No owning team', 'vulnhub' ),
		'service'  => __( 'No business service', 'vulnhub' ),
		'location' => __( 'No site', 'vulnhub' ),
	);
	?>

	<div class="vh-grid vh-grid--4">
		<div class="vh-card">
			<h2><?php esc_html_e( 'Assets', 'vulnhub' ); ?></h2>
			<p class="vh-card__value"><?php echo esc_html( number_format_i18n( $vh_cmdb_coverage['total'] ) ); ?></p>
			<p class="vh-card__meta"><?php esc_html_e( 'in the inventory', 'vulnhub' ); ?></p>
		</div>
		<div class="vh-card <?php echo esc_attr( $vh_cmdb_coverage['team'] < $vh_cmdb_coverage['total'] ? 'vh-card--warn' : 'vh-card--ok' ); ?>">
			<h2><?php esc_html_e( 'With an owning team', 'vulnhub' ); ?></h2>
			<p class="vh-card__value"><?php echo esc_html( $vh_cmdb_percent( $vh_cmdb_coverage['team'], $vh_cmdb_coverage['total'] ) ); ?></p>
			<p class="vh-card__meta"><?php echo esc_html( number_format_i18n( $vh_cmdb_coverage['team'] ) ); ?></p>
		</div>
		<div class="vh-card <?php echo esc_attr( $vh_cmdb_coverage['service'] < $vh_cmdb_coverage['total'] ? 'vh-card--warn' : 'vh-card--ok' ); ?>">
			<h2><?php esc_html_e( 'With a business service', 'vulnhub' ); ?></h2>
			<p class="vh-card__value"><?php echo esc_html( $vh_cmdb_percent( $vh_cmdb_coverage['service'], $vh_cmdb_coverage['total'] ) ); ?></p>
			<p class="vh-card__meta"><?php echo esc_html( number_format_i18n( $vh_cmdb_coverage['service'] ) ); ?></p>
		</div>
		<div class="vh-card <?php echo esc_attr( $vh_cmdb_coverage['location'] < $vh_cmdb_coverage['total'] ? 'vh-card--warn' : 'vh-card--ok' ); ?>">
			<h2><?php esc_html_e( 'With a site', 'vulnhub' ); ?></h2>
			<p class="vh-card__value"><?php echo esc_html( $vh_cmdb_percent( $vh_cmdb_coverage['location'], $vh_cmdb_coverage['total'] ) ); ?></p>
			<p class="vh-card__meta"><?php echo esc_html( number_format_i18n( $vh_cmdb_coverage['location'] ) ); ?></p>
		</div>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Coverage by asset type', 'vulnhub' ); ?></h2>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Asset type', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Assets', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Business service', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Owning team', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Site', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $vh_cmdb_coverage['by_type'] as $vh_cmdb_row ) : ?>
						<?php
						$vh_cmdb_total = (int) $vh_cmdb_row['total'];
						$vh_cmdb_types = vh_asset_types();
						?>
						<tr>
							<td><strong><?php echo esc_html( (string) ( $vh_cmdb_types[ (string) $vh_cmdb_row['asset_type'] ] ?? $vh_cmdb_row['asset_type'] ) ); ?></strong></td>
							<td><?php echo esc_html( number_format_i18n( $vh_cmdb_total ) ); ?></td>
							<?php foreach ( array( 'service', 'team', 'location' ) as $vh_cmdb_metric ) : ?>
								<?php $vh_cmdb_value = (int) $vh_cmdb_row[ $vh_cmdb_metric ]; ?>
								<td>
									<div class="vh-meter">
										<div class="vh-meter__track">
											<div class="vh-meter__fill" style="width:<?php echo esc_attr( (string) ( $vh_cmdb_total > 0 ? round( ( $vh_cmdb_value / $vh_cmdb_total ) * 100 ) : 0 ) ); ?>%"></div>
										</div>
									</div>
									<span class="vh-muted vh-nowrap">
										<?php
										printf(
											/* translators: 1: covered assets, 2: total assets. */
											esc_html__( '%1$s of %2$s', 'vulnhub' ),
											esc_html( number_format_i18n( $vh_cmdb_value ) ),
											esc_html( number_format_i18n( $vh_cmdb_total ) )
										);
										?>
									</span>
								</td>
							<?php endforeach; ?>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Assets the CMDB still cannot describe', 'vulnhub' ); ?></h2>
		<p class="vh-muted" style="margin:0 0 12px;line-height:1.6;max-width:840px">
			<?php esc_html_e( 'This list is the operational point of a CMDB integration: every row is an asset nobody can be asked to patch, ordered by how much open risk it is carrying.', 'vulnhub' ); ?>
		</p>

		<div class="vh-filters">
			<?php foreach ( $vh_cmdb_gap_labels as $vh_cmdb_key => $vh_cmdb_label ) : ?>
				<a class="button <?php echo $vh_cmdb_gap === $vh_cmdb_key ? 'button-primary' : ''; ?>"
					href="<?php echo esc_url( vh_admin_url( 'vulnhub-cmdb', array( 'tab' => 'coverage', 'gap' => $vh_cmdb_key ) ) ); ?>">
					<?php echo esc_html( $vh_cmdb_label ); ?>
				</a>
			<?php endforeach; ?>
		</div>

		<?php if ( ! $vh_cmdb_gaps ) : ?>
			<div class="vh-empty">
				<p><?php esc_html_e( 'Nothing missing. Every asset has an owning team, a business service and a site.', 'vulnhub' ); ?></p>
			</div>
		<?php else : ?>
			<div class="vh-table-wrap">
				<table class="wp-list-table widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Hostname', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Discovered by', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Business service', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Team', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Site', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Open critical / high', 'vulnhub' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php
						$vh_cmdb_types = vh_asset_types();
						foreach ( $vh_cmdb_gaps as $vh_cmdb_asset ) :
							?>
							<tr>
								<td class="vh-mono">
									<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets', array( 'asset' => (int) $vh_cmdb_asset['id'] ) ) ); ?>">
										<?php echo esc_html( (string) $vh_cmdb_asset['hostname'] ); ?>
									</a>
								</td>
								<td><?php echo esc_html( (string) ( $vh_cmdb_types[ (string) $vh_cmdb_asset['asset_type'] ] ?? $vh_cmdb_asset['asset_type'] ) ); ?></td>
								<td class="vh-muted"><?php echo esc_html( (string) $vh_cmdb_asset['primary_source'] ); ?></td>
								<td>
									<?php
									echo '' !== (string) $vh_cmdb_asset['business_service']
										? esc_html( (string) $vh_cmdb_asset['business_service'] )
										: '<span class="vh-pill vh-sev-high">' . esc_html__( 'missing', 'vulnhub' ) . '</span>';
									?>
								</td>
								<td>
									<?php
									$vh_cmdb_team_id = (int) $vh_cmdb_asset['team_id'];
									echo $vh_cmdb_team_id && isset( $vh_cmdb_teams[ $vh_cmdb_team_id ] )
										? esc_html( $vh_cmdb_teams[ $vh_cmdb_team_id ] )
										: '<span class="vh-pill vh-sev-high">' . esc_html__( 'missing', 'vulnhub' ) . '</span>';
									?>
								</td>
								<td>
									<?php
									$vh_cmdb_loc_id = (int) $vh_cmdb_asset['location_id'];
									echo $vh_cmdb_loc_id && isset( $vh_cmdb_locations[ $vh_cmdb_loc_id ] )
										? esc_html( $vh_cmdb_locations[ $vh_cmdb_loc_id ] )
										: '<span class="vh-pill vh-sev-medium">' . esc_html__( 'missing', 'vulnhub' ) . '</span>';
									?>
								</td>
								<td class="vh-nowrap">
									<?php
									echo esc_html(
										number_format_i18n( (int) $vh_cmdb_asset['open_critical'] ) . ' / ' . number_format_i18n( (int) $vh_cmdb_asset['open_high'] )
									);
									?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>

<?php endif; ?>

