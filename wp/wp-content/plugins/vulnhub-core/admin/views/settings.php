<?php
/**
 * Platform settings screen.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Crypto;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_s = vulnhub()->settings;
?>

<div class="vh-grid vh-grid--2">
	<div>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
			<?php wp_nonce_field( 'vulnhub_save_platform' ); ?>
			<input type="hidden" name="action" value="vulnhub_save_platform">

			<h2 style="margin-top:16px"><?php esc_html_e( 'Platform', 'vulnhub' ); ?></h2>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="vh-org"><?php esc_html_e( 'Organisation name', 'vulnhub' ); ?></label></th>
					<td>
						<input type="text" id="vh-org" name="org_name" class="regular-text"
							value="<?php echo esc_attr( (string) $vh_s->platform( 'org_name', get_bloginfo( 'name' ) ) ); ?>">
						<span class="vh-field-help"><?php esc_html_e( 'Used in ticket descriptions and reports.', 'vulnhub' ); ?></span>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Data mode', 'vulnhub' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="mock_mode" value="1" <?php checked( $vh_s->mock_mode() ); ?>>
							<?php esc_html_e( 'Run the whole platform on mock data', 'vulnhub' ); ?>
						</label>
						<span class="vh-field-help">
							<?php esc_html_e( 'A master switch. Individual connectors can still override this on their own settings screen. Mock data flows through exactly the same normalisation, mapping and automation code as live data, so anything you build against it will behave the same way in production.', 'vulnhub' ); ?>
						</span>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Ownership policy', 'vulnhub' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="require_user_on_workstation" value="1"
								<?php checked( (bool) $vh_s->platform( 'require_user_on_workstation', 1 ) ); ?>>
							<?php esc_html_e( 'A workstation or mobile device must resolve to an individual user', 'vulnhub' ); ?>
						</label>
						<span class="vh-field-help">
							<?php esc_html_e( 'When on, any user-bound asset without an owner is flagged on the overview and listed under Ownership → Unresolved assets. Servers, network gear and cloud resources are expected to resolve to a team instead.', 'vulnhub' ); ?>
						</span>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-verify"><?php esc_html_e( 'Closure verification delay', 'vulnhub' ); ?></label></th>
					<td>
						<input type="number" min="1" max="720" id="vh-verify" name="auto_verify_hours" class="small-text"
							value="<?php echo esc_attr( (string) vh_verification_delay_hours() ); ?>">
						<?php esc_html_e( 'hours', 'vulnhub' ); ?>
						<span class="vh-field-help">
							<?php esc_html_e( 'How long to wait after a ticket is closed in Jira before re-checking the finding against Tenable. Give the scanner enough time to have run again, or every closure will come back as "still detected".', 'vulnhub' ); ?>
						</span>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-sla-source"><?php esc_html_e( 'SLA source', 'vulnhub' ); ?></label></th>
					<td>
						<select id="vh-sla-source" name="sla_source">
							<option value="team" <?php selected( (string) $vh_s->platform( 'sla_source', 'team' ), 'team' ); ?>>
								<?php esc_html_e( 'Per-team SLA (set under Ownership → Teams)', 'vulnhub' ); ?>
							</option>
							<option value="global" <?php selected( (string) $vh_s->platform( 'sla_source', 'team' ), 'global' ); ?>>
								<?php esc_html_e( 'One SLA for the whole organisation', 'vulnhub' ); ?>
							</option>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Coverage scope', 'vulnhub' ); ?></th>
					<td>
						<fieldset>
							<legend class="screen-reader-text"><?php esc_html_e( 'Lifecycle statuses expected to carry a Tenable scan', 'vulnhub' ); ?></legend>
							<?php
							$vh_scope  = vh_scannable_statuses();
							$vh_counts = array();

							foreach ( \VulnHub\Core\Coverage::excluded_by_scope() as $vh_x ) {
								$vh_counts[ $vh_x['status'] ] = (int) $vh_x['count'];
							}

							global $wpdb;
							$vh_all_counts = (array) $wpdb->get_results(
								'SELECT lifecycle_status AS s, COUNT(*) AS n FROM ' . vh_table( 'assets' ) . ' GROUP BY lifecycle_status',
								ARRAY_A
							);
							$vh_by_status = array();

							foreach ( $vh_all_counts as $vh_row ) {
								$vh_by_status[ (string) $vh_row['s'] ] = (int) $vh_row['n'];
							}

							foreach ( vh_lifecycle_statuses() as $vh_slug => $vh_meta ) :
								?>
								<label style="display:block;margin-bottom:4px">
									<input type="checkbox" name="coverage_scope[]" value="<?php echo esc_attr( $vh_slug ); ?>"
										<?php checked( in_array( $vh_slug, $vh_scope, true ) ); ?>>
									<?php echo esc_html( (string) $vh_meta['label'] ); ?>
									<span class="description">
										<?php
										printf(
											/* translators: %s: number of assets currently carrying this status. */
											esc_html( _n( '%s asset', '%s assets', (int) ( $vh_by_status[ $vh_slug ] ?? 0 ), 'vulnhub' ) ),
											esc_html( number_format_i18n( (int) ( $vh_by_status[ $vh_slug ] ?? 0 ) ) )
										);
										?>
									</span>
								</label>
							<?php endforeach; ?>
						</fieldset>
						<span class="vh-field-help">
							<?php
							esc_html_e(
								'Which assets are expected to have a Tenable scan. Anything not ticked is reported as "out of scope" rather than as a coverage gap — a machine in quarantine or in a repair bay is not on the network to be scanned, and listing it as unscanned work buries the machines somebody can actually do something about. This is a separate question from ownership: everything here still has to resolve to a person or a team.',
								'vulnhub'
							);
							?>
						</span>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Reporting scope', 'vulnhub' ); ?></th>
					<td>
						<fieldset>
							<legend class="screen-reader-text"><?php esc_html_e( 'Lifecycle statuses counted by dashboard widgets and reports', 'vulnhub' ); ?></legend>
							<?php
							$vh_rscope = vh_reportable_statuses();

							foreach ( vh_lifecycle_statuses() as $vh_slug => $vh_meta ) :
								?>
								<label style="display:block;margin-bottom:4px">
									<input type="checkbox" name="reporting_scope[]" value="<?php echo esc_attr( $vh_slug ); ?>"
										<?php checked( in_array( $vh_slug, $vh_rscope, true ) ); ?>>
									<?php echo esc_html( (string) $vh_meta['label'] ); ?>
									<span class="description">
										<?php
										printf(
											/* translators: %s: number of assets currently carrying this status. */
											esc_html( _n( '%s asset', '%s assets', (int) ( $vh_by_status[ $vh_slug ] ?? 0 ), 'vulnhub' ) ),
											esc_html( number_format_i18n( (int) ( $vh_by_status[ $vh_slug ] ?? 0 ) ) )
										);
										?>
									</span>
								</label>
							<?php endforeach; ?>
						</fieldset>
						<span class="vh-field-help">
							<?php
							esc_html_e(
								'Which assets every dashboard widget counts, and which assets the report behind a widget lists. This is the denominator on the front page, so narrowing it makes the estate look smaller and safer without anything having been fixed. It is a third question, separate from both of the above: ownership asks who to ring about a machine, coverage asks whether Tenable should have scanned it, and this asks whether it belongs in a reported number at all. Untick "Unknown" with care — an unclassified device is usually the one carrying the most unattended risk.',
								'vulnhub'
							);
							?>
						</span>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-cov-window"><?php esc_html_e( 'Scan freshness window', 'vulnhub' ); ?></label></th>
					<td>
						<input type="number" min="1" max="365" id="vh-cov-window" name="coverage_window_days" class="small-text"
							value="<?php echo esc_attr( (string) \VulnHub\Core\Coverage::window_days() ); ?>">
						<?php esc_html_e( 'days', 'vulnhub' ); ?>
						<span class="vh-field-help"><?php esc_html_e( 'An asset Tenable has not seen for longer than this is reported as a stale scan rather than as covered.', 'vulnhub' ); ?></span>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-contact-window"><?php esc_html_e( 'Last-contact window', 'vulnhub' ); ?></label></th>
					<td>
						<input type="number" min="1" max="730" id="vh-contact-window" name="contact_window_days" class="small-text"
							value="<?php echo esc_attr( (string) \VulnHub\Core\Coverage::contact_days() ); ?>">
						<?php esc_html_e( 'days', 'vulnhub' ); ?>
						<span class="vh-field-help">
							<?php
							$vh_dated = \VulnHub\Core\Coverage::assets_with_contact();

							esc_html_e(
								'How long any system\'s word that an asset still exists stays good for. An asset Tenable has never scanned, that Intune or the CMDB saw inside this window, is reported as a live coverage gap — real work for whoever owns scanning. One that nothing has dated inside it is reported as "no recent contact", which is almost always a record nobody retired. Longer than the scan window on purpose: a laptop can sit in a drawer for a month without being gone.',
								'vulnhub'
							);
							?>
						</span>
						<?php if ( 0 === $vh_dated ) : ?>
							<p class="vh-field-help">
								<strong><?php esc_html_e( 'No asset carries a contact date yet.', 'vulnhub' ); ?></strong>
								<?php esc_html_e( 'Until an Intune sync or an import brings in a last check-in, every gap is reported as a live one — which is the safe answer, not a hidden one.', 'vulnhub' ); ?>
							</p>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-date-order"><?php esc_html_e( 'Date order in imports', 'vulnhub' ); ?></label></th>
					<td>
						<select id="vh-date-order" name="import_date_order">
							<?php
							$vh_order  = (string) $vh_s->platform( 'import_date_order', 'auto' );
							$vh_actual = vh_date_order();

							foreach (
								array(
									'auto' => sprintf(
										/* translators: %s: the order derived from the site locale. */
										__( 'Match the site language (currently %s)', 'vulnhub' ),
										'dmy' === $vh_actual ? __( 'day first', 'vulnhub' ) : __( 'month first', 'vulnhub' )
									),
									'dmy'  => __( 'Day first — 07/09/2026 is 7 September', 'vulnhub' ),
									'mdy'  => __( 'Month first — 07/09/2026 is 9 July', 'vulnhub' ),
								) as $vh_key => $vh_label
							) :
								?>
								<option value="<?php echo esc_attr( $vh_key ); ?>" <?php selected( $vh_order, $vh_key ); ?>>
									<?php echo esc_html( $vh_label ); ?>
								</option>
							<?php endforeach; ?>
						</select>
						<span class="vh-field-help">
							<?php
							esc_html_e(
								'How to read a slashed date in an uploaded file. PHP assumes the American order, so an export produced on a New Zealand machine had its dates moved by up to two months — which matters most for a last check-in, since that is what decides whether an unscanned asset is reported as live or as a record nobody retired. A date where one field is above 12 settles itself and ignores this setting; ISO dates are never ambiguous.',
								'vulnhub'
							);
							?>
						</span>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-retention"><?php esc_html_e( 'Log retention', 'vulnhub' ); ?></label></th>
					<td>
						<input type="number" min="7" max="3650" id="vh-retention" name="log_retention_days" class="small-text"
							value="<?php echo esc_attr( (string) $vh_s->platform( 'log_retention_days', 120 ) ); ?>">
						<?php esc_html_e( 'days', 'vulnhub' ); ?>
						<span class="vh-field-help"><?php esc_html_e( 'Audit entries and sync runs older than this are pruned nightly.', 'vulnhub' ); ?></span>
					</td>
				</tr>
			</table>

			<?php submit_button( __( 'Save settings', 'vulnhub' ) ); ?>
		</form>
	</div>

	<div>
		<div class="vh-card">
			<h2><?php esc_html_e( 'Credential storage', 'vulnhub' ); ?></h2>
			<?php if ( Crypto::using_config_key() ) : ?>
				<p>
					<span class="vh-health vh-health--ok"><?php esc_html_e( 'Key held outside the database', 'vulnhub' ); ?></span>
				</p>
				<p class="vh-card__meta" style="line-height:1.6">
					<?php esc_html_e( 'Connector credentials are encrypted with XChaCha20-Poly1305 using VULNHUB_ENCRYPTION_KEY from wp-config.php. A database dump on its own does not expose your API keys.', 'vulnhub' ); ?>
				</p>
			<?php else : ?>
				<p><span class="vh-health vh-health--warn"><?php esc_html_e( 'Key stored in the database', 'vulnhub' ); ?></span></p>
				<p class="vh-card__meta" style="line-height:1.6">
					<?php esc_html_e( 'Add a 64-character hex key to wp-config.php and re-enter your credentials:', 'vulnhub' ); ?>
				</p>
				<div class="vh-log" style="max-height:none"><?php echo esc_html( "define( 'VULNHUB_ENCRYPTION_KEY', '" . bin2hex( random_bytes( 32 ) ) . "' );" ); ?></div>
			<?php endif; ?>
		</div>

		<div class="vh-card" style="margin-top:16px">
			<h2><?php esc_html_e( 'Roles and capabilities', 'vulnhub' ); ?></h2>
			<p class="vh-card__meta" style="line-height:1.6;margin-bottom:12px">
				<?php esc_html_e( 'VulnHub ships four roles. Assign them on the Users screen; site administrators hold every capability automatically.', 'vulnhub' ); ?>
			</p>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Role', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Can', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( Caps::roles() as $vh_slug => $vh_role ) : ?>
					<tr>
						<td>
							<strong><?php echo esc_html( (string) $vh_role['label'] ); ?></strong>
							<div class="vh-mono vh-muted" style="font-size:11px"><?php echo esc_html( $vh_slug ); ?></div>
						</td>
						<td class="vh-muted" style="font-size:12px;line-height:1.6">
							<?php
							$vh_list = array();
							foreach ( (array) $vh_role['caps'] as $vh_cap ) {
								$vh_list[] = Caps::all()[ $vh_cap ] ?? $vh_cap;
							}
							echo esc_html( implode( '; ', $vh_list ) );
							?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>

		<div class="vh-card" style="margin-top:16px">
			<h2><?php esc_html_e( 'System', 'vulnhub' ); ?></h2>
			<div class="vh-detail">
				<dl>
					<dt><?php esc_html_e( 'Core version', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( VULNHUB_VERSION ); ?></dd>
					<dt><?php esc_html_e( 'Schema version', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( (string) get_option( 'vulnhub_db_version', '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'WordPress', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( get_bloginfo( 'version' ) ); ?></dd>
					<dt><?php esc_html_e( 'PHP', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( PHP_VERSION ); ?></dd>
					<dt><?php esc_html_e( 'libsodium', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( defined( 'SODIUM_LIBRARY_VERSION' ) ? SODIUM_LIBRARY_VERSION : __( 'unavailable', 'vulnhub' ) ); ?></dd>
					<dt><?php esc_html_e( 'WP-Cron', 'vulnhub' ); ?></dt>
					<dd>
						<?php
						echo defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON
							? esc_html__( 'external runner (recommended)', 'vulnhub' )
							: esc_html__( 'page-load driven', 'vulnhub' );
						?>
					</dd>
					<dt><?php esc_html_e( 'Site URL', 'vulnhub' ); ?></dt>
					<dd class="vh-mono" style="font-size:11px"><?php echo esc_html( home_url() ); ?></dd>
				</dl>
			</div>
		</div>
	</div>
</div>

