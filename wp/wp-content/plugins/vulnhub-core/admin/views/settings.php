<?php
/**
 * Platform settings screen — redesigned.
 *
 * Four sub-tab groups over one form, titled cards, `.vh-field` rows that never
 * let label / control / help collide, lifecycle scope as a chip grid, all long
 * help behind per-field info buttons, and a dirty-state save bar. The help
 * strings, POST field names, nonce and action are unchanged from the original
 * form — this is presentation only.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Crypto;
use VulnHub\Core\Coverage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_s = vulnhub()->settings;

/* Per-status asset counts, shared by both scope grids. */
global $wpdb;
$vh_by_status = array();
foreach (
	(array) $wpdb->get_results(
		'SELECT lifecycle_status AS s, COUNT(*) AS n FROM ' . vh_table( 'assets' ) . ' GROUP BY lifecycle_status',
		ARRAY_A
	) as $vh_row
) {
	$vh_by_status[ (string) $vh_row['s'] ] = (int) $vh_row['n'];
}

$vh_statuses = vh_lifecycle_statuses();
$vh_scope    = vh_scannable_statuses();
$vh_rscope   = vh_reportable_statuses();

$vh_scope_assets = 0;
foreach ( $vh_scope as $vh_st ) {
	$vh_scope_assets += (int) ( $vh_by_status[ $vh_st ] ?? 0 );
}
$vh_rscope_assets = 0;
foreach ( $vh_rscope as $vh_st ) {
	$vh_rscope_assets += (int) ( $vh_by_status[ $vh_st ] ?? 0 );
}

/**
 * Emit an info-button + speech bubble for a field's help text.
 *
 * @param string $id    Unique id, wired to aria-controls.
 * @param string $text  The (already-translated) help copy — preserved verbatim.
 * @param bool   $scope Reserve extra bottom margin (for the chip grids).
 */
$vh_help = static function ( string $id, string $text, bool $scope = false ): void {
	printf(
		'<button type="button" class="vh-help" aria-expanded="false" aria-controls="%1$s"><span class="vh-help__i" aria-hidden="true">i</span>%2$s</button>'
		. '<div class="vh-bubble%3$s" id="%1$s" role="note"><span class="vh-bubble__tail" aria-hidden="true"></span><p>%4$s</p></div>',
		esc_attr( $id ),
		esc_html__( 'Why this setting', 'vulnhub' ),
		$scope ? ' vh-bubble--scope' : '',
		esc_html( $text )
	);
};
?>

<div class="vh-set">
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-set__form" data-vh-settings>
		<?php wp_nonce_field( 'vulnhub_save_platform' ); ?>
		<input type="hidden" name="action" value="vulnhub_save_platform">

		<div class="vh-tabs" role="tablist" data-vh-tabs aria-label="<?php esc_attr_e( 'Settings groups', 'vulnhub' ); ?>">
			<?php
			foreach (
				array(
					'platform'  => __( 'Platform', 'vulnhub' ),
					'ownership' => __( 'Ownership', 'vulnhub' ),
					'coverage'  => __( 'Coverage', 'vulnhub' ),
					'retention' => __( 'Retention', 'vulnhub' ),
				) as $vh_tk => $vh_tlabel
			) :
				?>
				<button type="button" class="vh-tabs__tab<?php echo 'platform' === $vh_tk ? ' is-active' : ''; ?>"
					role="tab" data-vh-tab="<?php echo esc_attr( $vh_tk ); ?>"
					aria-controls="vh-tab-<?php echo esc_attr( $vh_tk ); ?>"
					aria-selected="<?php echo 'platform' === $vh_tk ? 'true' : 'false'; ?>">
					<span class="vh-tabs__dot" aria-hidden="true"></span><?php echo esc_html( $vh_tlabel ); ?>
				</button>
			<?php endforeach; ?>
		</div>

		<!-- Platform -->
		<div class="vh-tabpanel is-active" id="vh-tab-platform" role="tabpanel" data-vh-tabpanel="platform">
			<div class="vh-scard">
				<div class="vh-scard__head">
					<h2><?php esc_html_e( 'Identity &amp; data source', 'vulnhub' ); ?></h2>
					<p><?php esc_html_e( 'What this install calls itself, and whether it is running on live vendor data.', 'vulnhub' ); ?></p>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Organisation name', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<label class="vh-field__name" for="vh-org"><?php esc_html_e( 'Organisation name', 'vulnhub' ); ?></label>
						<span class="vh-field__slug">org_name</span>
					</div>
					<div class="vh-field__body">
						<div class="vh-field__row">
							<input type="text" id="vh-org" name="org_name" class="vh-field__text"
								value="<?php echo esc_attr( (string) $vh_s->platform( 'org_name', get_bloginfo( 'name' ) ) ); ?>">
							<span class="vh-changed"><?php esc_html_e( 'CHANGED', 'vulnhub' ); ?></span>
						</div>
						<?php $vh_help( 'vh-help-org', __( 'Used in ticket descriptions and reports.', 'vulnhub' ) ); ?>
					</div>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Data mode', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<span class="vh-field__name"><?php esc_html_e( 'Data mode', 'vulnhub' ); ?></span>
						<span class="vh-field__slug">master switch</span>
					</div>
					<div class="vh-field__body">
						<label class="vh-check">
							<input type="checkbox" name="mock_mode" value="1" <?php checked( $vh_s->mock_mode() ); ?>>
							<span><?php esc_html_e( 'Run the whole platform on mock data', 'vulnhub' ); ?></span>
						</label>
						<?php $vh_help( 'vh-help-mock', __( 'A master switch. Individual connectors can still override this on their own settings screen. Mock data flows through exactly the same normalisation, mapping and automation code as live data, so anything you build against it will behave the same way in production.', 'vulnhub' ) ); ?>
					</div>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Date order in imports', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<label class="vh-field__name" for="vh-date-order"><?php esc_html_e( 'Date order in imports', 'vulnhub' ); ?></label>
						<span class="vh-field__slug">import_date_order</span>
					</div>
					<div class="vh-field__body">
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
						<?php $vh_help( 'vh-help-dateorder', __( 'How to read a slashed date in an uploaded file. PHP assumes the American order, so an export produced on a New Zealand machine had its dates moved by up to two months — which matters most for a last check-in, since that is what decides whether an unscanned asset is reported as live or as a record nobody retired. A date where one field is above 12 settles itself and ignores this setting; ISO dates are never ambiguous.', 'vulnhub' ) ); ?>
					</div>
				</div>
			</div>
		</div>

		<!-- Ownership -->
		<div class="vh-tabpanel" id="vh-tab-ownership" role="tabpanel" data-vh-tabpanel="ownership">
			<div class="vh-scard">
				<div class="vh-scard__head">
					<h2><?php esc_html_e( 'Ownership &amp; response', 'vulnhub' ); ?></h2>
					<p><?php esc_html_e( 'Who has to answer for an asset, and against which clock.', 'vulnhub' ); ?></p>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Ownership policy', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<span class="vh-field__name"><?php esc_html_e( 'Ownership policy', 'vulnhub' ); ?></span>
						<span class="vh-field__slug">require_user</span>
					</div>
					<div class="vh-field__body">
						<label class="vh-check">
							<input type="checkbox" name="require_user_on_workstation" value="1"
								<?php checked( (bool) $vh_s->platform( 'require_user_on_workstation', 1 ) ); ?>>
							<span><?php esc_html_e( 'A workstation or mobile device must resolve to an individual user', 'vulnhub' ); ?></span>
						</label>
						<?php $vh_help( 'vh-help-requser', __( 'When on, any user-bound asset without an owner is flagged on the overview and listed under Ownership → Unresolved assets. Servers, network gear and cloud resources are expected to resolve to a team instead.', 'vulnhub' ) ); ?>
					</div>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'SLA source', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<label class="vh-field__name" for="vh-sla-source"><?php esc_html_e( 'SLA source', 'vulnhub' ); ?></label>
						<span class="vh-field__slug">sla_source</span>
					</div>
					<div class="vh-field__body">
						<select id="vh-sla-source" name="sla_source">
							<option value="team" <?php selected( (string) $vh_s->platform( 'sla_source', 'team' ), 'team' ); ?>>
								<?php esc_html_e( 'Per-team SLA (set under Ownership → Teams)', 'vulnhub' ); ?>
							</option>
							<option value="global" <?php selected( (string) $vh_s->platform( 'sla_source', 'team' ), 'global' ); ?>>
								<?php esc_html_e( 'One SLA for the whole organisation', 'vulnhub' ); ?>
							</option>
						</select>
					</div>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Organisation SLA', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<span class="vh-field__name"><?php esc_html_e( 'Organisation SLA', 'vulnhub' ); ?></span>
						<span class="vh-field__slug">sla_*_days</span>
					</div>
					<div class="vh-field__body">
						<div class="vh-field__row">
							<?php
							foreach (
								array(
									'critical' => __( 'Critical', 'vulnhub' ),
									'high'     => __( 'High', 'vulnhub' ),
									'medium'   => __( 'Medium', 'vulnhub' ),
									'low'      => __( 'Low', 'vulnhub' ),
								) as $vh_sev => $vh_sev_label
							) :
								?>
								<label class="vh-sla-day">
									<span><?php echo esc_html( $vh_sev_label ); ?></span>
									<input type="number" min="1" max="3650" name="sla_<?php echo esc_attr( $vh_sev ); ?>_days" class="vh-numfield"
										value="<?php echo esc_attr( (string) vh_sla_days( $vh_sev ) ); ?>">
								</label>
							<?php endforeach; ?>
							<span class="vh-unit"><?php esc_html_e( 'days', 'vulnhub' ); ?></span>
						</div>
						<?php $vh_help( 'vh-help-orgsla', __( 'How long a ticket gets, by its highest severity. A ticket raised today is due that many days from today, and the date is shown and can be changed in the review before anything is sent to Jira.', 'vulnhub' ) ); ?>
					</div>
				</div>
				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Asset request due in', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<label class="vh-field__name" for="vh-asset-due"><?php esc_html_e( 'Asset request due in', 'vulnhub' ); ?></label>
						<span class="vh-field__slug">asset_request_due_days</span>
					</div>
					<div class="vh-field__body">
						<div class="vh-field__row">
							<input type="number" min="1" max="3650" id="vh-asset-due" name="asset_request_due_days" class="vh-numfield"
								value="<?php echo esc_attr( (string) vh_asset_request_due_days() ); ?>">
							<span class="vh-unit"><?php esc_html_e( 'days', 'vulnhub' ); ?></span>
						</div>
						<?php $vh_help( 'vh-help-assetdue', __( 'Due date for tickets raised from an asset list (Tenable coverage, Defender onboarding, CMDB and Intune gaps, clean-up), which have no severity. Editable in the review before sending.', 'vulnhub' ) ); ?>
					</div>
				</div>
				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Closure verification delay', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<label class="vh-field__name" for="vh-verify"><?php esc_html_e( 'Closure verification delay', 'vulnhub' ); ?></label>
						<span class="vh-field__slug">auto_verify_hours</span>
					</div>
					<div class="vh-field__body">
						<div class="vh-field__row">
							<input type="number" min="1" max="720" id="vh-verify" name="auto_verify_hours" class="vh-numfield"
								value="<?php echo esc_attr( (string) vh_verification_delay_hours() ); ?>">
							<span class="vh-unit"><?php esc_html_e( 'hours', 'vulnhub' ); ?></span>
						</div>
						<?php $vh_help( 'vh-help-verify', __( 'How long to wait after a ticket is closed in Jira before re-checking the finding against Tenable. Give the scanner enough time to have run again, or every closure will come back as "still detected".', 'vulnhub' ) ); ?>
					</div>
				</div>
			</div>
		</div>

		<!-- Coverage -->
		<div class="vh-tabpanel" id="vh-tab-coverage" role="tabpanel" data-vh-tabpanel="coverage">
			<div class="vh-scard">
				<div class="vh-scard__head">
					<h2><?php esc_html_e( 'Three separate questions', 'vulnhub' ); ?></h2>
					<p><?php esc_html_e( 'Ownership asks who to ring about a machine; coverage asks whether Tenable should have scanned it; reporting asks whether it belongs in a reported number at all.', 'vulnhub' ); ?></p>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Coverage scope', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<span class="vh-field__name"><?php esc_html_e( 'Coverage scope', 'vulnhub' ); ?></span>
						<span class="vh-field__slug">coverage_scope</span>
					</div>
					<div class="vh-field__body">
						<div class="vh-scopes__head">
							<span class="vh-field__name"><?php esc_html_e( 'Expected to carry a Tenable scan', 'vulnhub' ); ?></span>
							<span class="vh-scopes__sum" data-vh-scope-sum="coverage" data-vh-scope-mode="scope"
								data-total="<?php echo esc_attr( (string) count( $vh_statuses ) ); ?>"><?php
								/* translators: 1: statuses ticked, 2: total statuses, 3: assets in scope. */
								echo esc_html( sprintf( __( '%1$d OF %2$d STATUSES · %3$s ASSETS IN SCOPE', 'vulnhub' ), count( $vh_scope ), count( $vh_statuses ), number_format_i18n( $vh_scope_assets ) ) );
							?></span>
						</div>
						<div class="vh-scopes" data-vh-scope-grid="coverage">
							<?php foreach ( $vh_statuses as $vh_slug => $vh_meta ) : $vh_n = (int) ( $vh_by_status[ $vh_slug ] ?? 0 ); ?>
								<label class="vh-scope<?php echo in_array( $vh_slug, $vh_scope, true ) ? ' is-on' : ''; ?>" data-n="<?php echo esc_attr( (string) $vh_n ); ?>">
									<input type="checkbox" name="coverage_scope[]" value="<?php echo esc_attr( $vh_slug ); ?>" <?php checked( in_array( $vh_slug, $vh_scope, true ) ); ?>>
									<span class="vh-scope__label"><?php echo esc_html( (string) $vh_meta['label'] ); ?></span>
									<span class="vh-scope__n"><?php echo esc_html( number_format_i18n( $vh_n ) ); ?></span>
								</label>
							<?php endforeach; ?>
						</div>
						<?php $vh_help( 'vh-help-covscope', __( 'Which assets are expected to have a Tenable scan. Anything not ticked is reported as "out of scope" rather than as a coverage gap — a machine in quarantine or in a repair bay is not on the network to be scanned, and listing it as unscanned work buries the machines somebody can actually do something about. This is a separate question from ownership: everything here still has to resolve to a person or a team.', 'vulnhub' ), true ); ?>
					</div>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Reporting scope', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<span class="vh-field__name"><?php esc_html_e( 'Reporting scope', 'vulnhub' ); ?></span>
						<span class="vh-field__slug">reporting_scope</span>
					</div>
					<div class="vh-field__body">
						<div class="vh-scopes__head">
							<span class="vh-field__name"><?php esc_html_e( 'Counted by widgets and reports', 'vulnhub' ); ?></span>
							<span class="vh-scopes__sum" data-vh-scope-sum="reporting" data-vh-scope-mode="report"
								data-total="<?php echo esc_attr( (string) count( $vh_statuses ) ); ?>"><?php
								/* translators: 1: statuses ticked, 2: total statuses, 3: assets counted. */
								echo esc_html( sprintf( __( '%1$d OF %2$d STATUSES · %3$s ASSETS COUNTED', 'vulnhub' ), count( $vh_rscope ), count( $vh_statuses ), number_format_i18n( $vh_rscope_assets ) ) );
							?></span>
						</div>
						<div class="vh-scopes" data-vh-scope-grid="reporting">
							<?php foreach ( $vh_statuses as $vh_slug => $vh_meta ) : $vh_n = (int) ( $vh_by_status[ $vh_slug ] ?? 0 ); ?>
								<label class="vh-scope<?php echo in_array( $vh_slug, $vh_rscope, true ) ? ' is-on' : ''; ?>" data-n="<?php echo esc_attr( (string) $vh_n ); ?>">
									<input type="checkbox" name="reporting_scope[]" value="<?php echo esc_attr( $vh_slug ); ?>" <?php checked( in_array( $vh_slug, $vh_rscope, true ) ); ?>>
									<span class="vh-scope__label"><?php echo esc_html( (string) $vh_meta['label'] ); ?></span>
									<span class="vh-scope__n"><?php echo esc_html( number_format_i18n( $vh_n ) ); ?></span>
								</label>
							<?php endforeach; ?>
						</div>
						<?php $vh_help( 'vh-help-repscope', __( 'Which assets every dashboard widget counts, and which assets the report behind a widget lists. This is the denominator on the front page, so narrowing it makes the estate look smaller and safer without anything having been fixed. It is a third question, separate from both of the above: ownership asks who to ring about a machine, coverage asks whether Tenable should have scanned it, and this asks whether it belongs in a reported number at all. Untick "Unknown" with care — an unclassified device is usually the one carrying the most unattended risk.', 'vulnhub' ), true ); ?>
					</div>
				</div>
			</div>

			<div class="vh-scard">
				<div class="vh-scard__head">
					<h2><?php esc_html_e( 'Freshness windows', 'vulnhub' ); ?></h2>
					<p><?php esc_html_e( 'How old a scan, and how old a sighting, may be before we stop believing it.', 'vulnhub' ); ?></p>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Scan freshness window', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<label class="vh-field__name" for="vh-cov-window"><?php esc_html_e( 'Scan freshness window', 'vulnhub' ); ?></label>
						<span class="vh-field__slug">coverage_window_days</span>
					</div>
					<div class="vh-field__body">
						<div class="vh-field__row">
							<input type="number" min="1" max="365" id="vh-cov-window" name="coverage_window_days" class="vh-numfield"
								value="<?php echo esc_attr( (string) Coverage::window_days() ); ?>">
							<span class="vh-unit"><?php esc_html_e( 'days', 'vulnhub' ); ?></span>
						</div>
						<?php $vh_help( 'vh-help-covwin', __( 'An asset Tenable has not seen for longer than this is reported as a stale scan rather than as covered.', 'vulnhub' ) ); ?>
					</div>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Last-contact window', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<label class="vh-field__name" for="vh-contact-window"><?php esc_html_e( 'Last-contact window', 'vulnhub' ); ?></label>
						<span class="vh-field__slug">contact_window_days</span>
					</div>
					<div class="vh-field__body">
						<div class="vh-field__row">
							<input type="number" min="1" max="730" id="vh-contact-window" name="contact_window_days" class="vh-numfield"
								value="<?php echo esc_attr( (string) Coverage::contact_days() ); ?>">
							<span class="vh-unit"><?php esc_html_e( 'days', 'vulnhub' ); ?></span>
						</div>
						<?php $vh_help( 'vh-help-contactwin', __( 'How long any system\'s word that an asset still exists stays good for. An asset Tenable has never scanned, that Intune or the CMDB saw inside this window, is reported as a live coverage gap — real work for whoever owns scanning. One that nothing has dated inside it is reported as "no recent contact", which is almost always a record nobody retired. Longer than the scan window on purpose: a laptop can sit in a drawer for a month without being gone.', 'vulnhub' ) ); ?>
						<?php if ( 0 === Coverage::assets_with_contact() ) : ?>
							<p class="vh-set__note">
								<strong><?php esc_html_e( 'No asset carries a contact date yet.', 'vulnhub' ); ?></strong>
								<?php esc_html_e( 'Until an Intune sync or an import brings in a last check-in, every gap is reported as a live one — which is the safe answer, not a hidden one.', 'vulnhub' ); ?>
							</p>
						<?php endif; ?>
					</div>
				</div>
			</div>
		</div>

		<!-- Retention -->
		<div class="vh-tabpanel" id="vh-tab-retention" role="tabpanel" data-vh-tabpanel="retention">
			<div class="vh-scard">
				<div class="vh-scard__head">
					<h2><?php esc_html_e( 'Retention', 'vulnhub' ); ?></h2>
					<p><?php esc_html_e( 'How long the platform\'s own record of itself is kept.', 'vulnhub' ); ?></p>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Log retention', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<div class="vh-field__label">
						<label class="vh-field__name" for="vh-retention"><?php esc_html_e( 'Log retention', 'vulnhub' ); ?></label>
						<span class="vh-field__slug">log_retention_days</span>
					</div>
					<div class="vh-field__body">
						<div class="vh-field__row">
							<input type="number" min="7" max="3650" id="vh-retention" name="log_retention_days" class="vh-numfield"
								value="<?php echo esc_attr( (string) $vh_s->platform( 'log_retention_days', 120 ) ); ?>">
							<span class="vh-unit"><?php esc_html_e( 'days', 'vulnhub' ); ?></span>
						</div>
						<?php $vh_help( 'vh-help-retention', __( 'Audit entries and sync runs older than this are pruned nightly.', 'vulnhub' ) ); ?>
					</div>
				</div>
			</div>
		</div>

		<div class="vh-savebar" data-vh-savebar>
			<span class="vh-savebar__dot" aria-hidden="true"></span>
			<span class="vh-savebar__n" data-vh-savebar-n><?php esc_html_e( 'Unsaved changes', 'vulnhub' ); ?></span>
			<span class="vh-savebar__names" data-vh-savebar-names></span>
			<button type="button" class="vh-btn" data-vh-discard><?php esc_html_e( 'Discard', 'vulnhub' ); ?></button>
			<button type="submit" class="vh-btn vh-btn--primary"><?php esc_html_e( 'Save settings', 'vulnhub' ); ?></button>
		</div>
	</form>

	<aside class="vh-set__rail">
		<div class="vh-rail-card">
			<h2><?php esc_html_e( 'Credential storage', 'vulnhub' ); ?></h2>
			<div class="vh-rail-card__body">
				<?php if ( Crypto::using_config_key() ) : ?>
					<p><span class="vh-health vh-health--ok"><?php esc_html_e( 'Key held outside the database', 'vulnhub' ); ?></span></p>
					<p><?php esc_html_e( 'Connector credentials are encrypted with XChaCha20-Poly1305 using', 'vulnhub' ); ?>
						<code>VULNHUB_ENCRYPTION_KEY</code>
						<?php esc_html_e( 'from wp-config.php. A database dump on its own does not expose your API keys.', 'vulnhub' ); ?></p>
				<?php else : ?>
					<p><span class="vh-health vh-health--warn"><?php esc_html_e( 'Key stored in the database', 'vulnhub' ); ?></span></p>
					<p><?php esc_html_e( 'Add a 64-character hex key to wp-config.php and re-enter your credentials:', 'vulnhub' ); ?></p>
					<code class="vh-codebox"><?php echo esc_html( "define( 'VULNHUB_ENCRYPTION_KEY', '" . bin2hex( random_bytes( 32 ) ) . "' );" ); ?></code>
				<?php endif; ?>
			</div>
		</div>

		<div class="vh-rail-card">
			<h2><?php esc_html_e( 'Roles and capabilities', 'vulnhub' ); ?></h2>
			<div class="vh-rail-card__body">
				<p><?php esc_html_e( 'VulnHub ships four roles. Assign them on the Users screen; site administrators hold every capability automatically.', 'vulnhub' ); ?></p>
			</div>
			<?php foreach ( Caps::roles() as $vh_slug => $vh_role ) : ?>
				<div class="vh-role">
					<div><span class="vh-role__name"><?php echo esc_html( (string) $vh_role['label'] ); ?></span><span class="vh-role__slug"><?php echo esc_html( $vh_slug ); ?></span></div>
					<div class="vh-role__caps">
						<?php foreach ( (array) $vh_role['caps'] as $vh_cap ) : ?>
							<span class="vh-role__cap"><?php echo esc_html( Caps::all()[ $vh_cap ] ?? $vh_cap ); ?></span>
						<?php endforeach; ?>
					</div>
				</div>
			<?php endforeach; ?>
		</div>

		<div class="vh-rail-card">
			<h2><?php esc_html_e( 'System', 'vulnhub' ); ?></h2>
			<dl style="margin:8px 0 0">
				<div class="vh-sysrow"><dt><?php esc_html_e( 'Core version', 'vulnhub' ); ?></dt><dd><?php echo esc_html( VULNHUB_VERSION ); ?></dd></div>
				<div class="vh-sysrow"><dt><?php esc_html_e( 'Schema version', 'vulnhub' ); ?></dt><dd><?php echo esc_html( (string) get_option( 'vulnhub_db_version', '—' ) ); ?></dd></div>
				<div class="vh-sysrow"><dt><?php esc_html_e( 'WordPress', 'vulnhub' ); ?></dt><dd><?php echo esc_html( get_bloginfo( 'version' ) ); ?></dd></div>
				<div class="vh-sysrow"><dt><?php esc_html_e( 'PHP', 'vulnhub' ); ?></dt><dd><?php echo esc_html( PHP_VERSION ); ?></dd></div>
				<div class="vh-sysrow"><dt><?php esc_html_e( 'libsodium', 'vulnhub' ); ?></dt><dd><?php echo esc_html( defined( 'SODIUM_LIBRARY_VERSION' ) ? SODIUM_LIBRARY_VERSION : __( 'unavailable', 'vulnhub' ) ); ?></dd></div>
				<div class="vh-sysrow"><dt><?php esc_html_e( 'WP-Cron', 'vulnhub' ); ?></dt><dd><?php echo esc_html( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ? __( 'external runner', 'vulnhub' ) : __( 'page-load driven', 'vulnhub' ) ); ?></dd></div>
				<div class="vh-sysrow"><dt><?php esc_html_e( 'Site URL', 'vulnhub' ); ?></dt><dd><?php echo esc_html( home_url() ); ?></dd></div>
				<?php
				/*
				 * Every time on every screen is stored in UTC and rendered in
				 * this timezone. Left unset, WordPress calls UTC "local" and
				 * says so nowhere: the platform then reports a scan that ran at
				 * 9am as having run at 9pm the day before, and nothing on the
				 * screen suggests the reader should doubt it. Worth one row.
				 */
				$vh_tz_name = (string) get_option( 'timezone_string' );
				$vh_tz_set  = '' !== $vh_tz_name;
				?>
				<div class="vh-sysrow">
					<dt><?php esc_html_e( 'Timezone', 'vulnhub' ); ?></dt>
					<dd>
						<?php if ( $vh_tz_set ) : ?>
							<?php echo esc_html( $vh_tz_name ); ?>
							<span class="vh-meta"><?php echo esc_html( wp_date( 'j M Y, H:i T' ) ); ?></span>
						<?php else : ?>
							<span class="vh-state vh-state--open"><?php esc_html_e( 'Not set — every time reads as UTC', 'vulnhub' ); ?></span>
							<span class="vh-meta">
								<?php
								if ( current_user_can( 'manage_options' ) ) {
									printf(
										/* translators: %s: link to the WordPress general settings screen. */
										esc_html__( 'Set it in %s so times match the people reading them.', 'vulnhub' ),
										'<a href="' . esc_url( admin_url( 'options-general.php' ) ) . '">' . esc_html__( 'WordPress general settings', 'vulnhub' ) . '</a>'
									);
								} else {
									esc_html_e( 'An administrator can set it in the WordPress general settings.', 'vulnhub' );
								}
								?>
							</span>
						<?php endif; ?>
					</dd>
				</div>
			</dl>
		</div>
	</aside>
</div>
