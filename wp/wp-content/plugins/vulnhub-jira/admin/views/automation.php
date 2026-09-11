<?php
/**
 * Automation screen.
 *
 * Rendered by core via the `vulnhub_render_admin_page` action, inside the
 * standard `.vulnhub-wrap` shell, so it reuses core's CSS classes throughout.
 *
 * Everything that changes state posts to admin-post.php with a nonce and is
 * handled by VulnHub_Jira_Automation_Admin. The one thing that happens on this
 * page is "Preview matches", which is a genuine dry run: it performs the same
 * selection, condition evaluation and grouping the engine would, and then
 * stops without touching Jira.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! current_user_can( 'vulnhub_view' ) ) {
	wp_die( esc_html__( 'You do not have permission to view this screen.', 'vulnhub' ) );
}

global $wpdb;

$vh_au_engine    = vulnhub_jira_automation();
$vh_au_connector = vulnhub_jira_connector();
$vh_au_can_edit  = current_user_can( \VulnHub\Core\Caps::MANAGE );
$vh_au_rules     = $vh_au_engine->rules();
$vh_au_triggers  = VulnHub_Jira_Automation::triggers();
$vh_au_actions   = VulnHub_Jira_Automation::action_types();
$vh_au_groupings = VulnHub_Jira_Connector::grouping_options();
$vh_au_teams     = \VulnHub\Core\Repo::teams();
$vh_au_locations = \VulnHub\Core\Repo::locations();
$vh_au_history   = $vh_au_engine->history();

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only screen state.
$vh_au_edit_id = isset( $_GET['rule'] ) ? (int) $_GET['rule'] : 0;
$vh_au_is_new  = isset( $_GET['new'] );
$vh_au_preview = isset( $_GET['preview'] ) ? (int) $_GET['preview'] : 0;
$vh_au_nonce   = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
// phpcs:enable WordPress.Security.NonceVerification.Recommended

$vh_au_editing = $vh_au_edit_id ? $vh_au_engine->rule( $vh_au_edit_id ) : null;

if ( $vh_au_is_new ) {
	$vh_au_editing = null;
}

$vh_au_form = VulnHub_Jira_Automation_Admin::form_values( $vh_au_editing );

$vh_au_enabled_count = 0;
foreach ( $vh_au_rules as $vh_au_r ) {
	$vh_au_enabled_count += empty( $vh_au_r['enabled'] ) ? 0 : 1;
}

$vh_au_auto_tickets = (int) $wpdb->get_var(
	$wpdb->prepare( 'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . ' WHERE created_via = %s', 'automation' )
);
$vh_au_actions_total = (int) $wpdb->get_var( 'SELECT COALESCE(SUM(action_count), 0) FROM ' . VulnHub_Jira_Automation::table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

/**
 * Human summary of a rule's conditions.
 *
 * @param array<string,mixed> $rule Hydrated rule.
 * @return array<int,string>
 */
$vh_au_describe = static function ( array $rule ) use ( $vh_au_teams, $vh_au_locations ): array {
	$out = array();

	foreach ( (array) ( $rule['conditions'] ?? array() ) as $condition ) {
		if ( ! is_array( $condition ) || empty( $condition['field'] ) ) {
			continue;
		}

		$field = (string) $condition['field'];
		$value = $condition['value'] ?? '';
		$list  = is_array( $value ) ? implode( ', ', array_map( 'strval', $value ) ) : (string) $value;

		switch ( $field ) {
			case 'severity':
				$out[] = sprintf( __( 'severity in [%s]', 'vulnhub' ), $list );
				break;
			case 'asset_type':
				$out[] = sprintf( __( 'asset type in [%s]', 'vulnhub' ), $list );
				break;
			case 'criticality':
				$out[] = sprintf( __( 'asset criticality in [%s]', 'vulnhub' ), $list );
				break;
			case 'team_id':
				$name = __( 'unknown team', 'vulnhub' );
				foreach ( $vh_au_teams as $team ) {
					if ( (int) $team['id'] === (int) $value ) {
						$name = (string) $team['name'];
					}
				}
				$out[] = sprintf( __( 'team is %s', 'vulnhub' ), $name );
				break;
			case 'location_id':
				$name = __( 'unknown location', 'vulnhub' );
				foreach ( $vh_au_locations as $location ) {
					if ( (int) $location['id'] === (int) $value ) {
						$name = (string) $location['name'];
					}
				}
				$out[] = sprintf( __( 'location is %s', 'vulnhub' ), $name );
				break;
			case 'environment':
				$out[] = sprintf( __( 'environment contains "%s"', 'vulnhub' ), $list );
				break;
			case 'tag':
				$out[] = sprintf( __( 'asset tag matches "%s"', 'vulnhub' ), $list );
				break;
			case 'cvss3_base':
				$out[] = sprintf( __( 'CVSSv3 ≥ %s', 'vulnhub' ), $list );
				break;
			case 'vpr_score':
				$out[] = sprintf( __( 'VPR ≥ %s', 'vulnhub' ), $list );
				break;
			case 'days_open':
				$out[] = sprintf( __( 'open for ≥ %s day(s)', 'vulnhub' ), $list );
				break;
			case 'exploit_available':
				$out[] = __( 'a public exploit exists', 'vulnhub' );
				break;
			case 'has_ticket':
				$out[] = __( 'the finding has no ticket', 'vulnhub' );
				break;
		}
	}

	return $out;
};
?>

<div class="vh-grid vh-grid--4">
	<div class="vh-card">
		<h2><?php esc_html_e( 'Rules', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( count( $vh_au_rules ) ) ); ?></p>
		<p class="vh-card__meta">
			<?php
			printf(
				/* translators: %s: number of enabled rules. */
				esc_html__( '%s enabled', 'vulnhub' ),
				'<strong>' . esc_html( number_format_i18n( $vh_au_enabled_count ) ) . '</strong>'
			);
			?>
		</p>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Tickets raised by automation', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( $vh_au_auto_tickets ) ); ?></p>
		<p class="vh-card__meta"><?php esc_html_e( 'created without anyone clicking anything', 'vulnhub' ); ?></p>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Actions performed', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( $vh_au_actions_total ) ); ?></p>
		<p class="vh-card__meta"><?php esc_html_e( 'groups actioned across every rule', 'vulnhub' ); ?></p>
	</div>

	<div class="vh-card <?php echo esc_attr( $vh_au_connector && $vh_au_connector->is_enabled() ? 'vh-card--ok' : 'vh-card--warn' ); ?>">
		<h2><?php esc_html_e( 'Jira connector', 'vulnhub' ); ?></h2>
		<p class="vh-card__value" style="font-size:20px">
			<?php
			echo esc_html(
				$vh_au_connector
					? (string) $vh_au_connector->health()['label']
					: __( 'Not registered', 'vulnhub' )
			);
			?>
		</p>
		<p class="vh-card__meta">
			<?php esc_html_e( 'Automation can only raise tickets while the connector is enabled.', 'vulnhub' ); ?>
		</p>
	</div>
</div>

<div class="vh-card">
	<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap">
		<div>
			<h2><?php esc_html_e( 'How automation works', 'vulnhub' ); ?></h2>
			<p class="vh-muted" style="max-width:80ch">
				<?php esc_html_e( 'Every rule is a trigger, a set of conditions and a set of actions. Core fires the engine every fifteen minutes. A rule will never action more groups in one pass than its per-run limit, and never runs more often than its throttle allows — so a rule that matches more than you expected raises a handful of tickets and stops, rather than flooding Jira. Preview any rule before you enable it: the preview runs the real selection and grouping and then does nothing.', 'vulnhub' ); ?>
			</p>
		</div>

		<?php if ( $vh_au_can_edit ) : ?>
			<div style="display:flex;gap:8px;flex-wrap:wrap">
				<a class="button button-primary" href="<?php echo esc_url( vh_admin_url( 'vulnhub-automation', array( 'new' => 1 ) ) ); ?>">
					<?php esc_html_e( 'Add a rule', 'vulnhub' ); ?>
				</a>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
					<?php wp_nonce_field( 'vulnhub_jira_run_all' ); ?>
					<input type="hidden" name="action" value="vulnhub_jira_run_all" />
					<button type="submit" class="button button-secondary">
						<?php esc_html_e( 'Run all enabled rules now', 'vulnhub' ); ?>
					</button>
				</form>

				<?php if ( ! $vh_au_rules ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
						<?php wp_nonce_field( 'vulnhub_jira_seed_rules' ); ?>
						<input type="hidden" name="action" value="vulnhub_jira_seed_rules" />
						<button type="submit" class="button">
							<?php esc_html_e( 'Create the example rules', 'vulnhub' ); ?>
						</button>
					</form>
				<?php endif; ?>
			</div>
		<?php endif; ?>
	</div>
</div>

<?php
/* =====================================================================
 * Preview — a real dry run
 * ================================================================== */

if ( $vh_au_preview > 0 && wp_verify_nonce( $vh_au_nonce, 'vulnhub_jira_preview_' . $vh_au_preview ) ) :
	$vh_au_rule = $vh_au_engine->rule( $vh_au_preview );

	if ( $vh_au_rule ) :
		$vh_au_dry = $vh_au_engine->preview( $vh_au_rule );
		?>
		<div class="vh-card">
			<h2>
				<?php
				printf(
					/* translators: %s: rule name. */
					esc_html__( 'Preview: %s', 'vulnhub' ),
					esc_html( (string) $vh_au_rule['name'] )
				);
				?>
			</h2>
			<p class="vh-muted">
				<?php
				printf(
					/* translators: 1: findings matched, 2: groups, 3: per-run cap, 4: grouping label. */
					esc_html__( '%1$d finding(s) match right now, which the rule would turn into %2$d ticket group(s) (grouped %4$s). The per-run limit is %3$d. Nothing has been sent to Jira.', 'vulnhub' ),
					(int) $vh_au_dry['matched'],
					count( $vh_au_dry['groups'] ),
					(int) $vh_au_rule['max_per_run'],
					esc_html( strtolower( (string) ( $vh_au_groupings[ (string) $vh_au_rule['grouping'] ] ?? $vh_au_rule['grouping'] ) ) )
				);
				?>
			</p>

			<?php foreach ( (array) $vh_au_dry['messages'] as $vh_au_msg ) : ?>
				<p class="vh-muted"><em><?php echo esc_html( (string) $vh_au_msg ); ?></em></p>
			<?php endforeach; ?>

			<?php if ( ! $vh_au_dry['groups'] ) : ?>
				<div class="vh-empty">
					<p><?php esc_html_e( 'Nothing matches this rule at the moment. That is a valid answer — it means the rule would sit quiet.', 'vulnhub' ); ?></p>
				</div>
			<?php else : ?>
				<div class="vh-table-wrap">
					<table class="wp-list-table widefat striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Ticket group', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Findings', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Asset', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Highest severity', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Team', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Would cover', 'vulnhub' ); ?></th>
							</tr>
						</thead>
						<tbody>
						<?php foreach ( $vh_au_dry['groups'] as $vh_au_key => $vh_au_rows ) : ?>
							<?php
							$vh_au_first = $vh_au_rows[0];
							$vh_au_sev   = 'info';

							foreach ( $vh_au_rows as $vh_au_row ) {
								if ( (int) ( vh_severities()[ (string) $vh_au_row['severity'] ]['id'] ?? 0 ) > (int) ( vh_severities()[ $vh_au_sev ]['id'] ?? 0 ) ) {
									$vh_au_sev = (string) $vh_au_row['severity'];
								}
							}

							$vh_au_titles = array();

							foreach ( array_slice( $vh_au_rows, 0, 4 ) as $vh_au_row ) {
								$vh_au_titles[] = vh_trim( (string) $vh_au_row['vuln_title'], 60 );
							}
							?>
							<tr>
								<td class="vh-mono"><?php echo esc_html( (string) $vh_au_key ); ?></td>
								<td><strong><?php echo esc_html( number_format_i18n( count( $vh_au_rows ) ) ); ?></strong></td>
								<td>
									<a class="vh-mono" href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets', array( 'asset' => (int) $vh_au_first['asset_id'] ) ) ); ?>">
										<?php echo esc_html( (string) $vh_au_first['hostname'] ); ?>
									</a>
									<br />
									<span class="vh-muted"><?php echo esc_html( (string) ( vh_asset_types()[ (string) $vh_au_first['asset_type'] ] ?? $vh_au_first['asset_type'] ) ); ?></span>
								</td>
								<td><?php echo wp_kses_post( vh_severity_pill( $vh_au_sev ) ); ?></td>
								<td><?php echo esc_html( (string) ( $vh_au_first['team_name'] ?: __( 'Unassigned', 'vulnhub' ) ) ); ?></td>
								<td class="vh-muted"><?php echo esc_html( implode( '; ', $vh_au_titles ) ); ?></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				</div>
			<?php endif; ?>

			<p style="margin-top:12px">
				<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-automation' ) ); ?>">
					<?php esc_html_e( 'Close preview', 'vulnhub' ); ?>
				</a>
			</p>
		</div>
		<?php
	endif;
endif;
?>

<?php
/* =====================================================================
 * Rule list
 * ================================================================== */
?>
<div class="vh-card">
	<h2><?php esc_html_e( 'Rules', 'vulnhub' ); ?></h2>

	<?php if ( ! $vh_au_rules ) : ?>
		<div class="vh-empty">
			<p><?php esc_html_e( 'No automation rules exist yet. Add one, or restore the two worked examples and edit them.', 'vulnhub' ); ?></p>
		</div>
	<?php else : ?>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Rule', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Trigger', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Conditions', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Limits', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Last run', 'vulnhub' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_au_rules as $vh_au_rule_row ) : ?>
					<?php
					$vh_au_id    = (int) $vh_au_rule_row['id'];
					$vh_au_on    = ! empty( $vh_au_rule_row['enabled'] );
					$vh_au_conds = $vh_au_describe( $vh_au_rule_row );
					$vh_au_acts  = array();

					foreach ( (array) $vh_au_rule_row['actions'] as $vh_au_action ) {
						if ( is_array( $vh_au_action ) && ! empty( $vh_au_action['type'] ) ) {
							$vh_au_acts[] = (string) ( $vh_au_actions[ (string) $vh_au_action['type'] ] ?? $vh_au_action['type'] );
						}
					}
					?>
					<tr>
						<td>
							<strong><?php echo esc_html( (string) $vh_au_rule_row['name'] ); ?></strong>
							<span class="vh-state <?php echo esc_attr( $vh_au_on ? 'vh-state--open' : 'vh-state--fixed' ); ?>">
								<?php echo esc_html( $vh_au_on ? __( 'Enabled', 'vulnhub' ) : __( 'Disabled', 'vulnhub' ) ); ?>
							</span>
							<br />
							<span class="vh-muted"><?php echo esc_html( vh_trim( (string) $vh_au_rule_row['description'], 220 ) ); ?></span>
						</td>
						<td>
							<?php echo esc_html( (string) ( $vh_au_triggers[ (string) $vh_au_rule_row['trigger_event'] ]['label'] ?? $vh_au_rule_row['trigger_event'] ) ); ?>
							<br />
							<span class="vh-muted vh-mono"><?php echo esc_html( (string) $vh_au_rule_row['trigger_event'] ); ?></span>
						</td>
						<td>
							<?php if ( ! $vh_au_conds ) : ?>
								<span class="vh-muted"><?php esc_html_e( 'every candidate', 'vulnhub' ); ?></span>
							<?php else : ?>
								<span class="vh-pill">
									<?php echo esc_html( empty( $vh_au_rule_row['match_all'] ) ? __( 'ANY', 'vulnhub' ) : __( 'ALL', 'vulnhub' ) ); ?>
								</span>
								<span class="vh-muted"><?php echo esc_html( implode( '; ', $vh_au_conds ) ); ?></span>
							<?php endif; ?>
						</td>
						<td><?php echo esc_html( $vh_au_acts ? implode( ', ', $vh_au_acts ) : __( 'none', 'vulnhub' ) ); ?></td>
						<td class="vh-nowrap">
							<?php
							printf(
								/* translators: %d: maximum groups per run. */
								esc_html__( 'max %d / run', 'vulnhub' ),
								(int) $vh_au_rule_row['max_per_run']
							);
							?>
							<br />
							<span class="vh-muted">
								<?php
								echo esc_html(
									(int) $vh_au_rule_row['throttle_minutes'] > 0
										? sprintf(
											/* translators: %d: throttle minutes. */
											__( 'throttle %d min', 'vulnhub' ),
											(int) $vh_au_rule_row['throttle_minutes']
										)
										: __( 'no throttle', 'vulnhub' )
								);
								?>
							</span>
							<br />
							<span class="vh-muted"><?php echo esc_html( (string) ( $vh_au_groupings[ (string) $vh_au_rule_row['grouping'] ] ?? $vh_au_rule_row['grouping'] ) ); ?></span>
						</td>
						<td class="vh-nowrap">
							<?php echo esc_html( $vh_au_rule_row['last_run_at'] ? vh_ago( (string) $vh_au_rule_row['last_run_at'] ) : __( 'never', 'vulnhub' ) ); ?>
							<br />
							<span class="vh-muted">
								<?php
								printf(
									/* translators: 1: run count, 2: action count. */
									esc_html__( '%1$d run(s), %2$d action(s)', 'vulnhub' ),
									(int) $vh_au_rule_row['run_count'],
									(int) $vh_au_rule_row['action_count']
								);
								?>
							</span>
						</td>
						<td class="vh-nowrap">
							<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( vh_admin_url( 'vulnhub-automation', array( 'preview' => $vh_au_id ) ), 'vulnhub_jira_preview_' . $vh_au_id ) ); ?>">
								<?php esc_html_e( 'Preview matches', 'vulnhub' ); ?>
							</a>

							<?php if ( $vh_au_can_edit ) : ?>
								<a class="button button-small" href="<?php echo esc_url( vh_admin_url( 'vulnhub-automation', array( 'rule' => $vh_au_id ) ) ); ?>">
									<?php esc_html_e( 'Edit', 'vulnhub' ); ?>
								</a>

								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
									<?php wp_nonce_field( 'vulnhub_jira_toggle_rule' ); ?>
									<input type="hidden" name="action" value="vulnhub_jira_toggle_rule" />
									<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $vh_au_id ); ?>" />
									<button type="submit" class="button button-small">
										<?php echo esc_html( $vh_au_on ? __( 'Disable', 'vulnhub' ) : __( 'Enable', 'vulnhub' ) ); ?>
									</button>
								</form>

								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
									<?php wp_nonce_field( 'vulnhub_jira_run_rule' ); ?>
									<input type="hidden" name="action" value="vulnhub_jira_run_rule" />
									<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $vh_au_id ); ?>" />
									<button type="submit" class="button button-small">
										<?php esc_html_e( 'Run now', 'vulnhub' ); ?>
									</button>
								</form>

								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline"
									onsubmit="return confirm('<?php echo esc_js( __( 'Delete this automation rule?', 'vulnhub' ) ); ?>');">
									<?php wp_nonce_field( 'vulnhub_jira_delete_rule' ); ?>
									<input type="hidden" name="action" value="vulnhub_jira_delete_rule" />
									<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $vh_au_id ); ?>" />
									<button type="submit" class="button button-small button-link-delete">
										<?php esc_html_e( 'Delete', 'vulnhub' ); ?>
									</button>
								</form>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
</div>

<?php
/* =====================================================================
 * Editor
 * ================================================================== */

if ( $vh_au_can_edit && ( $vh_au_is_new || $vh_au_editing ) ) :
	?>
	<div class="vh-card">
		<h2>
			<?php
			echo esc_html(
				$vh_au_editing
					/* translators: %s: rule name. */
					? sprintf( __( 'Edit rule: %s', 'vulnhub' ), (string) $vh_au_editing['name'] )
					: __( 'New automation rule', 'vulnhub' )
			);
			?>
		</h2>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
			<?php wp_nonce_field( 'vulnhub_jira_save_rule' ); ?>
			<input type="hidden" name="action" value="vulnhub_jira_save_rule" />
			<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) ( $vh_au_editing['id'] ?? 0 ) ); ?>" />

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="vh-au-name"><?php esc_html_e( 'Name', 'vulnhub' ); ?></label></th>
					<td>
						<input id="vh-au-name" name="name" type="text" class="regular-text" required
							value="<?php echo esc_attr( (string) ( $vh_au_editing['name'] ?? '' ) ); ?>" />
						<p class="description"><?php esc_html_e( 'This appears in the audit trail every time the rule acts, so name it after what it does.', 'vulnhub' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-desc"><?php esc_html_e( 'Description', 'vulnhub' ); ?></label></th>
					<td>
						<textarea id="vh-au-desc" name="description" rows="3" class="large-text"><?php echo esc_textarea( (string) ( $vh_au_editing['description'] ?? '' ) ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Why this rule exists. Future you will want to know.', 'vulnhub' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Enabled', 'vulnhub' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="enabled" value="1" <?php checked( ! empty( $vh_au_editing['enabled'] ) ); ?> />
							<?php esc_html_e( 'Run this rule on the scheduled pass', 'vulnhub' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Leave this off until Preview matches shows you what you expect.', 'vulnhub' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-trigger"><?php esc_html_e( 'Trigger', 'vulnhub' ); ?></label></th>
					<td>
						<select id="vh-au-trigger" name="trigger_event">
							<?php foreach ( $vh_au_triggers as $vh_au_slug => $vh_au_meta ) : ?>
								<option value="<?php echo esc_attr( $vh_au_slug ); ?>" <?php selected( (string) ( $vh_au_editing['trigger_event'] ?? 'finding.discovered' ), $vh_au_slug ); ?>>
									<?php echo esc_html( $vh_au_meta['label'] ); ?>
								</option>
							<?php endforeach; ?>
						</select>
						<p class="description">
							<?php
							foreach ( $vh_au_triggers as $vh_au_slug => $vh_au_meta ) {
								echo esc_html( $vh_au_meta['label'] . ' — ' . $vh_au_meta['help'] ) . '<br />';
							}
							?>
						</p>
					</td>
				</tr>
			</table>

			<h3><?php esc_html_e( 'Conditions', 'vulnhub' ); ?></h3>
			<p class="description">
				<?php esc_html_e( 'Leave a condition blank to ignore it. An empty set of conditions matches everything the trigger offers, which is rarely what you want.', 'vulnhub' ); ?>
			</p>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Match', 'vulnhub' ); ?></th>
					<td>
						<label style="margin-right:16px">
							<input type="radio" name="match_mode" value="all" <?php checked( empty( $vh_au_editing ) || ! empty( $vh_au_editing['match_all'] ) ); ?> />
							<?php esc_html_e( 'ALL of the conditions below', 'vulnhub' ); ?>
						</label>
						<label>
							<input type="radio" name="match_mode" value="any" <?php checked( $vh_au_editing && empty( $vh_au_editing['match_all'] ) ); ?> />
							<?php esc_html_e( 'ANY of the conditions below', 'vulnhub' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Severity is one of', 'vulnhub' ); ?></th>
					<td>
						<?php foreach ( vh_severities() as $vh_au_sev_slug => $vh_au_sev_meta ) : ?>
							<label style="margin-right:14px">
								<input type="checkbox" name="cond_severity[]" value="<?php echo esc_attr( $vh_au_sev_slug ); ?>"
									<?php checked( in_array( $vh_au_sev_slug, (array) $vh_au_form['cond_severity'], true ) ); ?> />
								<?php echo esc_html( (string) $vh_au_sev_meta['label'] ); ?>
							</label>
						<?php endforeach; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Asset type is one of', 'vulnhub' ); ?></th>
					<td>
						<?php foreach ( vh_asset_types() as $vh_au_type_slug => $vh_au_type_label ) : ?>
							<label style="margin-right:14px">
								<input type="checkbox" name="cond_asset_type[]" value="<?php echo esc_attr( $vh_au_type_slug ); ?>"
									<?php checked( in_array( $vh_au_type_slug, (array) $vh_au_form['cond_asset_type'], true ) ); ?> />
								<?php echo esc_html( $vh_au_type_label ); ?>
							</label>
						<?php endforeach; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Asset criticality is one of', 'vulnhub' ); ?></th>
					<td>
						<?php foreach ( array( 'critical', 'high', 'medium', 'low' ) as $vh_au_crit ) : ?>
							<label style="margin-right:14px">
								<input type="checkbox" name="cond_criticality[]" value="<?php echo esc_attr( $vh_au_crit ); ?>"
									<?php checked( in_array( $vh_au_crit, (array) $vh_au_form['cond_criticality'], true ) ); ?> />
								<?php echo esc_html( ucfirst( $vh_au_crit ) ); ?>
							</label>
						<?php endforeach; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-team"><?php esc_html_e( 'Owning team is', 'vulnhub' ); ?></label></th>
					<td>
						<select id="vh-au-team" name="cond_team_id">
							<option value="0"><?php esc_html_e( '— any team —', 'vulnhub' ); ?></option>
							<?php foreach ( $vh_au_teams as $vh_au_team ) : ?>
								<option value="<?php echo esc_attr( (string) $vh_au_team['id'] ); ?>" <?php selected( (int) $vh_au_form['cond_team_id'], (int) $vh_au_team['id'] ); ?>>
									<?php echo esc_html( (string) $vh_au_team['name'] ); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-location"><?php esc_html_e( 'Location is', 'vulnhub' ); ?></label></th>
					<td>
						<select id="vh-au-location" name="cond_location_id">
							<option value="0"><?php esc_html_e( '— any location —', 'vulnhub' ); ?></option>
							<?php foreach ( $vh_au_locations as $vh_au_location ) : ?>
								<option value="<?php echo esc_attr( (string) $vh_au_location['id'] ); ?>" <?php selected( (int) $vh_au_form['cond_location_id'], (int) $vh_au_location['id'] ); ?>>
									<?php echo esc_html( (string) $vh_au_location['name'] ); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-env"><?php esc_html_e( 'Environment contains', 'vulnhub' ); ?></label></th>
					<td>
						<input id="vh-au-env" name="cond_environment" type="text" class="regular-text"
							placeholder="production" value="<?php echo esc_attr( (string) $vh_au_form['cond_environment'] ); ?>" />
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-cvss"><?php esc_html_e( 'CVSSv3 base score is at least', 'vulnhub' ); ?></label></th>
					<td>
						<input id="vh-au-cvss" name="cond_cvss3_base" type="number" step="0.1" min="0" max="10" class="small-text"
							value="<?php echo esc_attr( (string) $vh_au_form['cond_cvss3_base'] ); ?>" />
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-vpr"><?php esc_html_e( 'VPR score is at least', 'vulnhub' ); ?></label></th>
					<td>
						<input id="vh-au-vpr" name="cond_vpr_score" type="number" step="0.1" min="0" max="10" class="small-text"
							value="<?php echo esc_attr( (string) $vh_au_form['cond_vpr_score'] ); ?>" />
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-days"><?php esc_html_e( 'Days open is at least', 'vulnhub' ); ?></label></th>
					<td>
						<input id="vh-au-days" name="cond_days_open" type="number" step="1" min="0" class="small-text"
							value="<?php echo esc_attr( (string) $vh_au_form['cond_days_open'] ); ?>" />
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-tag"><?php esc_html_e( 'An asset tag matches', 'vulnhub' ); ?></label></th>
					<td>
						<input id="vh-au-tag" name="cond_tag" type="text" class="regular-text"
							placeholder="PCI" value="<?php echo esc_attr( (string) $vh_au_form['cond_tag'] ); ?>" />
						<p class="description"><?php esc_html_e( 'Matched against both the tag key and its value, case insensitively.', 'vulnhub' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Other', 'vulnhub' ); ?></th>
					<td>
						<label style="display:block;margin-bottom:6px">
							<input type="checkbox" name="cond_exploit_available" value="1" <?php checked( (bool) $vh_au_form['cond_exploit_available'] ); ?> />
							<?php esc_html_e( 'A public exploit exists for the vulnerability', 'vulnhub' ); ?>
						</label>
						<label style="display:block">
							<input type="checkbox" name="cond_has_ticket" value="1" <?php checked( (bool) $vh_au_form['cond_has_ticket'] ); ?> />
							<?php esc_html_e( 'The finding does not already have a ticket', 'vulnhub' ); ?>
						</label>
					</td>
				</tr>
			</table>

			<h3><?php esc_html_e( 'Actions', 'vulnhub' ); ?></h3>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Create a Jira ticket', 'vulnhub' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="act_create_ticket" value="1" <?php checked( (bool) $vh_au_form['act_create_ticket'] ); ?> />
							<?php esc_html_e( 'Raise a ticket for each matching group', 'vulnhub' ); ?>
						</label>
						<p>
							<label for="vh-au-act-grouping"><?php esc_html_e( 'Group findings by', 'vulnhub' ); ?></label>
							<select id="vh-au-act-grouping" name="act_create_grouping">
								<option value=""><?php esc_html_e( '— use the rule grouping below —', 'vulnhub' ); ?></option>
								<?php foreach ( $vh_au_groupings as $vh_au_g => $vh_au_g_label ) : ?>
									<option value="<?php echo esc_attr( $vh_au_g ); ?>" <?php selected( (string) $vh_au_form['act_create_grouping'], $vh_au_g ); ?>>
										<?php echo esc_html( $vh_au_g_label ); ?>
									</option>
								<?php endforeach; ?>
							</select>
						</p>
						<p class="description"><?php esc_html_e( 'An open ticket already covering the same group is reused and the new findings are attached to it, so a nightly scan will not open the same issue twice.', 'vulnhub' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Add a comment', 'vulnhub' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="act_comment" value="1" <?php checked( (bool) $vh_au_form['act_comment'] ); ?> />
							<?php esc_html_e( 'Comment on the ticket covering the group', 'vulnhub' ); ?>
						</label>
						<textarea name="act_comment_text" rows="2" class="large-text" placeholder="<?php esc_attr_e( 'Optional text; the matching findings are always listed.', 'vulnhub' ); ?>"><?php echo esc_textarea( (string) $vh_au_form['act_comment_text'] ); ?></textarea>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Transition the issue', 'vulnhub' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="act_transition" value="1" <?php checked( (bool) $vh_au_form['act_transition'] ); ?> />
							<?php esc_html_e( 'Move the issue to this status', 'vulnhub' ); ?>
						</label>
						<input name="act_transition_status" type="text" class="regular-text" placeholder="In Progress"
							value="<?php echo esc_attr( (string) $vh_au_form['act_transition_status'] ); ?>" />
						<p class="description"><?php esc_html_e( 'The status name as it appears in your workflow. If the workflow offers no transition to it from the issue\'s current status, the move is skipped and logged.', 'vulnhub' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Set the priority', 'vulnhub' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="act_set_priority" value="1" <?php checked( (bool) $vh_au_form['act_set_priority'] ); ?> />
							<?php esc_html_e( 'Set the Jira priority to', 'vulnhub' ); ?>
						</label>
						<input name="act_priority" type="text" class="regular-text" placeholder="Highest"
							value="<?php echo esc_attr( (string) $vh_au_form['act_priority'] ); ?>" />
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Send an email', 'vulnhub' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="act_notify" value="1" <?php checked( (bool) $vh_au_form['act_notify'] ); ?> />
							<?php esc_html_e( 'Email a notification to', 'vulnhub' ); ?>
						</label>
						<select name="act_notify_recipient">
							<?php foreach ( VulnHub_Jira_Automation::notify_targets() as $vh_au_target => $vh_au_target_label ) : ?>
								<option value="<?php echo esc_attr( $vh_au_target ); ?>" <?php selected( (string) $vh_au_form['act_notify_recipient'], $vh_au_target ); ?>>
									<?php echo esc_html( $vh_au_target_label ); ?>
								</option>
							<?php endforeach; ?>
						</select>
						<p>
							<input name="act_notify_subject" type="text" class="regular-text"
								placeholder="<?php esc_attr_e( 'Subject (optional)', 'vulnhub' ); ?>"
								value="<?php echo esc_attr( (string) $vh_au_form['act_notify_subject'] ); ?>" />
						</p>
						<textarea name="act_notify_message" rows="2" class="large-text" placeholder="<?php esc_attr_e( 'Optional opening line; the findings, the Jira issue and the asset link are always appended.', 'vulnhub' ); ?>"><?php echo esc_textarea( (string) $vh_au_form['act_notify_message'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'The asset owner comes from ownership mapping; the team manager from the team\'s manager email on the Ownership screen.', 'vulnhub' ); ?></p>
					</td>
				</tr>
			</table>

			<h3><?php esc_html_e( 'Safety limits', 'vulnhub' ); ?></h3>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="vh-au-grouping"><?php esc_html_e( 'Group findings by', 'vulnhub' ); ?></label></th>
					<td>
						<select id="vh-au-grouping" name="grouping">
							<?php foreach ( $vh_au_groupings as $vh_au_g => $vh_au_g_label ) : ?>
								<option value="<?php echo esc_attr( $vh_au_g ); ?>" <?php selected( (string) ( $vh_au_editing['grouping'] ?? 'per_asset_and_severity' ), $vh_au_g ); ?>>
									<?php echo esc_html( $vh_au_g_label ); ?>
								</option>
							<?php endforeach; ?>
						</select>
						<p class="description"><?php esc_html_e( 'One group is one unit of work, and the per-run limit counts groups.', 'vulnhub' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-max"><?php esc_html_e( 'Maximum groups per run', 'vulnhub' ); ?></label></th>
					<td>
						<input id="vh-au-max" name="max_per_run" type="number" min="1" max="200" class="small-text"
							value="<?php echo esc_attr( (string) ( $vh_au_editing['max_per_run'] ?? 25 ) ); ?>" />
						<p class="description"><?php esc_html_e( 'The circuit breaker. A misconfigured rule stops here instead of filling your Jira project.', 'vulnhub' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-throttle"><?php esc_html_e( 'Throttle (minutes)', 'vulnhub' ); ?></label></th>
					<td>
						<input id="vh-au-throttle" name="throttle_minutes" type="number" min="0" max="10080" class="small-text"
							value="<?php echo esc_attr( (string) ( $vh_au_editing['throttle_minutes'] ?? 0 ) ); ?>" />
						<p class="description"><?php esc_html_e( 'Minimum gap between runs of this rule. 0 means it runs on every fifteen-minute pass.', 'vulnhub' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="vh-au-priority"><?php esc_html_e( 'Rule order', 'vulnhub' ); ?></label></th>
					<td>
						<input id="vh-au-priority" name="priority" type="number" min="1" max="999" class="small-text"
							value="<?php echo esc_attr( (string) ( $vh_au_editing['priority'] ?? 10 ) ); ?>" />
						<p class="description"><?php esc_html_e( 'Lower numbers run first.', 'vulnhub' ); ?></p>
					</td>
				</tr>
			</table>

			<p class="submit">
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Save rule', 'vulnhub' ); ?></button>
				<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-automation' ) ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
			</p>
		</form>
	</div>
	<?php
endif;
?>

<?php
/* =====================================================================
 * Recent passes
 * ================================================================== */
?>
<div class="vh-card">
	<h2><?php esc_html_e( 'Recent automation passes', 'vulnhub' ); ?></h2>

	<?php if ( ! $vh_au_history ) : ?>
		<div class="vh-empty">
			<p><?php esc_html_e( 'The engine has not run yet. It runs every fifteen minutes once at least one rule is enabled.', 'vulnhub' ); ?></p>
		</div>
	<?php else : ?>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'When', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Rules', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Matched', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Actioned', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Tickets', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Emails', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Throttled', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Detail', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_au_history as $vh_au_pass ) : ?>
					<?php
					$vh_au_bits = array();

					foreach ( (array) ( $vh_au_pass['detail'] ?? array() ) as $vh_au_detail ) {
						$vh_au_bits[] = sprintf(
							'%s: %d matched, %d actioned%s',
							(string) ( $vh_au_detail['name'] ?? '' ),
							(int) ( $vh_au_detail['matched'] ?? 0 ),
							(int) ( $vh_au_detail['actioned'] ?? 0 ),
							! empty( $vh_au_detail['capped'] ) ? ' (capped)' : ( ! empty( $vh_au_detail['throttled'] ) ? ' (throttled)' : '' )
						);
					}
					?>
					<tr>
						<td class="vh-nowrap"><?php echo esc_html( vh_ago( (string) ( $vh_au_pass['at'] ?? '' ) ) ); ?></td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_au_pass['rules'] ?? 0 ) ) ); ?></td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_au_pass['matched'] ?? 0 ) ) ); ?></td>
						<td><strong><?php echo esc_html( number_format_i18n( (int) ( $vh_au_pass['actioned'] ?? 0 ) ) ); ?></strong></td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_au_pass['tickets'] ?? 0 ) ) ); ?></td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_au_pass['emails'] ?? 0 ) ) ); ?></td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_au_pass['skipped'] ?? 0 ) ) ); ?></td>
						<td class="vh-muted"><?php echo esc_html( vh_trim( implode( ' · ', $vh_au_bits ), 220 ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
</div>

