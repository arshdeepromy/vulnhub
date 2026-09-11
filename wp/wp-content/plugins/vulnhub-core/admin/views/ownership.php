<?php
/**
 * Ownership mapping: rules, teams, and unresolved assets.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Mapping;
use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'rules';
$vh_edit = isset( $_GET['rule'] ) ? (int) $_GET['rule'] : 0;
$vh_team_edit = isset( $_GET['team'] ) ? (int) $_GET['team'] : 0;
// phpcs:enable

$vh_tabs = array(
	'rules'      => __( 'Mapping rules', 'vulnhub' ),
	'unresolved' => __( 'Unresolved assets', 'vulnhub' ),
	'teams'      => __( 'Teams &amp; SLAs', 'vulnhub' ),
	'people'     => __( 'People', 'vulnhub' ),
);
?>

<nav class="vh-tabs">
	<?php foreach ( $vh_tabs as $vh_key => $vh_label ) : ?>
		<a class="<?php echo $vh_tab === $vh_key ? 'is-active' : ''; ?>"
			href="<?php echo esc_url( vh_admin_url( 'vulnhub-ownership', array( 'tab' => $vh_key ) ) ); ?>">
			<?php echo esc_html( $vh_label ); ?>
		</a>
	<?php endforeach; ?>
</nav>

<?php if ( 'rules' === $vh_tab ) : ?>

	<?php
	$vh_rules = (array) $wpdb->get_results( 'SELECT * FROM ' . vh_table( 'mapping_rules' ) . ' ORDER BY priority ASC, id ASC', ARRAY_A );
	$vh_rule  = $vh_edit ? (array) $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'mapping_rules' ) . ' WHERE id = %d', $vh_edit ), ARRAY_A ) : array();
	$vh_last  = (array) get_option( 'vulnhub_last_mapping', array() );
	?>

	<div class="vh-card" style="margin-bottom:18px">
		<h2><?php esc_html_e( 'How ownership is resolved', 'vulnhub' ); ?></h2>
		<p style="margin:0 0 8px;line-height:1.6;max-width:840px">
			<?php esc_html_e( 'Rules run in priority order, lowest number first. Each matching rule applies its assignment; a rule marked "stop" ends the chain. After the rules run, any asset with an owner but no team or location inherits them from that person\'s Entra ID department and office.', 'vulnhub' ); ?>
		</p>
		<p style="margin:0;line-height:1.6;max-width:840px" class="vh-muted">
			<?php esc_html_e( 'The platform treats workstations and mobile devices as user-bound: they must resolve to an individual, not just a team. Anything that does not is listed under "Unresolved assets".', 'vulnhub' ); ?>
		</p>
		<?php if ( $vh_last ) : ?>
			<p class="vh-card__meta" style="margin-top:12px">
				<?php
				printf(
					/* translators: 1: relative time, 2: processed, 3: changed, 4: unresolved. */
					esc_html__( 'Last run %1$s — %2$d assets processed, %3$d updated, %4$d user-bound assets still unassigned.', 'vulnhub' ),
					esc_html( vh_ago( (string) ( $vh_last['at'] ?? '' ) ) ),
					(int) ( $vh_last['processed'] ?? 0 ),
					(int) ( $vh_last['changed'] ?? 0 ),
					(int) ( $vh_last['unresolved'] ?? 0 )
				);
				?>
			</p>
		<?php endif; ?>
		<?php if ( current_user_can( 'vulnhub_manage' ) ) : ?>
			<p style="margin:12px 0 0">
				<button type="button" class="button button-primary" data-vh-action="remap">
					<?php esc_html_e( 'Re-run mapping now', 'vulnhub' ); ?>
				</button>
			</p>
		<?php endif; ?>
	</div>

	<div class="vh-grid vh-grid--2">
		<div>
			<div class="vh-table-wrap">
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<th style="width:52px"><?php esc_html_e( 'Order', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Rule', 'vulnhub' ); ?></th>
							<th style="width:70px"><?php esc_html_e( 'Hits', 'vulnhub' ); ?></th>
							<th style="width:120px"><?php esc_html_e( 'Actions', 'vulnhub' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php if ( ! $vh_rules ) : ?>
						<tr><td colspan="4" class="vh-muted"><?php esc_html_e( 'No rules defined.', 'vulnhub' ); ?></td></tr>
					<?php endif; ?>
					<?php foreach ( $vh_rules as $vh_r ) : ?>
						<tr<?php echo empty( $vh_r['enabled'] ) ? ' style="opacity:.55"' : ''; ?>>
							<td class="vh-mono"><?php echo esc_html( (string) $vh_r['priority'] ); ?></td>
							<td>
								<strong><?php echo esc_html( (string) $vh_r['name'] ); ?></strong>
								<div class="vh-muted" style="font-size:11px;margin-top:3px">
									<?php
									$vh_fields = Mapping::match_fields();
									$vh_ops    = Mapping::operators();
									$vh_assign = Mapping::assign_types();
									printf(
										'%s %s %s &rarr; %s%s',
										esc_html( $vh_fields[ (string) $vh_r['match_field'] ] ?? (string) $vh_r['match_field'] ),
										esc_html( $vh_ops[ (string) $vh_r['match_operator'] ] ?? (string) $vh_r['match_operator'] ),
										'<code>' . esc_html( (string) ( $vh_r['match_value'] ?: '—' ) ) . '</code>',
										esc_html( $vh_assign[ (string) $vh_r['assign_type'] ] ?? (string) $vh_r['assign_type'] ),
										$vh_r['assign_value'] ? ' <code>' . esc_html( (string) $vh_r['assign_value'] ) . '</code>' : ''
									);
									?>
									<?php if ( ! empty( $vh_r['stop_processing'] ) ) : ?>
										&middot; <em><?php esc_html_e( 'stops here', 'vulnhub' ); ?></em>
									<?php endif; ?>
								</div>
							</td>
							<td class="vh-mono"><?php echo esc_html( number_format_i18n( (int) $vh_r['match_count'] ) ); ?></td>
							<td>
								<div class="vh-actions">
									<a class="button button-small" href="<?php echo esc_url( vh_admin_url( 'vulnhub-ownership', array( 'tab' => 'rules', 'rule' => (int) $vh_r['id'] ) ) ); ?>">
										<?php esc_html_e( 'Edit', 'vulnhub' ); ?>
									</a>
									<?php if ( current_user_can( 'vulnhub_manage' ) ) : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
											onsubmit="return confirm('<?php echo esc_js( __( 'Delete this rule?', 'vulnhub' ) ); ?>');" style="display:inline">
											<?php wp_nonce_field( 'vulnhub_delete_rule' ); ?>
											<input type="hidden" name="action" value="vulnhub_delete_rule">
											<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $vh_r['id'] ); ?>">
											<button class="button button-small button-link-delete"><?php esc_html_e( 'Delete', 'vulnhub' ); ?></button>
										</form>
									<?php endif; ?>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>

		<?php if ( current_user_can( 'vulnhub_manage' ) ) : ?>
		<div>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
				<?php wp_nonce_field( 'vulnhub_save_rule' ); ?>
				<input type="hidden" name="action" value="vulnhub_save_rule">
				<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) ( $vh_rule['id'] ?? 0 ) ); ?>">

				<h2 style="margin-top:16px">
					<?php echo $vh_edit ? esc_html__( 'Edit rule', 'vulnhub' ) : esc_html__( 'New rule', 'vulnhub' ); ?>
				</h2>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="vh-rule-name"><?php esc_html_e( 'Name', 'vulnhub' ); ?></label></th>
						<td><input type="text" class="regular-text" id="vh-rule-name" name="name" value="<?php echo esc_attr( (string) ( $vh_rule['name'] ?? '' ) ); ?>" required></td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-rule-priority"><?php esc_html_e( 'Priority', 'vulnhub' ); ?></label></th>
						<td>
							<input type="number" id="vh-rule-priority" name="priority" value="<?php echo esc_attr( (string) ( $vh_rule['priority'] ?? 50 ) ); ?>" class="small-text">
							<span class="vh-field-help"><?php esc_html_e( 'Lower runs first.', 'vulnhub' ); ?></span>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'When', 'vulnhub' ); ?></th>
						<td>
							<select name="match_field">
								<?php foreach ( Mapping::match_fields() as $vh_k => $vh_l ) : ?>
									<option value="<?php echo esc_attr( $vh_k ); ?>" <?php selected( (string) ( $vh_rule['match_field'] ?? '' ), $vh_k ); ?>><?php echo esc_html( $vh_l ); ?></option>
								<?php endforeach; ?>
							</select>
							<select name="match_operator">
								<?php foreach ( Mapping::operators() as $vh_k => $vh_l ) : ?>
									<option value="<?php echo esc_attr( $vh_k ); ?>" <?php selected( (string) ( $vh_rule['match_operator'] ?? '' ), $vh_k ); ?>><?php echo esc_html( $vh_l ); ?></option>
								<?php endforeach; ?>
							</select>
							<input type="text" name="match_value" value="<?php echo esc_attr( (string) ( $vh_rule['match_value'] ?? '' ) ); ?>"
								placeholder="<?php esc_attr_e( 'value', 'vulnhub' ); ?>" style="width:140px">
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Then', 'vulnhub' ); ?></th>
						<td>
							<select name="assign_type">
								<?php foreach ( Mapping::assign_types() as $vh_k => $vh_l ) : ?>
									<option value="<?php echo esc_attr( $vh_k ); ?>" <?php selected( (string) ( $vh_rule['assign_type'] ?? '' ), $vh_k ); ?>><?php echo esc_html( $vh_l ); ?></option>
								<?php endforeach; ?>
							</select>
							<input type="text" name="assign_value" value="<?php echo esc_attr( (string) ( $vh_rule['assign_value'] ?? '' ) ); ?>"
								placeholder="<?php esc_attr_e( 'team slug, tag key or UPN', 'vulnhub' ); ?>" class="regular-text" style="margin-top:6px">
							<span class="vh-field-help"><?php esc_html_e( 'Leave blank where the assignment needs no extra value.', 'vulnhub' ); ?></span>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Options', 'vulnhub' ); ?></th>
						<td>
							<label style="display:block">
								<input type="checkbox" name="enabled" value="1" <?php checked( (int) ( $vh_rule['enabled'] ?? 1 ), 1 ); ?>>
								<?php esc_html_e( 'Enabled', 'vulnhub' ); ?>
							</label>
							<label style="display:block;margin-top:6px">
								<input type="checkbox" name="stop_processing" value="1" <?php checked( (int) ( $vh_rule['stop_processing'] ?? 0 ), 1 ); ?>>
								<?php esc_html_e( 'Stop processing further rules when this one matches', 'vulnhub' ); ?>
							</label>
						</td>
					</tr>
				</table>

				<?php submit_button( $vh_edit ? __( 'Update rule', 'vulnhub' ) : __( 'Add rule', 'vulnhub' ) ); ?>
				<?php if ( $vh_edit ) : ?>
					<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-ownership', array( 'tab' => 'rules' ) ) ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
				<?php endif; ?>
			</form>
		</div>
		<?php endif; ?>
	</div>

<?php elseif ( 'unresolved' === $vh_tab ) : ?>

	<?php $vh_unresolved = Mapping::unresolved_user_assets( 200 ); ?>

	<div class="vh-card" style="margin-bottom:16px">
		<h2><?php esc_html_e( 'User-bound assets without an owner', 'vulnhub' ); ?></h2>
		<p style="margin:0;max-width:840px;line-height:1.6">
			<?php esc_html_e( 'Each of these is a workstation or mobile device, so the platform expects a named individual. The usual causes are: the device has no primary user set in Intune, the device is shared or kiosk-mode, or the user exists in Entra ID but has not been synced into VulnHub yet.', 'vulnhub' ); ?>
		</p>
	</div>

	<?php if ( ! $vh_unresolved ) : ?>
		<div class="vh-card vh-empty">
			<span class="dashicons dashicons-yes-alt" style="color:var(--vh-ok)"></span>
			<h2><?php esc_html_e( 'Everything resolves', 'vulnhub' ); ?></h2>
			<p><?php esc_html_e( 'Every workstation and mobile device maps to a person.', 'vulnhub' ); ?></p>
		</div>
	<?php else : ?>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Host', 'vulnhub' ); ?></th>
						<th style="width:110px"><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
						<th style="width:170px"><?php esc_html_e( 'Operating system', 'vulnhub' ); ?></th>
						<th style="width:150px"><?php esc_html_e( 'Intune enrolled', 'vulnhub' ); ?></th>
						<th style="width:130px"><?php esc_html_e( 'Open C/H', 'vulnhub' ); ?></th>
						<th style="width:110px"><?php esc_html_e( 'Last seen', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_unresolved as $vh_a ) : ?>
					<tr>
						<td>
							<a class="vh-mono" href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets', array( 'asset' => (int) $vh_a['id'] ) ) ); ?>">
								<strong><?php echo esc_html( (string) $vh_a['hostname'] ); ?></strong>
							</a>
						</td>
						<td><?php echo esc_html( vh_asset_types()[ (string) $vh_a['asset_type'] ] ?? (string) $vh_a['asset_type'] ); ?></td>
						<td><?php echo esc_html( vh_trim( trim( $vh_a['operating_system'] . ' ' . $vh_a['os_version'] ), 30 ) ); ?></td>
						<td>
							<?php if ( ! empty( $vh_a['intune_id'] ) ) : ?>
								<span class="vh-state vh-state--fixed"><?php esc_html_e( 'Yes', 'vulnhub' ); ?></span>
							<?php else : ?>
								<span class="vh-state vh-state--open"><?php esc_html_e( 'Not in Intune', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
						<td class="vh-mono"><?php echo esc_html( $vh_a['open_critical'] . ' / ' . $vh_a['open_high'] ); ?></td>
						<td class="vh-muted vh-nowrap"><?php echo esc_html( vh_ago( (string) $vh_a['last_seen'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>

<?php elseif ( 'teams' === $vh_tab ) : ?>

	<?php
	$vh_teams = Repo::teams();
	$vh_team  = $vh_team_edit ? Repo::team( $vh_team_edit ) : array();
	?>

	<div class="vh-grid vh-grid--2">
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Team', 'vulnhub' ); ?></th>
						<th style="width:110px"><?php esc_html_e( 'Jira project', 'vulnhub' ); ?></th>
						<th style="width:170px"><?php esc_html_e( 'SLA C/H/M/L (days)', 'vulnhub' ); ?></th>
						<th style="width:70px"></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_teams as $vh_t ) : ?>
					<tr>
						<td>
							<strong><?php echo esc_html( (string) $vh_t['name'] ); ?></strong>
							<?php if ( ! empty( $vh_t['manager_email'] ) ) : ?>
								<div class="vh-muted" style="font-size:11px"><?php echo esc_html( (string) $vh_t['manager_email'] ); ?></div>
							<?php endif; ?>
						</td>
						<td class="vh-mono"><?php echo esc_html( (string) ( $vh_t['jira_project_key'] ?: '—' ) ); ?></td>
						<td class="vh-mono">
							<?php echo esc_html( $vh_t['sla_critical_days'] . ' / ' . $vh_t['sla_high_days'] . ' / ' . $vh_t['sla_medium_days'] . ' / ' . $vh_t['sla_low_days'] ); ?>
						</td>
						<td>
							<a class="button button-small" href="<?php echo esc_url( vh_admin_url( 'vulnhub-ownership', array( 'tab' => 'teams', 'team' => (int) $vh_t['id'] ) ) ); ?>">
								<?php esc_html_e( 'Edit', 'vulnhub' ); ?>
							</a>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>

		<?php if ( current_user_can( 'vulnhub_manage' ) ) : ?>
		<div>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
				<?php wp_nonce_field( 'vulnhub_save_team' ); ?>
				<input type="hidden" name="action" value="vulnhub_save_team">
				<input type="hidden" name="team_id" value="<?php echo esc_attr( (string) ( $vh_team['id'] ?? 0 ) ); ?>">

				<h2 style="margin-top:16px"><?php echo $vh_team_edit ? esc_html__( 'Edit team', 'vulnhub' ) : esc_html__( 'New team', 'vulnhub' ); ?></h2>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="vh-team-name"><?php esc_html_e( 'Name', 'vulnhub' ); ?></label></th>
						<td><input type="text" id="vh-team-name" class="regular-text" name="name" value="<?php echo esc_attr( (string) ( $vh_team['name'] ?? '' ) ); ?>" required></td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-team-jira"><?php esc_html_e( 'Jira project key', 'vulnhub' ); ?></label></th>
						<td>
							<input type="text" id="vh-team-jira" name="jira_project_key" value="<?php echo esc_attr( (string) ( $vh_team['jira_project_key'] ?? '' ) ); ?>" class="small-text">
							<span class="vh-field-help"><?php esc_html_e( 'Tickets raised for this team\'s assets land in this project.', 'vulnhub' ); ?></span>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-team-issuetype"><?php esc_html_e( 'Jira issue type', 'vulnhub' ); ?></label></th>
						<td><input type="text" id="vh-team-issuetype" name="jira_issue_type" value="<?php echo esc_attr( (string) ( $vh_team['jira_issue_type'] ?? '' ) ); ?>" class="regular-text" placeholder="Task"></td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-team-assignee"><?php esc_html_e( 'Default assignee', 'vulnhub' ); ?></label></th>
						<td>
							<input type="text" id="vh-team-assignee" name="jira_default_assignee" value="<?php echo esc_attr( (string) ( $vh_team['jira_default_assignee'] ?? '' ) ); ?>" class="regular-text">
							<span class="vh-field-help"><?php esc_html_e( 'Atlassian account id.', 'vulnhub' ); ?></span>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-team-manager"><?php esc_html_e( 'Manager email', 'vulnhub' ); ?></label></th>
						<td><input type="email" id="vh-team-manager" name="manager_email" value="<?php echo esc_attr( (string) ( $vh_team['manager_email'] ?? '' ) ); ?>" class="regular-text"></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Remediation SLA (days)', 'vulnhub' ); ?></th>
						<td>
							<?php
							foreach ( array(
								'sla_critical_days' => __( 'Critical', 'vulnhub' ),
								'sla_high_days'     => __( 'High', 'vulnhub' ),
								'sla_medium_days'   => __( 'Medium', 'vulnhub' ),
								'sla_low_days'      => __( 'Low', 'vulnhub' ),
							) as $vh_field => $vh_label ) :
								?>
								<label style="display:inline-block;margin:0 14px 8px 0;text-transform:none;font-weight:400;font-size:12px">
									<?php echo esc_html( $vh_label ); ?><br>
									<input type="number" min="1" name="<?php echo esc_attr( $vh_field ); ?>" class="small-text"
										value="<?php echo esc_attr( (string) ( $vh_team[ $vh_field ] ?? 30 ) ); ?>">
								</label>
							<?php endforeach; ?>
							<span class="vh-field-help"><?php esc_html_e( 'A finding\'s due date is its first-found date plus the SLA for its severity.', 'vulnhub' ); ?></span>
						</td>
					</tr>
				</table>

				<?php submit_button( $vh_team_edit ? __( 'Update team', 'vulnhub' ) : __( 'Add team', 'vulnhub' ) ); ?>
				<?php if ( $vh_team_edit ) : ?>
					<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-ownership', array( 'tab' => 'teams' ) ) ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
				<?php endif; ?>
			</form>
		</div>
		<?php endif; ?>
	</div>

<?php else : ?>

	<?php
	$vh_people = (array) $wpdb->get_results(
		'SELECT p.*, (SELECT COUNT(*) FROM ' . vh_table( 'assets' ) . ' a WHERE a.owner_person_id = p.id) AS device_count
		 FROM ' . vh_table( 'people' ) . ' p ORDER BY p.display_name ASC LIMIT 300',
		ARRAY_A
	);
	?>

	<p class="vh-muted">
		<?php
		printf(
			/* translators: %s: number of people. */
			esc_html( _n( '%s person synced', '%s people synced', count( $vh_people ), 'vulnhub' ) ),
			'<strong>' . esc_html( number_format_i18n( count( $vh_people ) ) ) . '</strong>'
		);
		?>
	</p>

	<?php if ( ! $vh_people ) : ?>
		<div class="vh-card vh-empty">
			<span class="dashicons dashicons-groups"></span>
			<h2><?php esc_html_e( 'No people synced yet', 'vulnhub' ); ?></h2>
			<p><?php esc_html_e( 'Run an Intune / Entra ID sync to import users, their departments and their offices.', 'vulnhub' ); ?></p>
			<a class="button button-primary" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations' ) ); ?>"><?php esc_html_e( 'Go to integrations', 'vulnhub' ); ?></a>
		</div>
	<?php else : ?>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Person', 'vulnhub' ); ?></th>
						<th style="width:170px"><?php esc_html_e( 'Department', 'vulnhub' ); ?></th>
						<th style="width:150px"><?php esc_html_e( 'Office', 'vulnhub' ); ?></th>
						<th style="width:170px"><?php esc_html_e( 'Manager', 'vulnhub' ); ?></th>
						<th style="width:80px"><?php esc_html_e( 'Devices', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_people as $vh_p ) : ?>
					<tr<?php echo empty( $vh_p['is_active'] ) ? ' style="opacity:.55"' : ''; ?>>
						<td>
							<strong><?php echo esc_html( (string) $vh_p['display_name'] ); ?></strong>
							<div class="vh-muted" style="font-size:11px"><?php echo esc_html( (string) $vh_p['upn'] ); ?></div>
						</td>
						<td><?php echo esc_html( (string) ( $vh_p['department'] ?: '—' ) ); ?></td>
						<td><?php echo esc_html( (string) ( $vh_p['office_location'] ?: '—' ) ); ?></td>
						<td class="vh-muted"><?php echo esc_html( vh_trim( (string) ( $vh_p['manager_upn'] ?: '—' ), 26 ) ); ?></td>
						<td>
							<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets', array( 'owner_person_id' => (int) $vh_p['id'] ) ) ); ?>">
								<?php echo esc_html( number_format_i18n( (int) $vh_p['device_count'] ) ); ?>
							</a>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>

<?php endif; ?>

