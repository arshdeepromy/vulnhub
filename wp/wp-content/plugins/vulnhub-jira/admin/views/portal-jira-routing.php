<?php
/**
 * Portal admin → Jira routing.
 *
 * Rendered by VulnHub_Jira_Routing_Admin::render() inside the portal admin
 * shell, so it draws only the body of the section and reuses the portal's own
 * classes (vh-panel, vh-table, vh-tablewrap, vh-btn, vh-chip, vh-filters,
 * vh-sub, vh-mono) rather than shipping any CSS of its own.
 *
 * Everything on this page is read from the cached directory. Nothing here
 * touches Jira unless the operator presses Refresh.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
	return;
}

$vh_connector = vulnhub_jira_connector();

if ( ! $vh_connector ) {
	echo '<div class="vh-panel"><p class="vh-sub">'
		. esc_html__( 'The Jira connector is not registered.', 'vulnhub' )
		. '</p></div>';
	return;
}

$vh_directory = new VulnHub_Jira_Directory( $vh_connector );
$vh_snapshot  = $vh_directory->cached();
$vh_cold      = null === $vh_snapshot;

if ( $vh_cold ) {
	// First visit: one discovery pass, then cached for an hour.
	$vh_snapshot = $vh_directory->snapshot();
}

$vh_desks      = (array) ( $vh_snapshot['service_desks'] ?? array() );
$vh_projects   = (array) ( $vh_snapshot['projects'] ?? array() );
$vh_types      = (array) ( $vh_snapshot['request_types'] ?? array() );
$vh_field      = (array) ( $vh_snapshot['team_field'] ?? array() );
$vh_groups     = (array) ( $vh_snapshot['groups'] ?? array() );
$vh_roles      = (array) ( $vh_snapshot['roles'] ?? array() );
$vh_errors     = (array) ( $vh_snapshot['errors'] ?? array() );
$vh_notes      = (array) ( $vh_snapshot['notes'] ?? array() );
$vh_options    = (array) ( $vh_field['options'] ?? array() );
$vh_teams      = \VulnHub\Core\Repo::teams();
$vh_routing    = $vh_connector->team_routing();
$vh_mock       = $vh_connector->is_mock();
$vh_age        = $vh_directory->age();
$vh_post_url   = admin_url( 'admin-post.php' );
$vh_type_count = 0;

foreach ( $vh_types as $vh_bucket ) {
	$vh_type_count += count( (array) $vh_bucket );
}

/**
 * Every request type on the site, flattened for a picker, labelled with its
 * desk so an operator cannot mistake one desk's queue for another's.
 *
 * @var array<int,array<string,string>> $vh_flat_types
 */
$vh_flat_types = array();

foreach ( $vh_desks as $vh_desk ) {
	foreach ( (array) ( $vh_types[ (string) $vh_desk['id'] ] ?? array() ) as $vh_type ) {
		$vh_flat_types[] = array(
			'id'    => (string) $vh_type['id'],
			'label' => sprintf( '%s — %s', (string) $vh_desk['project_key'], (string) $vh_type['name'] ),
		);
	}
}

// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$vh_msg = isset( $_GET['vh_msg'] ) ? sanitize_text_field( rawurldecode( wp_unslash( (string) $_GET['vh_msg'] ) ) ) : '';
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$vh_msg_type = isset( $_GET['vh_type'] ) ? sanitize_key( wp_unslash( (string) $_GET['vh_type'] ) ) : 'success';
?>

<?php if ( '' !== $vh_msg ) : ?>
	<div class="vh-panel">
		<p>
			<span class="vh-chip vh-chip--<?php echo esc_attr( 'error' === $vh_msg_type ? 'bad' : ( 'warning' === $vh_msg_type ? 'warn' : 'good' ) ); ?>">
				<?php echo esc_html( 'error' === $vh_msg_type ? __( 'Problem', 'vulnhub' ) : ( 'warning' === $vh_msg_type ? __( 'Careful', 'vulnhub' ) : __( 'Saved', 'vulnhub' ) ) ); ?>
			</span>
			<?php echo esc_html( $vh_msg ); ?>
		</p>
	</div>
<?php endif; ?>

<div class="vh-panel">
	<div class="vh-panel__head">
		<h2><?php esc_html_e( 'Connection', 'vulnhub' ); ?></h2>
		<p class="vh-sub">
			<?php esc_html_e( 'Where this routing is being read from, and how fresh it is.', 'vulnhub' ); ?>
		</p>
	</div>

	<p>
		<span class="vh-chip vh-chip--<?php echo esc_attr( $vh_connector->is_enabled() ? 'good' : 'warn' ); ?>">
			<?php echo esc_html( $vh_connector->is_enabled() ? __( 'Connector enabled', 'vulnhub' ) : __( 'Connector disabled', 'vulnhub' ) ); ?>
		</span>
		<span class="vh-chip vh-chip--<?php echo esc_attr( $vh_mock ? 'warn' : 'good' ); ?>">
			<?php echo esc_html( $vh_mock ? __( 'Mock mode', 'vulnhub' ) : __( 'Live site', 'vulnhub' ) ); ?>
		</span>
		<span class="vh-chip vh-chip--<?php echo esc_attr( ! empty( $vh_snapshot['jsm'] ) ? 'good' : 'warn' ); ?>">
			<?php echo esc_html( ! empty( $vh_snapshot['jsm'] ) ? __( 'Jira Service Management', 'vulnhub' ) : __( 'No service desks', 'vulnhub' ) ); ?>
		</span>
		<span class="vh-mono"><?php echo esc_html( $vh_connector->client()->site_url() ); ?></span>
	</p>

	<p class="vh-sub">
		<?php
		if ( $vh_age >= 0 ) {
			printf(
				/* translators: 1: how long ago the directory was read, 2: desks, 3: request types, 4: projects. */
				esc_html__( 'Directory read %1$s ago: %2$d service desk(s), %3$d request type(s), %4$d project(s).', 'vulnhub' ),
				esc_html( human_time_diff( time() - $vh_age ) ),
				(int) count( $vh_desks ),
				(int) $vh_type_count,
				(int) count( $vh_projects )
			);
		} else {
			esc_html_e( 'The directory has not been read from Jira yet.', 'vulnhub' );
		}
		?>
	</p>

	<?php if ( ! empty( $vh_snapshot['jsm_note'] ) ) : ?>
		<p class="vh-sub"><?php echo esc_html( (string) $vh_snapshot['jsm_note'] ); ?></p>
	<?php endif; ?>

	<?php foreach ( $vh_errors as $vh_error ) : ?>
		<p class="vh-sub"><span class="vh-chip vh-chip--bad"><?php esc_html_e( 'Error', 'vulnhub' ); ?></span> <?php echo esc_html( (string) $vh_error ); ?></p>
	<?php endforeach; ?>

	<?php foreach ( $vh_notes as $vh_note ) : ?>
		<p class="vh-sub"><span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Note', 'vulnhub' ); ?></span> <?php echo esc_html( (string) $vh_note ); ?></p>
	<?php endforeach; ?>

	<form method="post" action="<?php echo esc_url( $vh_post_url ); ?>">
		<?php wp_nonce_field( 'vulnhub_jira_routing_refresh' ); ?>
		<input type="hidden" name="action" value="vulnhub_jira_routing_refresh">
		<button type="submit" class="vh-btn vh-btn--sm"><?php esc_html_e( 'Refresh from Jira', 'vulnhub' ); ?></button>
	</form>
</div>

<div class="vh-panel">
	<div class="vh-panel__head">
		<h2><?php esc_html_e( 'Default routing', 'vulnhub' ); ?></h2>
		<p class="vh-sub">
			<?php esc_html_e( 'Used whenever the owning team has no Jira project key of its own. A team that does have one always wins — this is a fallback, not an override.', 'vulnhub' ); ?>
		</p>
	</div>

	<form method="post" action="<?php echo esc_url( $vh_post_url ); ?>">
		<?php wp_nonce_field( 'vulnhub_jira_routing_defaults' ); ?>
		<input type="hidden" name="action" value="vulnhub_jira_routing_defaults">

		<div class="vh-filters">
			<label>
				<?php esc_html_e( 'Default service desk', 'vulnhub' ); ?>
				<select name="default_service_desk">
					<option value=""><?php esc_html_e( '— none —', 'vulnhub' ); ?></option>
					<?php foreach ( $vh_desks as $vh_desk ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_desk['id'] ); ?>" <?php selected( $vh_connector->default_service_desk(), (string) $vh_desk['id'] ); ?>>
							<?php
							printf(
								'%s (%s)',
								esc_html( (string) $vh_desk['project_name'] ),
								esc_html( (string) $vh_desk['project_key'] )
							);
							?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>

			<label>
				<?php esc_html_e( 'Default request type', 'vulnhub' ); ?>
				<select name="default_request_type">
					<option value=""><?php esc_html_e( '— none —', 'vulnhub' ); ?></option>
					<?php foreach ( $vh_flat_types as $vh_flat ) : ?>
						<option value="<?php echo esc_attr( $vh_flat['id'] ); ?>" <?php selected( $vh_connector->default_request_type(), $vh_flat['id'] ); ?>>
							<?php echo esc_html( $vh_flat['label'] ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>

			<label>
				<?php esc_html_e( 'Default team', 'vulnhub' ); ?>
				<?php if ( $vh_options ) : ?>
					<select name="default_team">
						<option value=""><?php esc_html_e( '— none —', 'vulnhub' ); ?></option>
						<?php foreach ( $vh_options as $vh_option ) : ?>
							<option value="<?php echo esc_attr( (string) $vh_option['value'] ); ?>" <?php selected( $vh_connector->default_team(), (string) $vh_option['value'] ); ?>>
								<?php echo esc_html( (string) $vh_option['value'] ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				<?php else : ?>
					<input type="text" name="default_team" value="<?php echo esc_attr( $vh_connector->default_team() ); ?>" placeholder="<?php esc_attr_e( 'Team id or name', 'vulnhub' ); ?>">
				<?php endif; ?>
			</label>

			<label>
				<?php esc_html_e( 'Fallback project key', 'vulnhub' ); ?>
				<input type="text" name="project_key" value="<?php echo esc_attr( $vh_connector->default_project() ); ?>" placeholder="SEC">
			</label>

			<label>
				<?php esc_html_e( 'Team field id', 'vulnhub' ); ?>
				<input type="text" name="team_field" value="<?php echo esc_attr( $vh_connector->team_field_id() ); ?>" placeholder="<?php esc_attr_e( 'auto-detect', 'vulnhub' ); ?>">
			</label>
		</div>

		<p class="vh-sub vh-sub--foot">
			<?php if ( ! empty( $vh_field['id'] ) ) : ?>
				<?php
				printf(
					/* translators: 1: field name, 2: field id, 3: field type. */
					esc_html__( 'Team field in use: %1$s (%2$s, %3$s).', 'vulnhub' ),
					esc_html( (string) $vh_field['name'] ),
					esc_html( (string) $vh_field['id'] ),
					esc_html( (string) $vh_field['type'] )
				);
				?>
			<?php else : ?>
				<?php esc_html_e( 'No Team field was discovered on this Jira site.', 'vulnhub' ); ?>
			<?php endif; ?>
			<?php if ( ! empty( $vh_field['note'] ) ) : ?>
				<?php echo esc_html( ' ' . (string) $vh_field['note'] ); ?>
			<?php endif; ?>
		</p>

		<p>
			<button type="submit" class="vh-btn vh-btn--primary"><?php esc_html_e( 'Save default routing', 'vulnhub' ); ?></button>
		</p>
	</form>
</div>

<div class="vh-panel">
	<div class="vh-panel__head">
		<h2><?php esc_html_e( 'Per-team routing', 'vulnhub' ); ?></h2>
		<p class="vh-sub">
			<?php esc_html_e( 'A team with a project key here is routed there, whatever the defaults say. Leave a row empty to let it fall through to the default routing above.', 'vulnhub' ); ?>
		</p>
	</div>

	<form method="post" action="<?php echo esc_url( $vh_post_url ); ?>">
		<?php wp_nonce_field( 'vulnhub_jira_routing_teams' ); ?>
		<input type="hidden" name="action" value="vulnhub_jira_routing_teams">

		<div class="vh-tablewrap">
			<table class="vh-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Team', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Jira project', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Issue type', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Request type', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Team value', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Resolves to', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php
					foreach ( $vh_teams as $vh_team ) :
						$vh_id       = (int) $vh_team['id'];
						$vh_override = $vh_routing[ $vh_id ] ?? array(
							'service_desk' => '',
							'request_type' => '',
							'team_value'   => '',
						);
						$vh_resolved = vulnhub_jira_ticketer()->routing( $vh_connector, $vh_team );
						?>
						<tr>
							<th scope="row">
								<?php echo esc_html( (string) $vh_team['name'] ); ?>
								<span class="vh-meta vh-mono"><?php echo esc_html( (string) $vh_team['slug'] ); ?></span>
							</th>
							<td>
								<input
									type="text"
									name="project[<?php echo esc_attr( (string) $vh_id ); ?>]"
									value="<?php echo esc_attr( (string) $vh_team['jira_project_key'] ); ?>"
									list="vh-jira-projects"
									size="10"
									placeholder="<?php esc_attr_e( 'default', 'vulnhub' ); ?>">
							</td>
							<td>
								<input
									type="text"
									name="issue_type[<?php echo esc_attr( (string) $vh_id ); ?>]"
									value="<?php echo esc_attr( (string) $vh_team['jira_issue_type'] ); ?>"
									size="10"
									placeholder="<?php esc_attr_e( 'default', 'vulnhub' ); ?>">
							</td>
							<td>
								<select name="request_type[<?php echo esc_attr( (string) $vh_id ); ?>]">
									<option value=""><?php esc_html_e( '— default —', 'vulnhub' ); ?></option>
									<?php foreach ( $vh_flat_types as $vh_flat ) : ?>
										<option value="<?php echo esc_attr( $vh_flat['id'] ); ?>" <?php selected( (string) $vh_override['request_type'], $vh_flat['id'] ); ?>>
											<?php echo esc_html( $vh_flat['label'] ); ?>
										</option>
									<?php endforeach; ?>
								</select>
							</td>
							<td>
								<?php if ( $vh_options ) : ?>
									<select name="team_value[<?php echo esc_attr( (string) $vh_id ); ?>]">
										<option value=""><?php esc_html_e( '— default —', 'vulnhub' ); ?></option>
										<?php foreach ( $vh_options as $vh_option ) : ?>
											<option value="<?php echo esc_attr( (string) $vh_option['value'] ); ?>" <?php selected( (string) $vh_override['team_value'], (string) $vh_option['value'] ); ?>>
												<?php echo esc_html( (string) $vh_option['value'] ); ?>
											</option>
										<?php endforeach; ?>
									</select>
								<?php else : ?>
									<input
										type="text"
										name="team_value[<?php echo esc_attr( (string) $vh_id ); ?>]"
										value="<?php echo esc_attr( (string) $vh_override['team_value'] ); ?>"
										size="18"
										placeholder="<?php esc_attr_e( 'default', 'vulnhub' ); ?>">
								<?php endif; ?>
							</td>
							<td class="vh-mono">
								<?php
								printf(
									'%s / %s',
									esc_html( (string) $vh_resolved['project'] ),
									esc_html( (string) $vh_resolved['issue_type'] )
								);
								?>
								<span class="vh-meta">
									<?php
									echo esc_html(
										sprintf(
											/* translators: 1: routing source, 2: team value or a dash. */
											__( 'via %1$s, team %2$s', 'vulnhub' ),
											(string) $vh_resolved['source'],
											'' !== (string) $vh_resolved['team_value'] ? (string) $vh_resolved['team_value'] : '—'
										)
									);
									?>
								</span>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>

		<datalist id="vh-jira-projects">
			<?php foreach ( $vh_projects as $vh_project ) : ?>
				<option value="<?php echo esc_attr( (string) $vh_project['key'] ); ?>">
					<?php echo esc_html( (string) $vh_project['name'] ); ?>
				</option>
			<?php endforeach; ?>
		</datalist>

		<p>
			<button type="submit" class="vh-btn vh-btn--primary"><?php esc_html_e( 'Save per-team routing', 'vulnhub' ); ?></button>
		</p>
	</form>
</div>

<div class="vh-grid vh-grid--2">
	<div class="vh-panel">
		<div class="vh-panel__head">
			<h2><?php esc_html_e( 'Service desks and request types', 'vulnhub' ); ?></h2>
			<p class="vh-sub"><?php esc_html_e( 'Read from GET /rest/servicedeskapi/servicedesk and its request type listing.', 'vulnhub' ); ?></p>
		</div>

		<?php if ( ! $vh_desks ) : ?>
			<p class="vh-sub"><?php esc_html_e( 'No service desks — this site is plain Jira, so tickets are routed by project key alone.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<div class="vh-tablewrap">
				<table class="vh-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Desk', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Project', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Request types', 'vulnhub' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $vh_desks as $vh_desk ) : ?>
							<tr>
								<th scope="row">
									<?php echo esc_html( (string) $vh_desk['project_name'] ); ?>
									<span class="vh-meta vh-mono"><?php echo esc_html( sprintf( 'id %s', (string) $vh_desk['id'] ) ); ?></span>
								</th>
								<td class="vh-mono"><?php echo esc_html( (string) $vh_desk['project_key'] ); ?></td>
								<td>
									<?php foreach ( (array) ( $vh_types[ (string) $vh_desk['id'] ] ?? array() ) as $vh_type ) : ?>
										<div>
											<?php echo esc_html( (string) $vh_type['name'] ); ?>
											<span class="vh-meta vh-mono">
												<?php
												echo esc_html(
													sprintf(
														/* translators: 1: request type id, 2: issue type id. */
														__( 'request type %1$s → issue type %2$s', 'vulnhub' ),
														(string) $vh_type['id'],
														(string) $vh_type['issue_type_id']
													)
												);
												?>
											</span>
										</div>
									<?php endforeach; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>

	<div class="vh-panel">
		<div class="vh-panel__head">
			<h2><?php esc_html_e( 'Teams, projects and groups', 'vulnhub' ); ?></h2>
			<p class="vh-sub">
				<?php esc_html_e( 'Jira Cloud has no REST endpoint that lists teams. What can be listed is shown here: the Team field\'s own values where the field is option-backed, plus projects, groups and project roles.', 'vulnhub' ); ?>
			</p>
		</div>

		<p class="vh-h3"><?php esc_html_e( 'Team values', 'vulnhub' ); ?></p>
		<?php if ( $vh_options ) : ?>
			<p>
				<?php foreach ( $vh_options as $vh_option ) : ?>
					<span class="vh-chip vh-chip--good"><?php echo esc_html( (string) $vh_option['value'] ); ?></span>
				<?php endforeach; ?>
			</p>
		<?php else : ?>
			<p class="vh-sub"><?php esc_html_e( 'None could be enumerated. Paste the team id from any issue instead.', 'vulnhub' ); ?></p>
		<?php endif; ?>

		<p class="vh-h3"><?php esc_html_e( 'Projects', 'vulnhub' ); ?></p>
		<p>
			<?php foreach ( $vh_projects as $vh_project ) : ?>
				<span class="vh-chip vh-chip--<?php echo esc_attr( '' !== (string) $vh_project['service_desk_id'] ? 'good' : 'warn' ); ?>">
					<?php echo esc_html( (string) $vh_project['key'] ); ?>
				</span>
			<?php endforeach; ?>
		</p>

		<p class="vh-h3"><?php esc_html_e( 'Groups', 'vulnhub' ); ?></p>
		<?php if ( $vh_groups ) : ?>
			<p>
				<?php foreach ( $vh_groups as $vh_group ) : ?>
					<span class="vh-chip vh-chip--warn"><?php echo esc_html( (string) $vh_group['name'] ); ?></span>
				<?php endforeach; ?>
			</p>
		<?php else : ?>
			<p class="vh-sub"><?php esc_html_e( 'No groups are readable with this token.', 'vulnhub' ); ?></p>
		<?php endif; ?>

		<p class="vh-h3"><?php esc_html_e( 'Project roles', 'vulnhub' ); ?></p>
		<?php if ( $vh_roles ) : ?>
			<p>
				<?php foreach ( array_keys( $vh_roles ) as $vh_role ) : ?>
					<span class="vh-chip vh-chip--warn"><?php echo esc_html( (string) $vh_role ); ?></span>
				<?php endforeach; ?>
			</p>
		<?php else : ?>
			<p class="vh-sub"><?php esc_html_e( 'No project roles are readable with this token.', 'vulnhub' ); ?></p>
		<?php endif; ?>
	</div>
</div>

