<?php
/**
 * Authentication & MFA admin screen.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'users';
// phpcs:enable

$vh_policy = VulnHub_Auth_Policy::all();
$vh_tabs   = array(
	'users'  => __( 'User enrolment', 'vulnhub' ),
	'policy' => __( 'MFA policy', 'vulnhub' ),
	'sso'    => __( 'Single sign-on', 'vulnhub' ),
);
?>

<nav class="vh-tabs">
	<?php foreach ( $vh_tabs as $vh_key => $vh_label ) : ?>
		<a class="<?php echo $vh_tab === $vh_key ? 'is-active' : ''; ?>"
			href="<?php echo esc_url( vh_admin_url( VULNHUB_AUTH_USERS_PAGE, array( 'tab' => $vh_key ) ) ); ?>">
			<?php echo esc_html( $vh_label ); ?>
		</a>
	<?php endforeach; ?>
</nav>

<?php if ( 'users' === $vh_tab ) : ?>

	<?php
	$vh_users    = get_users( array( 'number' => 300, 'orderby' => 'display_name' ) );
	$vh_enrolled = 0;
	foreach ( $vh_users as $vh_u ) {
		if ( VulnHub_Auth_User_MFA::is_enabled( (int) $vh_u->ID ) ) {
			++$vh_enrolled;
		}
	}
	$vh_total   = max( 1, count( $vh_users ) );
	$vh_percent = (int) round( ( $vh_enrolled / $vh_total ) * 100 );
	?>

	<div class="vh-grid vh-grid--4">
		<div class="vh-card <?php echo $vh_percent >= 80 ? 'vh-card--ok' : 'vh-card--warn'; ?>">
			<h2><?php esc_html_e( 'Enrolled', 'vulnhub' ); ?></h2>
			<p class="vh-card__value"><?php echo esc_html( $vh_enrolled . ' / ' . count( $vh_users ) ); ?></p>
			<div class="vh-meter">
				<span class="vh-meter__track"><span class="vh-meter__fill" style="width:<?php echo esc_attr( (string) $vh_percent ); ?>%"></span></span>
				<span class="vh-muted"><?php echo esc_html( $vh_percent . '%' ); ?></span>
			</div>
		</div>
		<div class="vh-card">
			<h2><?php esc_html_e( 'Policy', 'vulnhub' ); ?></h2>
			<p class="vh-card__value" style="font-size:19px;line-height:1.4">
				<?php echo esc_html( VulnHub_Auth_Policy::modes()[ $vh_policy['mode'] ] ?? (string) $vh_policy['mode'] ); ?>
			</p>
		</div>
		<div class="vh-card">
			<h2><?php esc_html_e( 'Grace period', 'vulnhub' ); ?></h2>
			<p class="vh-card__value"><?php echo esc_html( (string) $vh_policy['grace_days'] ); ?></p>
			<p class="vh-card__meta"><?php esc_html_e( 'days for a new user to enrol', 'vulnhub' ); ?></p>
		</div>
		<div class="vh-card">
			<h2><?php esc_html_e( 'SSO providers live', 'vulnhub' ); ?></h2>
			<?php
			$vh_live = array_filter( VulnHub_Auth_SSO::provider_ids(), array( 'VulnHub_Auth_SSO', 'is_active' ) );
			?>
			<p class="vh-card__value"><?php echo esc_html( (string) count( $vh_live ) ); ?></p>
			<p class="vh-card__meta">
				<?php echo esc_html( $vh_live ? implode( ', ', array_map( 'strtoupper', $vh_live ) ) : __( 'none configured yet', 'vulnhub' ) ); ?>
			</p>
		</div>
	</div>

	<div class="vh-table-wrap">
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'User', 'vulnhub' ); ?></th>
					<th style="width:150px"><?php esc_html_e( 'Roles', 'vulnhub' ); ?></th>
					<th style="width:110px"><?php esc_html_e( 'MFA', 'vulnhub' ); ?></th>
					<th style="width:110px"><?php esc_html_e( 'Required', 'vulnhub' ); ?></th>
					<th style="width:130px"><?php esc_html_e( 'Enrolled', 'vulnhub' ); ?></th>
					<th style="width:130px"><?php esc_html_e( 'Last used', 'vulnhub' ); ?></th>
					<th style="width:90px"><?php esc_html_e( 'Recovery', 'vulnhub' ); ?></th>
					<th style="width:90px"><?php esc_html_e( 'Devices', 'vulnhub' ); ?></th>
					<th style="width:90px"></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $vh_users as $vh_u ) : ?>
				<?php
				$vh_status   = VulnHub_Auth_User_MFA::status( (int) $vh_u->ID );
				$vh_required = VulnHub_Auth_Policy::required_for( $vh_u );
				?>
				<tr>
					<td>
						<strong><?php echo esc_html( $vh_u->display_name ); ?></strong>
						<div class="vh-muted" style="font-size:11px"><?php echo esc_html( $vh_u->user_email ); ?></div>
					</td>
					<td class="vh-muted" style="font-size:12px"><?php echo esc_html( implode( ', ', (array) $vh_u->roles ) ); ?></td>
					<td>
						<?php if ( $vh_status['enabled'] ) : ?>
							<span class="vh-state vh-state--approved"><?php esc_html_e( 'On', 'vulnhub' ); ?></span>
						<?php else : ?>
							<span class="vh-state vh-state--<?php echo $vh_required ? 'rejected' : 'draft'; ?>"><?php esc_html_e( 'Off', 'vulnhub' ); ?></span>
						<?php endif; ?>
					</td>
					<td>
						<?php echo $vh_required ? esc_html__( 'Yes', 'vulnhub' ) : '<span class="vh-muted">—</span>'; // phpcs:ignore ?>
					</td>
					<td class="vh-muted vh-nowrap"><?php echo esc_html( $vh_status['enrolled_at'] ? vh_ago( (string) $vh_status['enrolled_at'] ) : '—' ); ?></td>
					<td class="vh-muted vh-nowrap"><?php echo esc_html( $vh_status['last_used'] ? vh_ago( (string) $vh_status['last_used'] ) : '—' ); ?></td>
					<td><?php echo esc_html( $vh_status['enabled'] ? (string) $vh_status['recovery'] : '—' ); ?></td>
					<td><?php echo esc_html( $vh_status['enabled'] ? (string) $vh_status['devices'] : '—' ); ?></td>
					<td>
						<a class="button button-small" href="<?php echo esc_url( get_edit_user_link( (int) $vh_u->ID ) ); ?>">
							<?php esc_html_e( 'Manage', 'vulnhub' ); ?>
						</a>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>

	<p class="vh-muted" style="margin-top:12px">
		<?php esc_html_e( 'Enrolment happens on a user\'s own profile screen, so the secret is never handled by anyone else. An administrator can reset a locked-out user from their profile.', 'vulnhub' ); ?>
	</p>

<?php elseif ( 'policy' === $vh_tab ) : ?>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
		<?php wp_nonce_field( 'vulnhub_auth_save_policy' ); ?>
		<input type="hidden" name="action" value="vulnhub_auth_save_policy">

		<h2 style="margin-top:16px"><?php esc_html_e( 'Multi-factor policy', 'vulnhub' ); ?></h2>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="vh-mfa-mode"><?php esc_html_e( 'Enforcement', 'vulnhub' ); ?></label></th>
				<td>
					<select name="mode" id="vh-mfa-mode">
						<?php foreach ( VulnHub_Auth_Policy::modes() as $vh_k => $vh_l ) : ?>
							<option value="<?php echo esc_attr( $vh_k ); ?>" <?php selected( (string) $vh_policy['mode'], $vh_k ); ?>>
								<?php echo esc_html( $vh_l ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Required for these roles', 'vulnhub' ); ?></th>
				<td>
					<?php foreach ( wp_roles()->get_names() as $vh_slug => $vh_name ) : ?>
						<label style="display:inline-block;margin:0 16px 6px 0">
							<input type="checkbox" name="roles[]" value="<?php echo esc_attr( $vh_slug ); ?>"
								<?php checked( in_array( $vh_slug, (array) $vh_policy['roles'], true ) ); ?>>
							<?php echo esc_html( $vh_name ); ?>
						</label>
					<?php endforeach; ?>
					<span class="vh-field-help"><?php esc_html_e( 'Only applies when enforcement is set to "Required for selected roles".', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-grace"><?php esc_html_e( 'Grace period', 'vulnhub' ); ?></label></th>
				<td>
					<input type="number" min="0" max="365" id="vh-grace" name="grace_days" class="small-text" value="<?php echo esc_attr( (string) $vh_policy['grace_days'] ); ?>">
					<?php esc_html_e( 'days', 'vulnhub' ); ?>
					<span class="vh-field-help"><?php esc_html_e( 'How long a newly created account may sign in before it is forced to enrol. Set to 0 to require enrolment immediately.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Remembered browsers', 'vulnhub' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="remember_enabled" value="1" <?php checked( ! empty( $vh_policy['remember_enabled'] ) ); ?>>
						<?php esc_html_e( 'Let users skip the second factor on a browser they have marked as trusted', 'vulnhub' ); ?>
					</label>
					<br>
					<input type="number" min="1" max="365" name="remember_days" class="small-text" value="<?php echo esc_attr( (string) $vh_policy['remember_days'] ); ?>" style="margin-top:8px">
					<?php esc_html_e( 'days before a trusted browser is challenged again', 'vulnhub' ); ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Lockout', 'vulnhub' ); ?></th>
				<td>
					<input type="number" min="1" max="50" name="lockout_threshold" class="small-text" value="<?php echo esc_attr( (string) $vh_policy['lockout_threshold'] ); ?>">
					<?php esc_html_e( 'failed codes, then lock for', 'vulnhub' ); ?>
					<input type="number" min="1" max="1440" name="lockout_minutes" class="small-text" value="<?php echo esc_attr( (string) $vh_policy['lockout_minutes'] ); ?>">
					<?php esc_html_e( 'minutes', 'vulnhub' ); ?>
					<span class="vh-field-help"><?php esc_html_e( 'Counted per user and per source IP. Every attempt is written to the audit trail.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Single sign-on', 'vulnhub' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="skip_for_sso" value="1" <?php checked( ! empty( $vh_policy['skip_for_sso'] ) ); ?>>
						<?php esc_html_e( 'Do not challenge users who signed in through an identity provider', 'vulnhub' ); ?>
					</label>
					<span class="vh-field-help"><?php esc_html_e( 'Recommended — Okta and Entra enforce their own MFA, and challenging twice only trains people to click through prompts.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-issuer"><?php esc_html_e( 'Authenticator label', 'vulnhub' ); ?></label></th>
				<td>
					<input type="text" id="vh-issuer" name="issuer_label" class="regular-text" value="<?php echo esc_attr( (string) $vh_policy['issuer_label'] ); ?>" placeholder="<?php echo esc_attr( get_bloginfo( 'name' ) ); ?>">
					<span class="vh-field-help"><?php esc_html_e( 'The name shown beside the code in Google Authenticator, Authy, 1Password and so on.', 'vulnhub' ); ?></span>
				</td>
			</tr>
		</table>

		<?php submit_button( __( 'Save policy', 'vulnhub' ) ); ?>
	</form>

<?php else : ?>

	<?php
	$vh_map      = VulnHub_Auth_SSO::role_map();
	$vh_sso_only = VulnHub_Auth_SSO::sso_only();
	$vh_roles    = \VulnHub\Core\Caps::roles();
	?>

	<div class="vh-grid vh-grid--3">
		<?php foreach ( VulnHub_Auth_SSO::provider_ids() as $vh_p ) : ?>
			<?php
			$vh_conn   = vulnhub()->connectors->get( $vh_p );
			$vh_active = VulnHub_Auth_SSO::is_active( $vh_p );
			?>
			<div class="vh-card">
				<h2><?php echo esc_html( $vh_conn ? $vh_conn->label() : strtoupper( $vh_p ) ); ?></h2>
				<p>
					<span class="vh-health vh-health--<?php echo $vh_active ? 'ok' : 'off'; ?>">
						<?php echo $vh_active ? esc_html__( 'Live', 'vulnhub' ) : esc_html__( 'Not configured', 'vulnhub' ); ?>
					</span>
				</p>
				<p class="vh-card__meta" style="line-height:1.6">
					<?php esc_html_e( 'Redirect URI to register with this provider:', 'vulnhub' ); ?>
				</p>
				<div class="vh-log" style="max-height:none;font-size:11px"><?php echo esc_html( VulnHub_Auth_SSO::redirect_uri( $vh_p ) ); ?></div>
				<p style="margin:12px 0 0">
					<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations', array( 'connector' => $vh_p ) ) ); ?>">
						<?php esc_html_e( 'Configure', 'vulnhub' ); ?>
					</a>
				</p>
			</div>
		<?php endforeach; ?>
	</div>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form" style="margin-bottom:20px">
		<?php wp_nonce_field( 'vulnhub_auth_save_ssoonly' ); ?>
		<input type="hidden" name="action" value="vulnhub_auth_save_ssoonly">
		<h2 style="margin-top:16px"><?php esc_html_e( 'SSO-only login', 'vulnhub' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Password form', 'vulnhub' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="sso_only" value="1" <?php checked( $vh_sso_only ); ?>>
						<?php esc_html_e( 'Hide the username and password form — sign-in only through an identity provider', 'vulnhub' ); ?>
					</label>
					<span class="vh-field-help">
						<strong><?php esc_html_e( 'Keep this escape hatch somewhere safe before you turn this on.', 'vulnhub' ); ?></strong>
						<?php esc_html_e( 'If the identity provider ever becomes unreachable, the password form can still be reached at:', 'vulnhub' ); ?>
					</span>
					<div class="vh-log" style="max-height:none;font-size:11px;margin-top:8px"><?php echo esc_html( wp_login_url() . '?vh_local=1' ); ?></div>
				</td>
			</tr>
		</table>
		<?php submit_button( __( 'Save', 'vulnhub' ), 'secondary' ); ?>
	</form>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
		<?php wp_nonce_field( 'vulnhub_auth_save_rolemap' ); ?>
		<input type="hidden" name="action" value="vulnhub_auth_save_rolemap">

		<h2 style="margin-top:16px"><?php esc_html_e( 'Group to role mapping', 'vulnhub' ); ?></h2>
		<p class="vh-muted" style="max-width:800px;line-height:1.6">
			<?php esc_html_e( 'When someone signs in through an identity provider, the groups in their token are matched against this table and the matching VulnHub role is applied. Rules are evaluated top to bottom; a user who matches nothing gets the provider\'s default role.', 'vulnhub' ); ?>
		</p>

		<table class="wp-list-table widefat striped" style="margin:14px 0">
			<thead>
				<tr>
					<th style="width:170px"><?php esc_html_e( 'Provider', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Group / claim value', 'vulnhub' ); ?></th>
					<th style="width:260px"><?php esc_html_e( 'VulnHub role', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php
			$vh_rows = $vh_map;
			// Always render three spare rows so the table can be extended.
			for ( $vh_i = 0; $vh_i < 3; $vh_i++ ) {
				$vh_rows[] = array(
					'provider' => 'okta',
					'group'    => '',
					'role'     => 'vulnhub_viewer',
				);
			}
			foreach ( $vh_rows as $vh_row ) :
				?>
				<tr>
					<td>
						<select name="provider[]">
							<?php foreach ( array_merge( VulnHub_Auth_SSO::provider_ids(), array( 'ldap' ) ) as $vh_p ) : ?>
								<option value="<?php echo esc_attr( $vh_p ); ?>" <?php selected( (string) $vh_row['provider'], $vh_p ); ?>>
									<?php echo esc_html( strtoupper( $vh_p ) ); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
					<td>
						<input type="text" name="group[]" class="large-text" value="<?php echo esc_attr( (string) $vh_row['group'] ); ?>"
							placeholder="<?php esc_attr_e( 'e.g. SecurityEngineering', 'vulnhub' ); ?>">
					</td>
					<td>
						<select name="role[]">
							<?php foreach ( $vh_roles as $vh_slug => $vh_def ) : ?>
								<option value="<?php echo esc_attr( $vh_slug ); ?>" <?php selected( (string) $vh_row['role'], $vh_slug ); ?>>
									<?php echo esc_html( (string) $vh_def['label'] ); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>

		<p class="vh-muted" style="font-size:12px">
			<?php esc_html_e( 'Leave a group blank to delete that rule. Microsoft Entra ID stops sending the groups claim once a user is in more than about 150 groups and sends a _claim_names pointer instead — VulnHub detects that and says so on the login audit entry rather than silently granting nothing.', 'vulnhub' ); ?>
		</p>

		<?php submit_button( __( 'Save role mapping', 'vulnhub' ) ); ?>
	</form>

<?php endif; ?>

