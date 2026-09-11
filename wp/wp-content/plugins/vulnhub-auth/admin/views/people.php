<?php
/**
 * People — the portal's account screen.
 *
 * Rendered inside the portal admin shell by `vulnhub_render_portal_section`.
 * Never appears in wp-admin, and never shows a WordPress administrator.
 *
 * The table lists; it does not edit. Everything about one person -- their
 * name, address, title, team, phone, role, second factor and password link --
 * happens on one panel, opened with Edit, instead of being scattered across
 * six controls crammed into a table row.
 *
 * Email delivery is not configured here either. It is an integration in its
 * own right (Integrations › Email delivery), so this screen only reports
 * whether it works, because that decides whether an invitation reaches anyone.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only view state.
$vh_notice = isset( $_GET['vh_notice'] ) ? sanitize_key( wp_unslash( $_GET['vh_notice'] ) ) : '';
$vh_error  = isset( $_GET['vh_error'] ) ? sanitize_key( wp_unslash( $_GET['vh_error'] ) ) : '';
$vh_detail = isset( $_GET['vh_detail'] ) ? sanitize_text_field( wp_unslash( $_GET['vh_detail'] ) ) : '';
$vh_who    = isset( $_GET['vh_user'] ) ? (int) $_GET['vh_user'] : 0;
$vh_edit   = isset( $_GET['vh_edit'] ) ? (int) $_GET['vh_edit'] : 0;
// phpcs:enable

$vh_roles   = VulnHub_Auth_People::roles();
$vh_teams   = VulnHub_Auth_People::teams();
$vh_users   = VulnHub_Auth_People::manageable();
$vh_hidden  = VulnHub_Auth_People::hidden_count();
$vh_mail_ok = VulnHub_Auth_Mail::is_configured();
$vh_mail_on = VulnHub_Auth_Mail::is_enabled();
$vh_failure = VulnHub_Auth_Mail::last_failure();
$vh_me      = get_current_user_id();
$vh_mail_ui = function_exists( 'vh_admin_url' )
	? vh_admin_url( 'vulnhub-integrations', array( 'connector' => VulnHub_Auth_Mail::SETTINGS ) )
	: '';

$vh_subject = ( $vh_edit && VulnHub_Auth_People::is_manageable( $vh_edit ) ) ? get_userdata( $vh_edit ) : null;
$vh_subject = $vh_subject instanceof WP_User ? $vh_subject : null;

$vh_messages = array(
	'created'        => __( 'Account created. The invitation is on its way.', 'vulnhub' ),
	'created_nomail' => __( 'Account created, but the invitation could not be delivered. Hand over the link below instead.', 'vulnhub' ),
	'invited'        => __( 'Password link sent.', 'vulnhub' ),
	'invited_nomail' => __( 'The password link could not be emailed. Hand over the link below instead.', 'vulnhub' ),
	'updated'        => __( 'Details saved.', 'vulnhub' ),
	'unchanged'      => __( 'Nothing was different, so nothing was changed.', 'vulnhub' ),
	'mfa_reset'      => __( 'Second factor cleared and every session ended. They will be asked to enrol again at their next sign-in.', 'vulnhub' ),
	'suspended'      => __( 'Access suspended and every session ended.', 'vulnhub' ),
	'reactivated'    => __( 'Access restored.', 'vulnhub' ),
	'deleted'        => __( 'Account deleted.', 'vulnhub' ),
);

$vh_errors = array(
	'email'        => __( 'That is not a valid email address.', 'vulnhub' ),
	'email_taken'  => __( 'Somebody else already has that email address.', 'vulnhub' ),
	'role'         => __( 'Choose a role.', 'vulnhub' ),
	'target'       => __( 'That account cannot be managed from here.', 'vulnhub' ),
	'confirm'      => __( 'Deletion was not confirmed, so nothing happened.', 'vulnhub' ),
	'self_role'    => __( 'You cannot change your own role — ask another administrator.', 'vulnhub' ),
	'self_suspend' => __( 'You cannot suspend your own account.', 'vulnhub' ),
	'self_delete'  => __( 'You cannot delete your own account.', 'vulnhub' ),
	'mfa'          => __( 'The multi-factor module is not available, so there is nothing to reset.', 'vulnhub' ),
	/* translators: %s: the error WordPress gave. */
	'create'       => sprintf( __( 'The account could not be created. %s', 'vulnhub' ), $vh_detail ),
	/* translators: %s: the error WordPress gave. */
	'update'       => sprintf( __( 'Those details could not be saved. %s', 'vulnhub' ), $vh_detail ),
);

$vh_bad_notice = in_array( $vh_notice, array( 'created_nomail', 'invited_nomail' ), true );
?>

<?php if ( $vh_error && isset( $vh_errors[ $vh_error ] ) ) : ?>
	<p class="vh-warn-note"><?php echo esc_html( $vh_errors[ $vh_error ] ); ?></p>
<?php endif; ?>

<?php if ( $vh_notice && ! empty( $vh_messages[ $vh_notice ] ) ) : ?>
	<p class="<?php echo $vh_bad_notice ? 'vh-warn-note' : 'vh-flash vh-flash--good'; ?>">
		<?php echo esc_html( (string) $vh_messages[ $vh_notice ] ); ?>
	</p>
<?php endif; ?>

<?php
// The one-time link, shown only when the email did not get through. Rendering
// it mints a fresh key, which retires any link sent a moment ago -- the right
// trade when the only copy the person has is the one on screen.
if ( $vh_who && in_array( $vh_notice, array( 'created_nomail', 'invited_nomail' ), true ) ) :
	$vh_target = get_userdata( $vh_who );

	if ( $vh_target instanceof WP_User && VulnHub_Auth_People::is_manageable( $vh_who ) ) :
		$vh_link = VulnHub_Auth_People::invite_link( $vh_target );
		?>
		<div class="vh-form" style="margin-bottom:18px">
			<h2 style="margin-top:14px"><?php esc_html_e( 'One-time password link', 'vulnhub' ); ?></h2>
			<p class="vh-field-help">
				<?php
				printf(
					/* translators: %s: display name. */
					esc_html__( 'Send this to %s over a channel you trust. It can be used once, expires within a day, and works for whoever holds it — so do not post it anywhere shared.', 'vulnhub' ),
					esc_html( $vh_target->display_name )
				);
				?>
			</p>
			<input type="text" class="large-text vh-mono" readonly onclick="this.select()"
				value="<?php echo esc_attr( $vh_link ); ?>">
		</div>
		<?php
	endif;
endif;
?>

<?php if ( ! $vh_mail_ok ) : ?>
	<p class="vh-warn-note">
		<?php
		echo esc_html(
			$vh_mail_on
				? __( 'Email delivery is switched on but has no SMTP host, so invitations will not be delivered.', 'vulnhub' )
				: __( 'Email delivery is switched off, so invitations will not be delivered. Accounts can still be created — you will be given a one-time link to hand over instead.', 'vulnhub' )
		);
		?>
		<?php if ( $vh_mail_ui ) : ?>
			<a href="<?php echo esc_url( $vh_mail_ui ); ?>"><?php esc_html_e( 'Set up email delivery', 'vulnhub' ); ?></a>
		<?php endif; ?>
	</p>
<?php elseif ( $vh_failure ) : ?>
	<p class="vh-warn-note">
		<?php
		printf(
			/* translators: 1: error message, 2: relative time. */
			esc_html__( 'The last message the portal tried to send failed (%1$s, %2$s). Invitations may not be arriving.', 'vulnhub' ),
			esc_html( $vh_failure['message'] ),
			esc_html( $vh_failure['at'] ? vh_ago( gmdate( 'Y-m-d H:i:s', $vh_failure['at'] ) ) : '' )
		);
		?>
		<?php if ( $vh_mail_ui ) : ?>
			<a href="<?php echo esc_url( $vh_mail_ui ); ?>"><?php esc_html_e( 'Check email delivery', 'vulnhub' ); ?></a>
		<?php endif; ?>
	</p>
<?php endif; ?>

<?php if ( $vh_subject ) : ?>

	<!-- ------------------------------------------------------- edit a person -->
	<?php
	$vh_p         = VulnHub_Auth_People::profile( $vh_subject );
	$vh_mfa       = VulnHub_Auth_People::mfa( $vh_subject );
	$vh_is_self   = ( (int) $vh_subject->ID === $vh_me );
	$vh_role_now  = VulnHub_Auth_People::role_of( $vh_subject );
	$vh_suspended = VulnHub_Auth_People::is_suspended( $vh_subject );
	?>

	<form method="post" action="<?php echo esc_url( VulnHub_Auth_People::section_url() ); ?>" class="vh-form">
		<?php wp_nonce_field( VulnHub_Auth_People::NONCE_ACTION, VulnHub_Auth_People::NONCE_FIELD ); ?>
		<input type="hidden" name="vh_people_action" value="edit">
		<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $vh_subject->ID ); ?>">

		<h2 style="margin-top:14px">
			<?php
			printf(
				/* translators: %s: display name. */
				esc_html__( 'Editing %s', 'vulnhub' ),
				esc_html( $vh_subject->display_name )
			);
			?>
		</h2>
		<p class="vh-field-help">
			<?php
			printf(
				/* translators: 1: username, 2: relative time. */
				esc_html__( 'Signs in as %1$s. Account created %2$s. The username cannot be changed.', 'vulnhub' ),
				esc_html( $vh_subject->user_login ),
				esc_html( vh_ago( (string) $vh_subject->user_registered ) )
			);
			?>
		</p>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="vh-e-name"><?php esc_html_e( 'Full name', 'vulnhub' ); ?></label></th>
				<td><input type="text" id="vh-e-name" name="display_name" class="regular-text"
					value="<?php echo esc_attr( $vh_subject->display_name ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-e-email"><?php esc_html_e( 'Email address', 'vulnhub' ); ?></label></th>
				<td>
					<input type="email" id="vh-e-email" name="email" class="regular-text"
						value="<?php echo esc_attr( $vh_subject->user_email ); ?>">
					<span class="vh-field-help"><?php esc_html_e( 'Changing this sends WordPress\'s own notice to the old address, and is recorded in the audit trail.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-e-title"><?php esc_html_e( 'Job title', 'vulnhub' ); ?></label></th>
				<td><input type="text" id="vh-e-title" name="job_title" class="regular-text"
					value="<?php echo esc_attr( $vh_p['title'] ); ?>" placeholder="<?php esc_attr_e( 'Security Analyst', 'vulnhub' ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-e-team"><?php esc_html_e( 'Team', 'vulnhub' ); ?></label></th>
				<td>
					<?php if ( $vh_teams ) : ?>
						<select id="vh-e-team" name="team_id">
							<option value="0"><?php esc_html_e( '— none —', 'vulnhub' ); ?></option>
							<?php foreach ( $vh_teams as $vh_tid => $vh_tname ) : ?>
								<option value="<?php echo esc_attr( (string) $vh_tid ); ?>" <?php selected( $vh_tid, $vh_p['team_id'] ); ?>>
									<?php echo esc_html( $vh_tname ); ?>
								</option>
							<?php endforeach; ?>
						</select>
						<span class="vh-field-help"><?php esc_html_e( 'The same teams the ownership rules and Jira routing use.', 'vulnhub' ); ?></span>
					<?php else : ?>
						<span class="vh-muted"><?php esc_html_e( 'No teams have been created yet — add them under Teams & SLAs.', 'vulnhub' ); ?></span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-e-phone"><?php esc_html_e( 'Phone', 'vulnhub' ); ?></label></th>
				<td>
					<input type="text" id="vh-e-phone" name="phone" class="regular-text"
						value="<?php echo esc_attr( $vh_p['phone'] ); ?>" placeholder="+64 21 000 000">
					<span class="vh-field-help"><?php esc_html_e( 'Shown to administrators only. Not used for authentication.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-e-role"><?php esc_html_e( 'Role', 'vulnhub' ); ?></label></th>
				<td>
					<select id="vh-e-role" name="role" <?php disabled( $vh_is_self ); ?>>
						<?php foreach ( $vh_roles as $vh_slug => $vh_label ) : ?>
							<option value="<?php echo esc_attr( $vh_slug ); ?>" <?php selected( $vh_slug, $vh_role_now ); ?>>
								<?php echo esc_html( $vh_label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
					<span class="vh-field-help">
						<?php
						if ( $vh_is_self ) {
							esc_html_e( 'You cannot change your own role. Ask another administrator.', 'vulnhub' );
						} elseif ( $vh_suspended ) {
							esc_html_e( 'This account is suspended — the role chosen here is the one it will come back to.', 'vulnhub' );
						} else {
							esc_html_e( 'A VulnHub role grants nothing in WordPress.', 'vulnhub' );
						}
						?>
					</span>
				</td>
			</tr>
		</table>

		<p>
			<button type="submit" class="button button-primary"><?php esc_html_e( 'Save changes', 'vulnhub' ); ?></button>
			<a class="button" href="<?php echo esc_url( VulnHub_Auth_People::section_url() ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
		</p>
	</form>

	<div class="vh-form" style="margin-top:16px">
		<h2 style="margin-top:14px"><?php esc_html_e( 'Access', 'vulnhub' ); ?></h2>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Password', 'vulnhub' ); ?></th>
				<td>
					<form method="post" action="<?php echo esc_url( VulnHub_Auth_People::section_url() ); ?>" style="display:inline">
						<?php wp_nonce_field( VulnHub_Auth_People::NONCE_ACTION, VulnHub_Auth_People::NONCE_FIELD ); ?>
						<input type="hidden" name="vh_people_action" value="invite">
						<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $vh_subject->ID ); ?>">
						<button type="submit" class="button"><?php esc_html_e( 'Send password link', 'vulnhub' ); ?></button>
					</form>
					<span class="vh-field-help"><?php esc_html_e( 'Emails a one-time link. Their current password keeps working until they use it.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Second factor', 'vulnhub' ); ?></th>
				<td>
					<?php if ( null === $vh_mfa ) : ?>
						<span class="vh-muted"><?php esc_html_e( 'The multi-factor module is not available.', 'vulnhub' ); ?></span>
					<?php elseif ( empty( $vh_mfa['enabled'] ) ) : ?>
						<span class="vh-muted"><?php esc_html_e( 'Not enrolled.', 'vulnhub' ); ?></span>
						<span class="vh-field-help"><?php esc_html_e( 'They will be prompted according to the MFA policy on the Authentication screen.', 'vulnhub' ); ?></span>
					<?php else : ?>
						<form method="post" action="<?php echo esc_url( VulnHub_Auth_People::section_url() ); ?>" style="display:inline"
							onsubmit="return confirm('<?php echo esc_js( __( 'Clear their second factor? They will be signed out everywhere and must enrol a new device before they can get back in.', 'vulnhub' ) ); ?>');">
							<?php wp_nonce_field( VulnHub_Auth_People::NONCE_ACTION, VulnHub_Auth_People::NONCE_FIELD ); ?>
							<input type="hidden" name="vh_people_action" value="mfa_reset">
							<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $vh_subject->ID ); ?>">
							<button type="submit" class="button"><?php esc_html_e( 'Reset enrolment', 'vulnhub' ); ?></button>
						</form>
						<span class="vh-field-help">
							<?php
							printf(
								/* translators: 1: relative time enrolled, 2: number of recovery codes left, 3: number of trusted devices. */
								esc_html__( 'Enrolled %1$s · %2$d recovery codes left · %3$d trusted devices. Use this when somebody has lost their phone.', 'vulnhub' ),
								esc_html( $vh_mfa['enrolled_at'] ? vh_ago( (string) $vh_mfa['enrolled_at'] ) : __( 'at some point', 'vulnhub' ) ),
								(int) $vh_mfa['recovery'],
								(int) $vh_mfa['devices']
							);
							?>
						</span>
					<?php endif; ?>
				</td>
			</tr>
		</table>
	</div>

<?php else : ?>

	<!-- ------------------------------------------------------- add a person -->
	<form method="post" action="<?php echo esc_url( VulnHub_Auth_People::section_url() ); ?>" class="vh-form">
		<?php wp_nonce_field( VulnHub_Auth_People::NONCE_ACTION, VulnHub_Auth_People::NONCE_FIELD ); ?>
		<input type="hidden" name="vh_people_action" value="create">

		<h2 style="margin-top:14px"><?php esc_html_e( 'Add someone', 'vulnhub' ); ?></h2>
		<p class="vh-field-help">
			<?php esc_html_e( 'They receive an email with a one-time link and choose their own password — no password is ever set on their behalf, and none is shown to you. Title, team and phone can be filled in afterwards.', 'vulnhub' ); ?>
		</p>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="vh-new-email"><?php esc_html_e( 'Email address', 'vulnhub' ); ?></label></th>
				<td>
					<input type="email" id="vh-new-email" name="email" class="regular-text" required
						placeholder="analyst@<?php echo esc_attr( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ); ?>">
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-new-name"><?php esc_html_e( 'Full name', 'vulnhub' ); ?></label></th>
				<td>
					<input type="text" id="vh-new-name" name="display_name" class="regular-text">
					<span class="vh-field-help"><?php esc_html_e( 'Shown against their triage decisions and exception approvals.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-new-user"><?php esc_html_e( 'Username', 'vulnhub' ); ?></label></th>
				<td>
					<input type="text" id="vh-new-user" name="username" class="regular-text" autocomplete="off">
					<span class="vh-field-help"><?php esc_html_e( 'Optional. Left blank, the part of the email before the @ is used, with a number appended if it is taken. It cannot be changed afterwards.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-new-role"><?php esc_html_e( 'Role', 'vulnhub' ); ?></label></th>
				<td>
					<select id="vh-new-role" name="role" required>
						<?php foreach ( $vh_roles as $vh_slug => $vh_label ) : ?>
							<option value="<?php echo esc_attr( $vh_slug ); ?>" <?php selected( $vh_slug, 'vulnhub_viewer' ); ?>>
								<?php echo esc_html( $vh_label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
					<span class="vh-field-help">
						<?php esc_html_e( 'A VulnHub role grants nothing in WordPress: whichever you choose, this person can only ever reach the portal.', 'vulnhub' ); ?>
					</span>
				</td>
			</tr>
		</table>

		<p><button type="submit" class="button button-primary"><?php esc_html_e( 'Create account and send invitation', 'vulnhub' ); ?></button></p>
	</form>

<?php endif; ?>

<!-- --------------------------------------------------------------- the list -->
<div class="vh-panel" style="margin-top:20px">
	<div class="vh-panel__head">
		<h2><?php esc_html_e( 'Portal accounts', 'vulnhub' ); ?></h2>
		<p class="vh-sub">
			<?php
			printf(
				/* translators: %d: number of accounts. */
				esc_html( _n( '%d account.', '%d accounts.', count( $vh_users ), 'vulnhub' ) ),
				count( $vh_users )
			);
			?>
		</p>
	</div>

	<?php if ( ! $vh_users ) : ?>
		<div class="vh-empty">
			<h2><?php esc_html_e( 'Nobody yet', 'vulnhub' ); ?></h2>
			<p><?php esc_html_e( 'Add the first person above. Single sign-on, once configured, will also create accounts on first login.', 'vulnhub' ); ?></p>
		</div>
	<?php else : ?>
		<div style="overflow-x:auto">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Person', 'vulnhub' ); ?></th>
						<th style="width:190px"><?php esc_html_e( 'Role', 'vulnhub' ); ?></th>
						<th style="width:110px"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
						<th style="width:90px"><?php esc_html_e( 'MFA', 'vulnhub' ); ?></th>
						<th style="width:280px"></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_users as $vh_u ) : ?>
					<?php
					$vh_row_susp = VulnHub_Auth_People::is_suspended( $vh_u );
					$vh_invited  = VulnHub_Auth_People::is_invited( $vh_u );
					$vh_role     = VulnHub_Auth_People::role_of( $vh_u );
					$vh_self     = ( (int) $vh_u->ID === $vh_me );
					$vh_prof     = VulnHub_Auth_People::profile( $vh_u );
					$vh_row_mfa  = VulnHub_Auth_People::mfa( $vh_u );
					$vh_edit_url = VulnHub_Auth_People::section_url( array( 'vh_edit' => (string) $vh_u->ID ) );

					$vh_meta = array_filter(
						array(
							$vh_prof['title'],
							$vh_teams[ $vh_prof['team_id'] ] ?? '',
						)
					);
					?>
					<tr>
						<td>
							<strong><a href="<?php echo esc_url( $vh_edit_url ); ?>"><?php echo esc_html( $vh_u->display_name ); ?></a></strong>
							<?php if ( $vh_self ) : ?>
								<span class="vh-muted">&nbsp;<?php esc_html_e( '(you)', 'vulnhub' ); ?></span>
							<?php endif; ?>
							<div class="vh-muted" style="font-size:11.5px">
								<?php echo esc_html( $vh_u->user_email ); ?>
								<?php if ( $vh_meta ) : ?>
									&middot; <?php echo esc_html( implode( ' · ', $vh_meta ) ); ?>
								<?php endif; ?>
							</div>
						</td>

						<td><?php echo esc_html( $vh_roles[ $vh_role ] ?? __( 'No role', 'vulnhub' ) ); ?></td>

						<td>
							<?php if ( $vh_row_susp ) : ?>
								<span class="vh-chip vh-chip--bad"><?php esc_html_e( 'Suspended', 'vulnhub' ); ?></span>
							<?php elseif ( $vh_invited ) : ?>
								<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Invited', 'vulnhub' ); ?></span>
							<?php else : ?>
								<span class="vh-chip vh-chip--good"><?php esc_html_e( 'Active', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>

						<td>
							<?php
							echo ! empty( $vh_row_mfa['enabled'] )
								? esc_html__( 'On', 'vulnhub' )
								: '<span class="vh-muted">—</span>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							?>
						</td>

						<td>
							<div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">
								<a class="button button-small" href="<?php echo esc_url( $vh_edit_url ); ?>"><?php esc_html_e( 'Edit', 'vulnhub' ); ?></a>

								<form method="post" action="<?php echo esc_url( VulnHub_Auth_People::section_url() ); ?>">
									<?php wp_nonce_field( VulnHub_Auth_People::NONCE_ACTION, VulnHub_Auth_People::NONCE_FIELD ); ?>
									<input type="hidden" name="vh_people_action" value="<?php echo $vh_row_susp ? 'reactivate' : 'suspend'; ?>">
									<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $vh_u->ID ); ?>">
									<button type="submit" class="button button-small" <?php disabled( $vh_self && ! $vh_row_susp ); ?>>
										<?php echo $vh_row_susp ? esc_html__( 'Reactivate', 'vulnhub' ) : esc_html__( 'Suspend', 'vulnhub' ); ?>
									</button>
								</form>

								<form method="post" action="<?php echo esc_url( VulnHub_Auth_People::section_url() ); ?>"
									onsubmit="return confirm('<?php echo esc_js( sprintf( /* translators: %s: username. */ __( 'Delete %s permanently? Their name will disappear from past triage decisions and approvals. Suspending keeps that history.', 'vulnhub' ), $vh_u->display_name ) ); ?>');">
									<?php wp_nonce_field( VulnHub_Auth_People::NONCE_ACTION, VulnHub_Auth_People::NONCE_FIELD ); ?>
									<input type="hidden" name="vh_people_action" value="delete">
									<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $vh_u->ID ); ?>">
									<input type="hidden" name="confirm" value="delete">
									<button type="submit" class="button button-small" <?php disabled( $vh_self ); ?>>
										<?php esc_html_e( 'Delete', 'vulnhub' ); ?>
									</button>
								</form>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
</div>

<p class="vh-sub vh-sub--foot">
	<?php
	if ( $vh_hidden > 0 ) {
		printf(
			/* translators: %d: number of WordPress administrator accounts. */
			esc_html( _n( '%d WordPress administrator account is not listed here and cannot be managed from the portal.', '%d WordPress administrator accounts are not listed here and cannot be managed from the portal.', $vh_hidden, 'vulnhub' ) ),
			(int) $vh_hidden
		);
		echo ' ';
	}
	esc_html_e( 'Suspending ends every session immediately and blocks sign-in, but keeps the person\'s history. Deleting does not.', 'vulnhub' );
	?>
</p>

