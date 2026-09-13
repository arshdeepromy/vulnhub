<?php
/**
 * The AWS accounts screen.
 *
 * @package VulnHub\AWS
 *
 * @var array{text:string,tone:string}|null    $notice
 * @var array<int,array<string,mixed>>         $accounts
 * @var array<string,int>                      $summary
 * @var array<string,string>                   $types
 * @var array<string,mixed>|null               $edit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_regions = implode( ', ', VulnHub_AWS_Setup::suggested_regions() );
?>

<?php if ( $notice ) : ?>
	<div class="vh-notice vh-notice--<?php echo esc_attr( $notice['tone'] ); ?>">
		<?php echo esc_html( $notice['text'] ); ?>
	</div>
<?php endif; ?>

<div class="vh-aws-accounts">

	<ul class="vh-aws-tally">
		<li><strong><?php echo esc_html( number_format_i18n( $summary['total'] ) ); ?></strong> <?php esc_html_e( 'accounts', 'vulnhub' ); ?></li>
		<li><strong><?php echo esc_html( number_format_i18n( $summary['ok'] ) ); ?></strong> <?php esc_html_e( 'read cleanly', 'vulnhub' ); ?></li>
		<li class="<?php echo $summary['failed'] ? 'is-bad' : ''; ?>"><strong><?php echo esc_html( number_format_i18n( $summary['failed'] ) ); ?></strong> <?php esc_html_e( 'failed', 'vulnhub' ); ?></li>
		<li><strong><?php echo esc_html( number_format_i18n( $summary['never'] ) ); ?></strong> <?php esc_html_e( 'never run', 'vulnhub' ); ?></li>
	</ul>

	<?php /* Adding fifty-eight accounts one form at a time is fifty-eight page
	         loads, and the numbers always already exist as a list somewhere. */ ?>
	<details class="vh-card vh-aws-bulk" <?php echo $accounts ? '' : 'open'; ?>>
		<summary><strong><?php esc_html_e( 'Add accounts in bulk', 'vulnhub' ); ?></strong> — <?php esc_html_e( 'paste a list of account numbers', 'vulnhub' ); ?></summary>

		<form method="post">
			<?php VulnHub_AWS_Admin::nonce_field(); ?>
			<input type="hidden" name="vh_action" value="bulk_add">

			<p class="vh-field-help">
				<?php esc_html_e( 'One account per line. A name after a comma is optional — “123456789012, Production” works, and so does the account number on its own.', 'vulnhub' ); ?>
			</p>

			<textarea name="bulk" rows="8" class="large-text code" placeholder="123456789012, Production&#10;210987654321, Staging&#10;345678901234"></textarea>

			<p>
				<label>
					<?php esc_html_e( 'Regions', 'vulnhub' ); ?>
					<input type="text" name="bulk_regions" value="<?php echo esc_attr( $vh_regions ); ?>" class="regular-text">
				</label>
			</p>

			<p>
				<label>
					<input type="radio" name="bulk_auth_mode" value="role" checked>
					<?php esc_html_e( 'Assume a read-only role in each account (recommended — no credentials to store or rotate)', 'vulnhub' ); ?>
				</label><br>
				<label>
					<input type="radio" name="bulk_auth_mode" value="keys">
					<?php esc_html_e( 'Each account has its own access key (added per account afterwards)', 'vulnhub' ); ?>
				</label>
			</p>

			<?php submit_button( __( 'Add these accounts', 'vulnhub' ), 'primary', 'submit', false ); ?>
		</form>
	</details>

	<div class="vh-card">
		<h2><?php echo $edit ? esc_html__( 'Edit account', 'vulnhub' ) : esc_html__( 'Add one account', 'vulnhub' ); ?></h2>

		<form method="post" class="vh-aws-one">
			<?php VulnHub_AWS_Admin::nonce_field(); ?>
			<input type="hidden" name="vh_action" value="save">
			<input type="hidden" name="id" value="<?php echo esc_attr( (string) ( $edit['id'] ?? 0 ) ); ?>">

			<div class="vh-aws-grid">
				<label>
					<span><?php esc_html_e( 'Account ID', 'vulnhub' ); ?></span>
					<input type="text" name="account_id" required inputmode="numeric" placeholder="123456789012"
						value="<?php echo esc_attr( (string) ( $edit['account_id'] ?? '' ) ); ?>">
				</label>

				<label>
					<span><?php esc_html_e( 'Name', 'vulnhub' ); ?></span>
					<input type="text" name="label" placeholder="<?php esc_attr_e( 'Production, Shared services…', 'vulnhub' ); ?>"
						value="<?php echo esc_attr( (string) ( $edit['label'] ?? '' ) ); ?>">
				</label>

				<label>
					<span><?php esc_html_e( 'Regions', 'vulnhub' ); ?></span>
					<input type="text" name="regions" placeholder="<?php echo esc_attr( $vh_regions ); ?>"
						value="<?php echo esc_attr( (string) ( $edit['regions'] ?? '' ) ); ?>">
				</label>

				<label>
					<span><?php esc_html_e( 'How to reach it', 'vulnhub' ); ?></span>
					<select name="auth_mode" data-vh-aws-mode>
						<option value="role" <?php selected( (string) ( $edit['auth_mode'] ?? 'role' ), 'role' ); ?>>
							<?php esc_html_e( 'Assume a role (recommended)', 'vulnhub' ); ?>
						</option>
						<option value="keys" <?php selected( (string) ( $edit['auth_mode'] ?? 'role' ), 'keys' ); ?>>
							<?php esc_html_e( 'Its own access key', 'vulnhub' ); ?>
						</option>
					</select>
				</label>
			</div>

			<fieldset class="vh-aws-mode vh-aws-mode--role">
				<legend><?php esc_html_e( 'Role details', 'vulnhub' ); ?></legend>
				<p class="vh-field-help">
					<?php
					printf(
						/* translators: %s: default role name. */
						esc_html__( 'Leave the ARN blank to use arn:aws:iam::<account>:role/%s. The connector signs in with its own credentials and borrows this role in the target account, so nothing long-lived is stored per account.', 'vulnhub' ),
						esc_html( VulnHub_AWS_Connector::DEFAULT_ROLE )
					);
					?>
				</p>
				<div class="vh-aws-grid">
					<label>
						<span><?php esc_html_e( 'Role ARN', 'vulnhub' ); ?></span>
						<input type="text" name="role_arn" placeholder="arn:aws:iam::123456789012:role/<?php echo esc_attr( VulnHub_AWS_Connector::DEFAULT_ROLE ); ?>"
							value="<?php echo esc_attr( (string) ( $edit['role_arn'] ?? '' ) ); ?>">
					</label>
					<label>
						<span><?php esc_html_e( 'External ID', 'vulnhub' ); ?></span>
						<input type="text" name="external_id" value="<?php echo esc_attr( (string) ( $edit['external_id'] ?? '' ) ); ?>"
							placeholder="<?php esc_attr_e( 'only if the role’s trust policy requires one', 'vulnhub' ); ?>">
					</label>
				</div>
			</fieldset>

			<fieldset class="vh-aws-mode vh-aws-mode--keys">
				<legend><?php esc_html_e( 'Access key', 'vulnhub' ); ?></legend>
				<div class="vh-aws-grid">
					<label>
						<span><?php esc_html_e( 'Access key ID', 'vulnhub' ); ?></span>
						<input type="text" name="access_key_id" placeholder="AKIA… or ASIA…"
							value="<?php echo esc_attr( (string) ( $edit['access_key_id'] ?? '' ) ); ?>">
					</label>
					<label>
						<span><?php esc_html_e( 'Secret access key', 'vulnhub' ); ?></span>
						<input type="password" name="secret_access_key" autocomplete="new-password"
							placeholder="<?php echo $edit && VulnHub_AWS_Accounts::has_secret( (int) $edit['id'], 'secret' ) ? esc_attr__( 'stored — leave blank to keep', 'vulnhub' ) : ''; ?>">
					</label>
					<label class="vh-aws-wide">
						<span><?php esc_html_e( 'Session token', 'vulnhub' ); ?></span>
						<input type="password" name="session_token" autocomplete="new-password"
							placeholder="<?php esc_attr_e( 'required only for a short-term ASIA… key', 'vulnhub' ); ?>">
					</label>
				</div>
			</fieldset>

			<p>
				<label>
					<input type="checkbox" name="enabled" value="1" <?php checked( $edit ? (bool) $edit['enabled'] : true ); ?>>
					<?php esc_html_e( 'Include this account in scheduled syncs', 'vulnhub' ); ?>
				</label>
			</p>

			<?php submit_button( $edit ? __( 'Save account', 'vulnhub' ) : __( 'Add account', 'vulnhub' ), 'primary', 'submit', false ); ?>
			<?php if ( $edit ) : ?>
				<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( remove_query_arg( 'edit' ) ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
			<?php endif; ?>
		</form>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Accounts', 'vulnhub' ); ?></h2>

		<?php if ( ! $accounts ) : ?>
			<p class="vh-chart-empty"><?php esc_html_e( 'No accounts yet. Add one above, or paste a list.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<div class="vh-tablewrap">
				<table class="vh-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Account', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Reached by', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Last sync', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'What it read', 'vulnhub' ); ?></th>
							<th></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $accounts as $vh_a ) : ?>
						<?php
						$vh_stats  = (array) $vh_a['stats'];
						$vh_denied = (array) ( $vh_stats['denied'] ?? array() );
						?>
						<tr class="<?php echo $vh_a['enabled'] ? '' : 'is-off'; ?>">
							<td>
								<strong class="vh-mono"><?php echo esc_html( (string) $vh_a['account_id'] ); ?></strong>
								<span class="vh-meta">
									<?php echo esc_html( (string) $vh_a['label'] ?: '—' ); ?>
									<?php if ( ! $vh_a['enabled'] ) : ?>
										· <?php esc_html_e( 'not scheduled', 'vulnhub' ); ?>
									<?php endif; ?>
								</span>
							</td>

							<td>
								<?php if ( 'role' === (string) $vh_a['auth_mode'] ) : ?>
									<?php esc_html_e( 'assumed role', 'vulnhub' ); ?>
									<span class="vh-meta"><?php echo esc_html( (string) $vh_a['role_arn'] ?: VulnHub_AWS_Connector::DEFAULT_ROLE ); ?></span>
								<?php else : ?>
									<?php esc_html_e( 'access key', 'vulnhub' ); ?>
									<span class="vh-meta"><?php echo esc_html( (string) $vh_a['access_key_id'] ?: '—' ); ?></span>
								<?php endif; ?>
							</td>

							<td>
								<span class="vh-health vh-health--<?php echo esc_attr( 'ok' === $vh_a['last_status'] ? 'good' : ( 'failed' === $vh_a['last_status'] ? 'bad' : 'off' ) ); ?>">
									<?php echo esc_html( (string) $vh_a['last_status'] ); ?>
								</span>
								<span class="vh-meta">
									<?php
									echo 'never' === (string) $vh_a['last_status']
										? esc_html__( 'not yet run', 'vulnhub' )
										: esc_html( sprintf( /* translators: %s: relative time. */ __( '%s ago', 'vulnhub' ), human_time_diff( (int) strtotime( (string) $vh_a['last_sync_at'] . ' UTC' ) ) ) );
									?>
								</span>
							</td>

							<td>
								<?php if ( ! $vh_stats ) : ?>
									<span class="vh-meta">—</span>
								<?php else : ?>
									<ul class="vh-aws-read">
										<?php foreach ( $types as $vh_k => $vh_label ) : ?>
											<?php
											if ( 'inspector' === $vh_k ) {
												$vh_val = (string) ( $vh_stats['inspector'] ?? '' );

												if ( '' === $vh_val ) {
													continue;
												}

												printf(
													'<li class="%s"><span>%s</span><em>%s</em></li>',
													'denied' === $vh_val ? 'is-denied' : '',
													esc_html( $vh_label ),
													esc_html( $vh_val )
												);
												continue;
											}

											if ( isset( $vh_denied[ $vh_k ] ) ) {
												printf(
													'<li class="is-denied"><span>%s</span><em>%s</em></li>',
													esc_html( $vh_label ),
													esc_html__( 'not permitted', 'vulnhub' )
												);
												continue;
											}

											if ( ! isset( $vh_stats[ $vh_k ] ) ) {
												continue;
											}

											printf(
												'<li><span>%s</span><em>%s</em></li>',
												esc_html( $vh_label ),
												esc_html( number_format_i18n( (int) $vh_stats[ $vh_k ] ) )
											);
											?>
										<?php endforeach; ?>
									</ul>
									<?php if ( (string) $vh_a['last_message'] !== '' && 'ok' !== (string) $vh_a['last_status'] ) : ?>
										<p class="vh-meta vh-aws-err"><?php echo esc_html( (string) $vh_a['last_message'] ); ?></p>
									<?php endif; ?>
								<?php endif; ?>
							</td>

							<td class="vh-aws-actions">
								<form method="post">
									<?php VulnHub_AWS_Admin::nonce_field(); ?>
									<input type="hidden" name="id" value="<?php echo esc_attr( (string) $vh_a['id'] ); ?>">
									<button class="vh-btn" name="vh_action" value="test"><?php esc_html_e( 'Read now', 'vulnhub' ); ?></button>
								</form>
								<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( add_query_arg( 'edit', (int) $vh_a['id'] ) ); ?>"><?php esc_html_e( 'Edit', 'vulnhub' ); ?></a>
								<form method="post" onsubmit="return confirm('<?php echo esc_js( __( 'Remove this account?', 'vulnhub' ) ); ?>');">
									<?php VulnHub_AWS_Admin::nonce_field(); ?>
									<input type="hidden" name="id" value="<?php echo esc_attr( (string) $vh_a['id'] ); ?>">
									<button class="vh-btn vh-btn--ghost" name="vh_action" value="delete"><?php esc_html_e( 'Remove', 'vulnhub' ); ?></button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>
</div>
