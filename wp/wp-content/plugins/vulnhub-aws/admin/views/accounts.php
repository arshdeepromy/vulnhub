<?php
/**
 * Cloud connectors: the list first, then a way to add one.
 *
 * The list leads because that is the question somebody arrives with -- which
 * of these is importing, which is broken -- and a form at the top of the page
 * answers a question they only ask twice a year. Adding is a button and a
 * dialog.
 *
 * @package VulnHub\AWS
 *
 * @var array{text:string,tone:string}|null    $notice
 * @var array<int,array<string,mixed>>         $accounts
 * @var array<string,int>                      $summary
 * @var array<string,string>                   $types
 * @var array<string,mixed>|null               $edit
 * @var array<int,array<string,mixed>>         $found
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_regions = implode( ', ', VulnHub_AWS_Setup::suggested_regions() );

// Open the dialog on load when a form was being edited, or ?add=1 was used --
// which is also what makes the button work with no JavaScript.
$vh_open = $edit || isset( $_GET['add'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
?>

<?php if ( $notice ) : ?>
	<div class="vh-notice vh-notice--<?php echo esc_attr( $notice['tone'] ); ?>">
		<?php echo esc_html( $notice['text'] ); ?>
	</div>
<?php endif; ?>

<div class="vh-aws-accounts">

	<div class="vh-cc__bar">
		<div class="vh-cc__search">
			<input type="search" id="vh-cc-search" data-vh-filter="vh-cc-table"
				placeholder="<?php esc_attr_e( 'Search name, account or region…', 'vulnhub' ); ?>"
				aria-label="<?php esc_attr_e( 'Search connectors', 'vulnhub' ); ?>">
			<span class="vh-cc__count" data-vh-filter-count><?php
				printf(
					/* translators: %s: number of connectors. */
					esc_html( _n( '%s connector', '%s connectors', count( $accounts ), 'vulnhub' ) ),
					esc_html( number_format_i18n( count( $accounts ) ) )
				);
			?></span>
		</div>

		<div class="vh-cc__tally">
			<span><strong><?php echo esc_html( number_format_i18n( $summary['ok'] ) ); ?></strong> <?php esc_html_e( 'importing', 'vulnhub' ); ?></span>
			<span class="<?php echo $summary['failed'] ? 'is-bad' : ''; ?>"><strong><?php echo esc_html( number_format_i18n( $summary['failed'] ) ); ?></strong> <?php esc_html_e( 'error', 'vulnhub' ); ?></span>
			<span><strong><?php echo esc_html( number_format_i18n( $summary['never'] ) ); ?></strong> <?php esc_html_e( 'pending', 'vulnhub' ); ?></span>
		</div>

		<a class="vh-btn vh-btn--primary vh-cc__add" href="<?php echo esc_url( add_query_arg( 'add', 1 ) ); ?>" data-vh-dialog="vh-cc-dialog">
			<?php esc_html_e( '+ Add connector', 'vulnhub' ); ?>
		</a>
	</div>

	<?php if ( ! $accounts ) : ?>
		<div class="vh-card">
			<p class="vh-chart-empty"><?php esc_html_e( 'No cloud connectors yet.', 'vulnhub' ); ?></p>
		</div>
	<?php else : ?>
		<div class="vh-tablewrap">
			<table class="vh-table vh-cc-table" id="vh-cc-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Name', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'What it read', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Added', 'vulnhub' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $accounts as $vh_a ) : ?>
					<?php
					$vh_stats  = (array) $vh_a['stats'];
					$vh_denied = (array) ( $vh_stats['denied'] ?? array() );

					/*
					 * Four states, because "enabled but never run" and
					 * "enabled and failing" call for different actions and a
					 * single ok/not-ok flag cannot tell them apart.
					 */
					if ( ! $vh_a['enabled'] ) {
						$vh_state = 'paused';
						$vh_word  = __( 'Paused', 'vulnhub' );
					} elseif ( 'failed' === (string) $vh_a['last_status'] ) {
						$vh_state = 'bad';
						$vh_word  = __( 'Error', 'vulnhub' );
					} elseif ( 'ok' === (string) $vh_a['last_status'] ) {
						$vh_state = 'good';
						$vh_word  = __( 'Importing', 'vulnhub' );
					} else {
						$vh_state = 'off';
						$vh_word  = __( 'Pending', 'vulnhub' );
					}
					?>
					<tr data-vh-row="<?php echo esc_attr( strtolower( $vh_a['label'] . ' ' . $vh_a['account_id'] . ' ' . $vh_a['regions'] ) ); ?>">
						<td>
							<strong><?php echo esc_html( (string) $vh_a['label'] ?: (string) $vh_a['account_id'] ); ?></strong>
							<span class="vh-meta vh-mono"><?php echo esc_html( (string) $vh_a['account_id'] ); ?> · <?php echo esc_html( (string) $vh_a['regions'] ?: '—' ); ?></span>
						</td>

						<td>
							<span class="vh-mono vh-cc__type">
								<?php echo 'role' === (string) $vh_a['auth_mode'] ? 'AWS_ROLE' : 'AWS_KEYS'; ?>
							</span>
						</td>

						<td>
							<span class="vh-health vh-health--<?php echo esc_attr( $vh_state ); ?>"><?php echo esc_html( $vh_word ); ?></span>
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

								<?php if ( 'ok' === (string) $vh_a['last_status'] && 0 === (int) ( $vh_stats['instances'] ?? 0 ) ) : ?>
									<p class="vh-meta vh-aws-empty">
										<?php esc_html_e( 'Connected, but no EC2 instances in the regions checked. Nothing is wrong — check this is the account the machines are in.', 'vulnhub' ); ?>
									</p>
								<?php endif; ?>
							<?php endif; ?>
						</td>

						<td class="vh-meta">
							<?php echo esc_html( mb_substr( (string) $vh_a['created_at'], 0, 10 ) ); ?>
						</td>

						<td class="vh-aws-actions">
							<form method="post">
								<?php VulnHub_AWS_Admin::nonce_field(); ?>
								<input type="hidden" name="id" value="<?php echo esc_attr( (string) $vh_a['id'] ); ?>">
								<button class="vh-btn" name="vh_action" value="test"><?php esc_html_e( 'Sync', 'vulnhub' ); ?></button>
							</form>
							<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( add_query_arg( 'edit', (int) $vh_a['id'] ) ); ?>"><?php esc_html_e( 'Edit', 'vulnhub' ); ?></a>
							<form method="post" onsubmit="return confirm('<?php echo esc_js( __( 'Remove this connector?', 'vulnhub' ) ); ?>');">
								<?php VulnHub_AWS_Admin::nonce_field(); ?>
								<input type="hidden" name="id" value="<?php echo esc_attr( (string) $vh_a['id'] ); ?>">
								<button class="vh-btn vh-btn--ghost" name="vh_action" value="delete"><?php esc_html_e( 'Remove', 'vulnhub' ); ?></button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<p class="vh-cc__none" data-vh-filter-empty hidden><?php esc_html_e( 'Nothing matches that search.', 'vulnhub' ); ?></p>
		</div>
	<?php endif; ?>

	<?php // ------------------------------------------------ the add dialog. ?>
	<dialog id="vh-cc-dialog" class="vh-modal" <?php echo $vh_open ? 'open' : ''; ?>>
		<form method="dialog" class="vh-modal__x">
			<button aria-label="<?php esc_attr_e( 'Close', 'vulnhub' ); ?>">&times;</button>
		</form>

		<h2><?php echo $edit ? esc_html__( 'Edit connector', 'vulnhub' ) : esc_html__( 'Add a cloud connector', 'vulnhub' ); ?></h2>

		<?php if ( $found && ! $edit ) : ?>
			<?php
			/*
			 * The accounts our own inventory already points at, offered before
			 * the empty form. Typing an account number from memory is how
			 * somebody ends up connecting the account they sign in to -- an
			 * SSO or management account with nothing in it -- and reading a
			 * successful sync of zero instances as a broken connector.
			 */
			?>
			<details class="vh-modal__found" open>
				<summary>
					<strong><?php esc_html_e( 'Accounts your assets are already in', 'vulnhub' ); ?></strong>
					<?php
					printf(
						/* translators: 1: accounts, 2: assets. */
						esc_html__( ' — %1$d accounts holding %2$d machines you already track', 'vulnhub' ),
						count( $found ),
						array_sum( array_column( $found, 'assets' ) )
					);
					?>
				</summary>

				<form method="post">
					<?php VulnHub_AWS_Admin::nonce_field(); ?>
					<input type="hidden" name="vh_action" value="add_discovered">

					<ul class="vh-aws-found-list">
						<?php foreach ( $found as $vh_f ) : ?>
							<li>
								<label>
									<input type="checkbox" name="accounts[]" value="<?php echo esc_attr( (string) $vh_f['account_id'] ); ?>" checked>
									<span class="vh-mono"><?php echo esc_html( (string) $vh_f['account_id'] ); ?></span>
									<em><?php echo esc_html( (string) $vh_f['regions'] ); ?></em>
									<strong><?php echo esc_html( sprintf( /* translators: %s: asset count. */ _n( '%s asset', '%s assets', (int) $vh_f['assets'], 'vulnhub' ), number_format_i18n( (int) $vh_f['assets'] ) ) ); ?></strong>
								</label>
							</li>
						<?php endforeach; ?>
					</ul>

					<input type="hidden" name="discover_auth_mode" value="role">
					<?php submit_button( __( 'Add these', 'vulnhub' ), 'primary', 'submit', false ); ?>
				</form>
			</details>
		<?php endif; ?>

		<form method="post" class="vh-aws-one">
			<?php VulnHub_AWS_Admin::nonce_field(); ?>
			<input type="hidden" name="vh_action" value="save">
			<input type="hidden" name="id" value="<?php echo esc_attr( (string) ( $edit['id'] ?? 0 ) ); ?>">

			<div class="vh-aws-grid">
				<label>
					<span><?php esc_html_e( 'Connector name', 'vulnhub' ); ?></span>
					<input type="text" name="label" placeholder="<?php esc_attr_e( 'bc-au-gas-prod', 'vulnhub' ); ?>"
						value="<?php echo esc_attr( (string) ( $edit['label'] ?? '' ) ); ?>">
				</label>

				<label>
					<span><?php esc_html_e( 'Account ID', 'vulnhub' ); ?> *</span>
					<input type="text" name="account_id" required inputmode="numeric" placeholder="123456789012"
						value="<?php echo esc_attr( (string) ( $edit['account_id'] ?? '' ) ); ?>">
				</label>

				<label>
					<span><?php esc_html_e( 'Regions', 'vulnhub' ); ?></span>
					<input type="text" name="regions" placeholder="<?php echo esc_attr( $vh_regions ); ?>"
						value="<?php echo esc_attr( (string) ( $edit['regions'] ?? $vh_regions ) ); ?>">
				</label>

				<label>
					<span><?php esc_html_e( 'Type', 'vulnhub' ); ?></span>
					<select name="auth_mode" data-vh-aws-mode>
						<option value="role" <?php selected( (string) ( $edit['auth_mode'] ?? 'role' ), 'role' ); ?>>AWS_ROLE — <?php esc_html_e( 'assume a role', 'vulnhub' ); ?></option>
						<option value="keys" <?php selected( (string) ( $edit['auth_mode'] ?? 'role' ), 'keys' ); ?>>AWS_KEYS — <?php esc_html_e( 'its own access key', 'vulnhub' ); ?></option>
					</select>
				</label>
			</div>

			<fieldset class="vh-aws-mode vh-aws-mode--role">
				<legend><?php esc_html_e( 'Role', 'vulnhub' ); ?></legend>
				<p class="vh-field-help">
					<?php
					printf(
						/* translators: %s: default role name. */
						esc_html__( 'Blank uses arn:aws:iam::<account>:role/%s. The connector signs in with its own credentials and borrows this role, so nothing long-lived is stored per account.', 'vulnhub' ),
						esc_html( VulnHub_AWS_Connector::DEFAULT_ROLE )
					);
					?>
				</p>
				<div class="vh-aws-grid">
					<label>
						<span><?php esc_html_e( 'Role ARN', 'vulnhub' ); ?></span>
						<input type="text" name="role_arn" value="<?php echo esc_attr( (string) ( $edit['role_arn'] ?? '' ) ); ?>"
							placeholder="arn:aws:iam::123456789012:role/<?php echo esc_attr( VulnHub_AWS_Connector::DEFAULT_ROLE ); ?>">
					</label>
					<label>
						<span><?php esc_html_e( 'External ID', 'vulnhub' ); ?></span>
						<input type="text" name="external_id" value="<?php echo esc_attr( (string) ( $edit['external_id'] ?? '' ) ); ?>"
							placeholder="<?php esc_attr_e( 'only if the trust policy requires one', 'vulnhub' ); ?>">
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
							placeholder="<?php echo $edit && VulnHub_AWS_Accounts::has_secret( (int) $edit['id'], 'secret' ) ? esc_attr__( 'stored — blank keeps it', 'vulnhub' ) : ''; ?>">
					</label>
					<label class="vh-aws-wide">
						<span><?php esc_html_e( 'Session token', 'vulnhub' ); ?></span>
						<input type="password" name="session_token" autocomplete="new-password"
							placeholder="<?php esc_attr_e( 'required for a short-term ASIA… key', 'vulnhub' ); ?>">
					</label>
				</div>
			</fieldset>

			<p>
				<label>
					<input type="checkbox" name="enabled" value="1" <?php checked( $edit ? (bool) $edit['enabled'] : true ); ?>>
					<?php esc_html_e( 'Import on the connector schedule', 'vulnhub' ); ?>
				</label>
			</p>

			<div class="vh-modal__foot">
				<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( remove_query_arg( array( 'add', 'edit' ) ) ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
				<?php submit_button( $edit ? __( 'Save', 'vulnhub' ) : __( 'Add connector', 'vulnhub' ), 'primary', 'submit', false ); ?>
			</div>
		</form>

		<details class="vh-modal__bulk">
			<summary><?php esc_html_e( 'Or paste a list of account numbers', 'vulnhub' ); ?></summary>
			<form method="post">
				<?php VulnHub_AWS_Admin::nonce_field(); ?>
				<input type="hidden" name="vh_action" value="bulk_add">
				<p class="vh-field-help"><?php esc_html_e( 'One per line. A name after a comma is optional.', 'vulnhub' ); ?></p>
				<textarea name="bulk" rows="6" class="large-text code" placeholder="123456789012, Production&#10;210987654321, Staging"></textarea>
				<input type="hidden" name="bulk_regions" value="<?php echo esc_attr( $vh_regions ); ?>">
				<input type="hidden" name="bulk_auth_mode" value="role">
				<?php submit_button( __( 'Add them', 'vulnhub' ), 'secondary', 'submit', false ); ?>
			</form>
		</details>
	</dialog>
</div>
