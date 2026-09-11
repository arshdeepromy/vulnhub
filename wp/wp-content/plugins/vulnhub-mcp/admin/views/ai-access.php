<?php
/**
 * AI access — connect an assistant to VulnHub.
 *
 * @package VulnHub\MCP
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only view state.
$vh_notice = isset( $_GET['vh_notice'] ) ? sanitize_key( wp_unslash( $_GET['vh_notice'] ) ) : '';
// phpcs:enable

$vh_me       = wp_get_current_user();
$vh_endpoint = VulnHub_MCP_Admin::endpoint();
$vh_fresh    = VulnHub_MCP_Admin::fresh_token();
$vh_mine     = VulnHub_MCP_Tokens::for_user( (int) $vh_me->ID );
$vh_is_admin = current_user_can( Caps::MANAGE );
$vh_tools    = VulnHub_MCP_Tools::available();
$vh_all      = VulnHub_MCP_Tools::all();

// What this person's role actually unlocks, in their own words.
$vh_caps = array();
foreach ( Caps::all() as $vh_cap => $vh_label ) {
	if ( current_user_can( $vh_cap ) ) {
		$vh_caps[] = $vh_label;
	}
}
?>

<?php if ( 'revoked' === $vh_notice ) : ?>
	<p class="vh-flash vh-flash--good"><?php esc_html_e( 'Token revoked. Anything using it stops working immediately.', 'vulnhub' ); ?></p>
<?php endif; ?>

<?php if ( $vh_fresh ) : ?>
	<?php
	$vh_desktop_config = wp_json_encode(
		array(
			'mcpServers' => array(
				'vulnhub' => array(
					'command' => 'npx',
					'args'    => array(
						'-y',
						'mcp-remote',
						$vh_endpoint,
						'--header',
						'Authorization: Bearer ' . $vh_fresh['token'],
					),
				),
			),
		),
		JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
	);
	?>
	<div class="vh-form" style="border-left:3px solid var(--vh-good);margin-bottom:18px">
		<h2 style="margin-top:14px"><?php esc_html_e( 'Your connector token', 'vulnhub' ); ?></h2>
		<p class="vh-warn-note">
			<?php esc_html_e( 'This is the only time it will be shown. Copy it now — it is stored hashed, so nobody, including an administrator, can read it back. If you lose it, revoke it and make another.', 'vulnhub' ); ?>
		</p>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Token', 'vulnhub' ); ?></th>
				<td><input type="text" class="large-text vh-mono" readonly onclick="this.select()"
					value="<?php echo esc_attr( $vh_fresh['token'] ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Server URL', 'vulnhub' ); ?></th>
				<td><input type="text" class="large-text vh-mono" readonly onclick="this.select()"
					value="<?php echo esc_attr( $vh_endpoint ); ?>"></td>
			</tr>
		</table>

		<?php if ( 'claude' === $vh_fresh['client'] ) : ?>
			<h2 style="margin-top:18px"><?php esc_html_e( 'Claude Desktop', 'vulnhub' ); ?></h2>
			<p class="vh-field-help">
				<?php esc_html_e( 'Paste this into claude_desktop_config.json (Settings → Developer → Edit Config) and restart Claude. It is already filled in with your token.', 'vulnhub' ); ?>
			</p>
			<textarea class="large-text vh-mono" rows="14" readonly onclick="this.select()"><?php echo esc_textarea( (string) $vh_desktop_config ); ?></textarea>

			<h2 style="margin-top:18px"><?php esc_html_e( 'Claude on the web', 'vulnhub' ); ?></h2>
			<p class="vh-field-help">
				<?php esc_html_e( 'Settings → Connectors → Add custom connector. Use the server URL above, and give the token as an Authorization header of "Bearer <token>".', 'vulnhub' ); ?>
			</p>
		<?php else : ?>
			<h2 style="margin-top:18px"><?php esc_html_e( 'Point a client at it', 'vulnhub' ); ?></h2>
			<p class="vh-field-help">
				<?php esc_html_e( 'Any MCP client will do. Send the token as either header — whichever your client supports.', 'vulnhub' ); ?>
			</p>
			<pre class="vh-log">Authorization: Bearer <?php echo esc_html( $vh_fresh['token'] ); ?>

X-VulnHub-Token: <?php echo esc_html( $vh_fresh['token'] ); ?></pre>
		<?php endif; ?>
	</div>
<?php endif; ?>

<!-- ------------------------------------------------------------ what it can do -->
<div class="vh-form">
	<h2 style="margin-top:14px"><?php esc_html_e( 'What a connector of yours can do', 'vulnhub' ); ?></h2>
	<p class="vh-field-help">
		<?php
		printf(
			/* translators: 1: display name, 2: number of tools, 3: total tools. */
			esc_html__( 'A token is you. It signs in as %1$s and every action is checked against your role at the moment it runs — %2$d of the %3$d available tools, and nothing beyond them. Change your role and the connector changes with it, with no token to reissue.', 'vulnhub' ),
			esc_html( $vh_me->display_name ),
			count( $vh_tools ),
			count( $vh_all )
		);
		?>
	</p>

	<ul class="vh-tags" style="margin:10px 0 0">
		<?php foreach ( $vh_caps as $vh_label ) : ?>
			<li><span class="vh-chip vh-chip--good"><?php echo esc_html( $vh_label ); ?></span></li>
		<?php endforeach; ?>
	</ul>

	<details class="vh-tableview" style="margin-top:14px">
		<summary><?php esc_html_e( 'The tools it would be offered', 'vulnhub' ); ?></summary>
		<div class="vh-tableview__scroll">
			<table>
				<tbody>
				<?php foreach ( $vh_tools as $vh_name => $vh_tool ) : ?>
					<tr>
						<td class="vh-mono"><?php echo esc_html( (string) $vh_name ); ?></td>
						<td><?php echo esc_html( (string) $vh_tool['title'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</details>
</div>

<!-- --------------------------------------------------------------- one click -->
<div class="vh-grid vh-grid--2" style="margin-top:16px">
	<form method="post" action="<?php echo esc_url( VulnHub_MCP_Admin::section_url() ); ?>" class="vh-form">
		<?php wp_nonce_field( VulnHub_MCP_Admin::NONCE_ACTION, VulnHub_MCP_Admin::NONCE_FIELD ); ?>
		<input type="hidden" name="vh_mcp_action" value="create">
		<input type="hidden" name="client" value="claude">
		<input type="hidden" name="label" value="Claude">

		<h2 style="margin-top:14px"><?php esc_html_e( 'Connect Claude', 'vulnhub' ); ?></h2>
		<p class="vh-field-help">
			<?php esc_html_e( 'Creates a token and hands you a finished configuration block to paste into Claude Desktop, or the URL and header for a custom connector on the web.', 'vulnhub' ); ?>
		</p>
		<p style="margin-top:14px">
			<button type="submit" class="button button-primary"><?php esc_html_e( 'Create a Claude connector', 'vulnhub' ); ?></button>
		</p>
	</form>

	<form method="post" action="<?php echo esc_url( VulnHub_MCP_Admin::section_url() ); ?>" class="vh-form">
		<?php wp_nonce_field( VulnHub_MCP_Admin::NONCE_ACTION, VulnHub_MCP_Admin::NONCE_FIELD ); ?>
		<input type="hidden" name="vh_mcp_action" value="create">
		<input type="hidden" name="client" value="generic">

		<h2 style="margin-top:14px"><?php esc_html_e( 'Another assistant', 'vulnhub' ); ?></h2>
		<p class="vh-field-help">
			<?php esc_html_e( 'Any MCP-speaking client. Same endpoint, same permissions — you just wire the header up yourself.', 'vulnhub' ); ?>
		</p>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="vh-mcp-label"><?php esc_html_e( 'What is it for', 'vulnhub' ); ?></label></th>
				<td><input type="text" id="vh-mcp-label" name="label" class="regular-text"
					placeholder="<?php esc_attr_e( 'Triage agent on the ops box', 'vulnhub' ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-mcp-days"><?php esc_html_e( 'Expires after', 'vulnhub' ); ?></label></th>
				<td>
					<select id="vh-mcp-days" name="days">
						<option value="90"><?php esc_html_e( '90 days', 'vulnhub' ); ?></option>
						<option value="365"><?php esc_html_e( 'A year', 'vulnhub' ); ?></option>
						<option value="30"><?php esc_html_e( '30 days', 'vulnhub' ); ?></option>
						<option value="0"><?php esc_html_e( 'Never', 'vulnhub' ); ?></option>
					</select>
					<span class="vh-field-help"><?php esc_html_e( 'A token that never expires is one you will forget you issued.', 'vulnhub' ); ?></span>
				</td>
			</tr>
		</table>

		<p><button type="submit" class="button"><?php esc_html_e( 'Create a token', 'vulnhub' ); ?></button></p>
	</form>
</div>

<!-- ------------------------------------------------------------------ tokens -->
<div class="vh-panel" style="margin-top:20px">
	<div class="vh-panel__head">
		<h2><?php esc_html_e( 'Your connectors', 'vulnhub' ); ?></h2>
		<p class="vh-sub"><?php esc_html_e( 'Revoking takes effect on the next call — there is no cache to wait out.', 'vulnhub' ); ?></p>
	</div>

	<?php if ( ! $vh_mine ) : ?>
		<div class="vh-empty">
			<h2><?php esc_html_e( 'No connectors yet', 'vulnhub' ); ?></h2>
			<p><?php esc_html_e( 'Nothing is connected to VulnHub on your behalf.', 'vulnhub' ); ?></p>
		</div>
	<?php else : ?>
		<div style="overflow-x:auto">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Label', 'vulnhub' ); ?></th>
						<th style="width:130px"><?php esc_html_e( 'Token', 'vulnhub' ); ?></th>
						<th style="width:110px"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
						<th style="width:150px"><?php esc_html_e( 'Last used', 'vulnhub' ); ?></th>
						<th style="width:90px"><?php esc_html_e( 'Calls', 'vulnhub' ); ?></th>
						<th style="width:110px"></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_mine as $vh_t ) : ?>
					<?php $vh_live = VulnHub_MCP_Tokens::is_live( $vh_t ); ?>
					<tr>
						<td>
							<strong><?php echo esc_html( (string) $vh_t['label'] ); ?></strong>
							<div class="vh-muted" style="font-size:11.5px">
								<?php
								echo esc_html(
									'claude' === (string) $vh_t['client']
										? __( 'Claude', 'vulnhub' )
										: __( 'Generic MCP client', 'vulnhub' )
								);
								?>
								&middot; <?php echo esc_html( vh_ago( (string) $vh_t['created_at'] ) ); ?>
							</div>
						</td>
						<td class="vh-mono"><?php echo esc_html( (string) $vh_t['hint'] ); ?>…</td>
						<td>
							<?php if ( ! empty( $vh_t['revoked_at'] ) ) : ?>
								<span class="vh-chip vh-chip--bad"><?php esc_html_e( 'Revoked', 'vulnhub' ); ?></span>
							<?php elseif ( ! $vh_live ) : ?>
								<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Expired', 'vulnhub' ); ?></span>
							<?php else : ?>
								<span class="vh-chip vh-chip--good"><?php esc_html_e( 'Active', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
						<td class="vh-muted" style="font-size:12px">
							<?php
							echo esc_html(
								! empty( $vh_t['last_used_at'] )
									? vh_ago( (string) $vh_t['last_used_at'] )
									: __( 'never', 'vulnhub' )
							);
							?>
						</td>
						<td class="vh-muted"><?php echo esc_html( number_format_i18n( (int) $vh_t['calls'] ) ); ?></td>
						<td>
							<?php if ( empty( $vh_t['revoked_at'] ) ) : ?>
								<form method="post" action="<?php echo esc_url( VulnHub_MCP_Admin::section_url() ); ?>"
									onsubmit="return confirm('<?php echo esc_js( __( 'Revoke this token? Anything using it stops working immediately.', 'vulnhub' ) ); ?>');">
									<?php wp_nonce_field( VulnHub_MCP_Admin::NONCE_ACTION, VulnHub_MCP_Admin::NONCE_FIELD ); ?>
									<input type="hidden" name="vh_mcp_action" value="revoke">
									<input type="hidden" name="token_id" value="<?php echo esc_attr( (string) $vh_t['id'] ); ?>">
									<button type="submit" class="button button-small"><?php esc_html_e( 'Revoke', 'vulnhub' ); ?></button>
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

<?php if ( $vh_is_admin ) : ?>
	<?php $vh_everyone = VulnHub_MCP_Tokens::all(); ?>
	<div class="vh-panel" style="margin-top:20px">
		<div class="vh-panel__head">
			<h2><?php esc_html_e( 'Every connector on the platform', 'vulnhub' ); ?></h2>
			<p class="vh-sub"><?php esc_html_e( 'Who has wired an assistant into VulnHub, and with whose permissions.', 'vulnhub' ); ?></p>
		</div>

		<div style="overflow-x:auto">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Label', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Runs as', 'vulnhub' ); ?></th>
						<th style="width:110px"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
						<th style="width:150px"><?php esc_html_e( 'Last used', 'vulnhub' ); ?></th>
						<th style="width:110px"></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_everyone as $vh_t ) : ?>
					<?php
					$vh_owner = get_userdata( (int) $vh_t['user_id'] );
					$vh_live  = VulnHub_MCP_Tokens::is_live( $vh_t );
					?>
					<tr>
						<td><strong><?php echo esc_html( (string) $vh_t['label'] ); ?></strong></td>
						<td>
							<?php echo esc_html( $vh_owner ? $vh_owner->display_name : __( 'deleted account', 'vulnhub' ) ); ?>
							<div class="vh-muted" style="font-size:11.5px">
								<?php echo esc_html( $vh_owner ? implode( ', ', (array) $vh_owner->roles ) : '' ); ?>
							</div>
						</td>
						<td>
							<?php if ( ! empty( $vh_t['revoked_at'] ) ) : ?>
								<span class="vh-chip vh-chip--bad"><?php esc_html_e( 'Revoked', 'vulnhub' ); ?></span>
							<?php elseif ( ! $vh_live ) : ?>
								<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Expired', 'vulnhub' ); ?></span>
							<?php else : ?>
								<span class="vh-chip vh-chip--good"><?php esc_html_e( 'Active', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
						<td class="vh-muted" style="font-size:12px">
							<?php
							echo esc_html(
								! empty( $vh_t['last_used_at'] )
									? vh_ago( (string) $vh_t['last_used_at'] )
									: __( 'never', 'vulnhub' )
							);
							?>
						</td>
						<td>
							<?php if ( empty( $vh_t['revoked_at'] ) ) : ?>
								<form method="post" action="<?php echo esc_url( VulnHub_MCP_Admin::section_url() ); ?>"
									onsubmit="return confirm('<?php echo esc_js( __( 'Revoke this token?', 'vulnhub' ) ); ?>');">
									<?php wp_nonce_field( VulnHub_MCP_Admin::NONCE_ACTION, VulnHub_MCP_Admin::NONCE_FIELD ); ?>
									<input type="hidden" name="vh_mcp_action" value="revoke">
									<input type="hidden" name="token_id" value="<?php echo esc_attr( (string) $vh_t['id'] ); ?>">
									<button type="submit" class="button button-small"><?php esc_html_e( 'Revoke', 'vulnhub' ); ?></button>
								</form>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>
<?php endif; ?>

<p class="vh-sub vh-sub--foot">
	<?php esc_html_e( 'Every action a connector takes is written to the audit trail under an mcp. prefix, so what an agent did can always be told apart from what a person did.', 'vulnhub' ); ?>
</p>

