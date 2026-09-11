<?php
/**
 * End-of-life table editor.
 *
 * The dates in data/eol.php were right the day they were checked, and vendors
 * move them: Microsoft extends an ESU, Red Hat shifts a maintenance end,
 * Canonical announces an interim. Waiting for a plugin release to correct a
 * date that is wrong on the dashboard today is not a reasonable answer, so
 * this screen writes over the shipped table.
 *
 * Corrections are stored as differences, not as copies. Change one date and
 * only that field is remembered, so the next release's dates still reach
 * every row nobody has touched — and "Restore the shipped table" is always
 * one button away.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Eol;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! current_user_can( Caps::MANAGE ) ) {
	wp_die( esc_html__( 'You do not have permission to edit the lifecycle table.', 'vulnhub' ) );
}

$vh_table    = Eol::table();
$vh_statuses = Eol::statuses();
$vh_edit     = isset( $_GET['row'] ) ? sanitize_key( wp_unslash( $_GET['row'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$vh_row      = $vh_edit && isset( $vh_table[ $vh_edit ] ) ? $vh_table[ $vh_edit ] : null;
$vh_in_use   = array();

foreach ( array_merge( Eol::estate(), Eol::software() ) as $vh_g ) {
	$vh_in_use[ (string) $vh_g['key'] ] = (int) $vh_g['assets'];
}

$vh_kinds = array(
	'os'       => __( 'Operating system', 'vulnhub' ),
	'software' => __( 'Installed software', 'vulnhub' ),
);
?>

<p class="vh-lede">
	<?php
	printf(
		/* translators: 1: number of rows, 2: number of corrections. */
		esc_html__( 'The lifecycle table has %1$s releases in it, %2$s of them corrected here. Everything else is what the plugin shipped, checked against the vendor lifecycle page listed on each row.', 'vulnhub' ),
		esc_html( number_format_i18n( count( $vh_table ) ) ),
		esc_html( number_format_i18n( count( Eol::overrides() ) ) )
	);
	?>
</p>

<?php if ( $vh_row ) : ?>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
		<?php wp_nonce_field( 'vulnhub_save_eol' ); ?>
		<input type="hidden" name="action" value="vulnhub_save_eol">
		<input type="hidden" name="key" value="<?php echo esc_attr( (string) $vh_row['key'] ); ?>">

		<h2><?php echo esc_html( trim( $vh_row['product'] . ' ' . $vh_row['release'] ) ); ?></h2>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="vh-eol-product"><?php esc_html_e( 'Product', 'vulnhub' ); ?></label></th>
				<td><input type="text" id="vh-eol-product" name="product" class="regular-text" value="<?php echo esc_attr( (string) $vh_row['product'] ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-eol-release"><?php esc_html_e( 'Release', 'vulnhub' ); ?></label></th>
				<td><input type="text" id="vh-eol-release" name="release" class="regular-text" value="<?php echo esc_attr( (string) $vh_row['release'] ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-eol-date"><?php esc_html_e( 'End of security updates', 'vulnhub' ); ?></label></th>
				<td>
					<input type="date" id="vh-eol-date" name="eol" value="<?php echo esc_attr( (string) $vh_row['eol'] ); ?>">
					<span class="vh-field-help">
						<?php esc_html_e( 'The date the vendor stops shipping fixes — the extended date where there is one, not the mainstream date. Leave empty if the vendor has not published one; the release is still counted, under "no published date".', 'vulnhub' ); ?>
					</span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-eol-mainstream"><?php esc_html_e( 'End of mainstream support', 'vulnhub' ); ?></label></th>
				<td>
					<input type="date" id="vh-eol-mainstream" name="mainstream" value="<?php echo esc_attr( (string) $vh_row['mainstream'] ); ?>">
					<span class="vh-field-help"><?php esc_html_e( 'Recorded for context. It does not affect the status shown on the dashboard.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-eol-note"><?php esc_html_e( 'Note', 'vulnhub' ); ?></label></th>
				<td>
					<textarea id="vh-eol-note" name="note" class="large-text" rows="3"><?php echo esc_textarea( (string) $vh_row['note'] ); ?></textarea>
					<span class="vh-field-help"><?php esc_html_e( 'Shown in the export and on the lifecycle table. Say what a reader needs to know that the date alone does not — an ESU option, an edition that differs.', 'vulnhub' ); ?></span>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-eol-source"><?php esc_html_e( 'Source', 'vulnhub' ); ?></label></th>
				<td><input type="url" id="vh-eol-source" name="source" class="large-text" value="<?php echo esc_attr( (string) $vh_row['source'] ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Matched by', 'vulnhub' ); ?></th>
				<td>
					<?php if ( 'os' === $vh_row['kind'] ) : ?>
						<label for="vh-eol-build"><?php esc_html_e( 'Windows build', 'vulnhub' ); ?></label>
						<input type="text" id="vh-eol-build" name="build" class="small-text" value="<?php echo esc_attr( (string) $vh_row['build'] ); ?>">
						<label for="vh-eol-version" style="margin-left:12px"><?php esc_html_e( 'or version prefix', 'vulnhub' ); ?></label>
						<input type="text" id="vh-eol-version" name="version" class="small-text" value="<?php echo esc_attr( (string) $vh_row['version'] ); ?>">
						<span class="vh-field-help">
							<?php esc_html_e( 'Windows is matched on the build number out of the inventory version string, because the product name in the inventory is often wrong. Everything else is matched on a version prefix — "9" matches 9.3, and a longer prefix wins over a shorter one.', 'vulnhub' ); ?>
						</span>
					<?php else : ?>
						<label for="vh-eol-cpe"><?php esc_html_e( 'CPE vendor:product', 'vulnhub' ); ?></label>
						<input type="text" id="vh-eol-cpe" name="cpe" class="regular-text" value="<?php echo esc_attr( (string) $vh_row['cpe'] ); ?>">
						<label for="vh-eol-version" style="margin-left:12px"><?php esc_html_e( 'Version prefix', 'vulnhub' ); ?></label>
						<input type="text" id="vh-eol-version" name="version" class="small-text" value="<?php echo esc_attr( (string) $vh_row['version'] ); ?>">
						<span class="vh-field-help">
							<?php esc_html_e( 'Tenable reports installed software as cpe:/a:vendor:product:version. Enter the vendor:product half, for example openssl:openssl.', 'vulnhub' ); ?>
						</span>
					<?php endif; ?>
				</td>
			</tr>
		</table>

		<p class="submit">
			<?php submit_button( __( 'Save this release', 'vulnhub' ), 'primary', 'submit', false ); ?>
			<a class="button" href="<?php echo esc_url( remove_query_arg( 'row' ) ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
		</p>
	</form>

	<hr>

<?php endif; ?>

<h2><?php esc_html_e( 'Add a release', 'vulnhub' ); ?></h2>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
	<?php wp_nonce_field( 'vulnhub_save_eol' ); ?>
	<input type="hidden" name="action" value="vulnhub_save_eol">
	<input type="hidden" name="new" value="1">

	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><label for="vh-new-kind"><?php esc_html_e( 'Kind', 'vulnhub' ); ?></label></th>
			<td>
				<select id="vh-new-kind" name="kind">
					<?php foreach ( $vh_kinds as $vh_k => $vh_label ) : ?>
						<option value="<?php echo esc_attr( $vh_k ); ?>"><?php echo esc_html( $vh_label ); ?></option>
					<?php endforeach; ?>
				</select>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="vh-new-product"><?php esc_html_e( 'Product', 'vulnhub' ); ?></label></th>
			<td><input type="text" id="vh-new-product" name="product" class="regular-text" required></td>
		</tr>
		<tr>
			<th scope="row"><label for="vh-new-release"><?php esc_html_e( 'Release', 'vulnhub' ); ?></label></th>
			<td><input type="text" id="vh-new-release" name="release" class="regular-text"></td>
		</tr>
		<tr>
			<th scope="row"><label for="vh-new-eol"><?php esc_html_e( 'End of security updates', 'vulnhub' ); ?></label></th>
			<td><input type="date" id="vh-new-eol" name="eol"></td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Matched by', 'vulnhub' ); ?></th>
			<td>
				<label for="vh-new-family"><?php esc_html_e( 'OS family', 'vulnhub' ); ?></label>
				<input type="text" id="vh-new-family" name="family" class="small-text" placeholder="ubuntu">
				<label for="vh-new-cpe" style="margin-left:12px"><?php esc_html_e( 'or CPE', 'vulnhub' ); ?></label>
				<input type="text" id="vh-new-cpe" name="cpe" class="regular-text" placeholder="openssl:openssl">
				<label for="vh-new-build" style="margin-left:12px"><?php esc_html_e( 'Build', 'vulnhub' ); ?></label>
				<input type="text" id="vh-new-build" name="build" class="small-text">
				<label for="vh-new-version" style="margin-left:12px"><?php esc_html_e( 'Version', 'vulnhub' ); ?></label>
				<input type="text" id="vh-new-version" name="version" class="small-text">
				<span class="vh-field-help">
					<?php esc_html_e( 'An operating system row needs a family (the slug VulnHub groups platforms under, such as ubuntu, rhel or windows_server) plus either a build or a version prefix. A software row needs a CPE and a version prefix.', 'vulnhub' ); ?>
				</span>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="vh-new-source"><?php esc_html_e( 'Source', 'vulnhub' ); ?></label></th>
			<td><input type="url" id="vh-new-source" name="source" class="large-text" placeholder="https://"></td>
		</tr>
	</table>

	<?php submit_button( __( 'Add release', 'vulnhub' ) ); ?>
</form>

<hr>

<h2><?php esc_html_e( 'The lifecycle table', 'vulnhub' ); ?></h2>

<?php /* 13 columns will not fold into a phone. Let the table scroll inside
   its own box rather than widening the whole admin screen. */ ?>
<div class="vh-tableview__scroll">
<table class="widefat striped vh-table">
	<thead>
		<tr>
			<th scope="col"><?php esc_html_e( 'Product', 'vulnhub' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Release', 'vulnhub' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Matched by', 'vulnhub' ); ?></th>
			<th scope="col"><?php esc_html_e( 'End of life', 'vulnhub' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
			<th scope="col"><?php esc_html_e( 'In the estate', 'vulnhub' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Source', 'vulnhub' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Actions', 'vulnhub' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<?php foreach ( $vh_table as $vh_key => $vh_r ) : ?>
			<?php $vh_state = Eol::status( (string) $vh_r['eol'] ); ?>
			<tr>
				<td>
					<strong><?php echo esc_html( (string) $vh_r['product'] ); ?></strong>
					<?php if ( $vh_r['edited'] ) : ?>
						<span class="vh-tag"><?php esc_html_e( 'edited', 'vulnhub' ); ?></span>
					<?php endif; ?>
					<?php if ( $vh_r['custom'] ) : ?>
						<span class="vh-tag"><?php esc_html_e( 'added here', 'vulnhub' ); ?></span>
					<?php endif; ?>
					<?php if ( (string) $vh_r['note'] ) : ?>
						<br><span class="vh-field-help"><?php echo esc_html( (string) $vh_r['note'] ); ?></span>
					<?php endif; ?>
				</td>
				<td><?php echo esc_html( (string) $vh_r['release'] ); ?></td>
				<td>
					<code><?php
					echo esc_html(
						'os' === $vh_r['kind']
							? ( (string) $vh_r['build'] ? 'build ' . $vh_r['build'] : $vh_r['family'] . ' ' . $vh_r['version'] )
							: $vh_r['cpe'] . ' ' . $vh_r['version']
					);
					?></code>
				</td>
				<td><?php echo esc_html( (string) $vh_r['eol'] ?: '—' ); ?></td>
				<td><?php echo esc_html( (string) $vh_state['label'] ); ?></td>
				<td><?php echo esc_html( isset( $vh_in_use[ $vh_key ] ) ? number_format_i18n( $vh_in_use[ $vh_key ] ) : '—' ); ?></td>
				<td>
					<?php if ( (string) $vh_r['source'] ) : ?>
						<a href="<?php echo esc_url( (string) $vh_r['source'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'vendor page', 'vulnhub' ); ?></a>
					<?php endif; ?>
				</td>
				<td>
					<a class="button button-small" href="<?php echo esc_url( add_query_arg( 'row', $vh_key ) ); ?>"><?php esc_html_e( 'Edit', 'vulnhub' ); ?></a>
					<?php if ( $vh_r['edited'] || $vh_r['custom'] ) : ?>
						<a class="button button-small" href="<?php
						echo esc_url(
							wp_nonce_url(
								add_query_arg(
									array(
										'action' => 'vulnhub_delete_eol',
										'key'    => $vh_key,
										'mode'   => $vh_r['custom'] ? 'delete' : 'revert',
									),
									admin_url( 'admin-post.php' )
								),
								'vulnhub_delete_eol'
							)
						);
						?>"><?php echo $vh_r['custom'] ? esc_html__( 'Delete', 'vulnhub' ) : esc_html__( 'Revert', 'vulnhub' ); ?></a>
					<?php endif; ?>
				</td>
			</tr>
		<?php endforeach; ?>
	</tbody>
</table>
</div>

<?php if ( Eol::overrides() ) : ?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:16px">
		<?php wp_nonce_field( 'vulnhub_reset_eol' ); ?>
		<input type="hidden" name="action" value="vulnhub_reset_eol">
		<?php submit_button( __( 'Restore the shipped table', 'vulnhub' ), 'secondary', 'submit', false ); ?>
		<span class="vh-field-help"><?php esc_html_e( 'Discards every correction and addition made here.', 'vulnhub' ); ?></span>
	</form>
<?php endif; ?>

