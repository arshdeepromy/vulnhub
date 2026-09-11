<?php
/**
 * Audit trail screen.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_page   = max( 1, isset( $_GET['paged'] ) ? (int) $_GET['paged'] : 1 );
$vh_search = isset( $_GET['search'] ) ? sanitize_text_field( wp_unslash( $_GET['search'] ) ) : '';
$vh_action = isset( $_GET['action_filter'] ) ? sanitize_text_field( wp_unslash( $_GET['action_filter'] ) ) : '';
// phpcs:enable

$vh_per   = 60;
$vh_rows  = vulnhub()->logger->audit_log(
	array(
		'search' => $vh_search,
		'action' => $vh_action,
		'limit'  => $vh_per,
		'offset' => ( $vh_page - 1 ) * $vh_per,
	)
);
$vh_total = vulnhub()->logger->audit_count();
$vh_pages = max( 1, (int) ceil( $vh_total / $vh_per ) );

$vh_groups = array(
	''           => __( 'All activity', 'vulnhub' ),
	'connector'  => __( 'Connector changes', 'vulnhub' ),
	'sync'       => __( 'Syncs', 'vulnhub' ),
	'ticket'     => __( 'Tickets', 'vulnhub' ),
	'exception'  => __( 'Exceptions', 'vulnhub' ),
	'asset'      => __( 'Asset changes', 'vulnhub' ),
	'mapping'    => __( 'Mapping rules', 'vulnhub' ),
	'auth'       => __( 'Authentication', 'vulnhub' ),
	'platform'   => __( 'Platform settings', 'vulnhub' ),
);
?>

<form method="get" class="vh-filters">
	<input type="hidden" name="page" value="vulnhub-audit">
	<label>
		<?php esc_html_e( 'Category', 'vulnhub' ); ?>
		<select name="action_filter" data-vh-autosubmit>
			<?php foreach ( $vh_groups as $vh_k => $vh_l ) : ?>
				<option value="<?php echo esc_attr( $vh_k ); ?>" <?php selected( $vh_action, $vh_k ); ?>><?php echo esc_html( $vh_l ); ?></option>
			<?php endforeach; ?>
		</select>
	</label>
	<label>
		<?php esc_html_e( 'Search', 'vulnhub' ); ?>
		<input type="search" name="search" value="<?php echo esc_attr( $vh_search ); ?>" placeholder="<?php esc_attr_e( 'summary or user…', 'vulnhub' ); ?>">
	</label>
	<button class="button button-primary"><?php esc_html_e( 'Filter', 'vulnhub' ); ?></button>
	<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-audit' ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
</form>

<?php if ( ! $vh_rows ) : ?>
	<div class="vh-card vh-empty">
		<span class="dashicons dashicons-list-view"></span>
		<h2><?php esc_html_e( 'No audit entries', 'vulnhub' ); ?></h2>
		<p><?php esc_html_e( 'Every configuration change, sync, ticket and exception decision is recorded here.', 'vulnhub' ); ?></p>
	</div>
<?php else : ?>
	<div class="vh-table-wrap">
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th style="width:150px"><?php esc_html_e( 'When', 'vulnhub' ); ?></th>
					<th style="width:130px"><?php esc_html_e( 'Actor', 'vulnhub' ); ?></th>
					<th style="width:180px"><?php esc_html_e( 'Action', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Summary', 'vulnhub' ); ?></th>
					<th style="width:110px"><?php esc_html_e( 'Object', 'vulnhub' ); ?></th>
					<th style="width:110px"><?php esc_html_e( 'IP', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $vh_rows as $vh_a ) : ?>
				<tr>
					<td class="vh-muted vh-nowrap" title="<?php echo esc_attr( vh_date( (string) $vh_a['logged_at'], 'j M Y H:i:s' ) ); ?>">
						<?php echo esc_html( vh_ago( (string) $vh_a['logged_at'] ) ); ?>
					</td>
					<td><?php echo esc_html( (string) $vh_a['actor'] ); ?></td>
					<td class="vh-mono" style="font-size:11px"><?php echo esc_html( (string) $vh_a['action'] ); ?></td>
					<td>
						<?php if ( 'error' === $vh_a['severity'] ) : ?>
							<span class="dashicons dashicons-warning" style="color:var(--vh-crit);font-size:15px;width:15px;height:15px"></span>
						<?php elseif ( 'warning' === $vh_a['severity'] ) : ?>
							<span class="dashicons dashicons-flag" style="color:var(--vh-high);font-size:15px;width:15px;height:15px"></span>
						<?php endif; ?>
						<?php echo esc_html( (string) $vh_a['summary'] ); ?>
					</td>
					<td class="vh-muted" style="font-size:11px">
						<?php echo esc_html( $vh_a['object_type'] ? $vh_a['object_type'] . ' ' . $vh_a['object_id'] : '—' ); ?>
					</td>
					<td class="vh-mono vh-muted" style="font-size:11px"><?php echo esc_html( (string) ( $vh_a['ip'] ?: '—' ) ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>

	<?php if ( $vh_pages > 1 ) : ?>
		<div class="tablenav bottom"><div class="tablenav-pages">
		<?php
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$vh_base = add_query_arg( array_map( 'sanitize_text_field', wp_unslash( $_GET ) ), admin_url( 'admin.php' ) );
		echo wp_kses_post( paginate_links( array( 'base' => add_query_arg( 'paged', '%#%', $vh_base ), 'format' => '', 'total' => $vh_pages, 'current' => $vh_page ) ) ?? '' );
		?>
		</div></div>
	<?php endif; ?>
<?php endif; ?>

