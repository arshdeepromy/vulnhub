<?php
/**
 * Exception register: request, approve, track and revoke risk acceptances.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Exceptions;
use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_new        = isset( $_GET['new'] );
$vh_finding_id = isset( $_GET['finding'] ) ? (int) $_GET['finding'] : 0;
// From a By-product row: every bundled library or file in one application.
$vh_bundled    = isset( $_GET['bundled'] ) ? sanitize_title( wp_unslash( (string) $_GET['bundled'] ) ) : '';
$vh_bundled_nm = isset( $_GET['app'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['app'] ) ) : $vh_bundled;
$vh_view_id    = isset( $_GET['exception'] ) ? (int) $_GET['exception'] : 0;
$vh_status     = isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : '';
// phpcs:enable

/* ------------------------------------------------------------------ new. */
if ( $vh_new && current_user_can( 'vulnhub_request_exception' ) ) :
	$vh_finding = $vh_finding_id ? Repo::finding( $vh_finding_id ) : null;
	$vh_asset   = $vh_finding ? Repo::asset( (int) $vh_finding['asset_id'] ) : null;
	$vh_vuln    = $vh_finding ? Repo::vuln( (int) $vh_finding['vuln_id'] ) : null;
	?>
	<p style="margin:0 0 14px">
		<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-exceptions' ) ); ?>">&larr; <?php esc_html_e( 'Exception register', 'vulnhub' ); ?></a>
	</p>

	<div class="vh-grid vh-grid--2">
		<div class="vh-form" style="padding:18px">
			<h2 style="margin-top:0"><?php esc_html_e( 'Request an exception', 'vulnhub' ); ?></h2>
			<p class="vh-muted" style="line-height:1.6">
				<?php esc_html_e( 'An approved exception suppresses matching findings from open counts and SLA breach reporting until it expires. It does not hide them — they stay visible and are re-counted the moment the exception lapses or is revoked.', 'vulnhub' ); ?>
			</p>

			<form id="vh-exception-form">
				<input type="hidden" name="scope_ref" value="<?php echo esc_attr( '' !== $vh_bundled ? $vh_bundled : (string) $vh_finding_id ); ?>">
				<input type="hidden" name="asset_id" value="<?php echo esc_attr( (string) ( $vh_finding['asset_id'] ?? 0 ) ); ?>">
				<input type="hidden" name="vuln_id" value="<?php echo esc_attr( (string) ( $vh_finding['vuln_id'] ?? 0 ) ); ?>">
				<input type="hidden" name="severity" value="<?php echo esc_attr( (string) ( $vh_finding['severity'] ?? '' ) ); ?>">

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="vh-exc-title"><?php esc_html_e( 'Title', 'vulnhub' ); ?></label></th>
						<td>
							<input type="text" id="vh-exc-title" name="title" class="large-text"
								value="<?php echo esc_attr( '' !== $vh_bundled ? sprintf( /* translators: %s: application. */ __( 'Bundled libraries and files in %s', 'vulnhub' ), $vh_bundled_nm ) : ( $vh_vuln && $vh_asset ? ( $vh_vuln['title'] . ' on ' . $vh_asset['hostname'] ) : '' ) ); ?>" required>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-exc-scope"><?php esc_html_e( 'Scope', 'vulnhub' ); ?></label></th>
						<td>
							<select id="vh-exc-scope" name="scope_type">
								<?php foreach ( Exceptions::scope_types() as $vh_k => $vh_l ) : ?>
									<?php
									// A request for an application's bundled components has
									// no finding behind it, so only that scope makes sense.
									if ( '' !== $vh_bundled && 'bundled' !== $vh_k ) {
										continue;
									}
									?>
									<option value="<?php echo esc_attr( $vh_k ); ?>" <?php selected( '' !== $vh_bundled && 'bundled' === $vh_k ); ?>><?php echo esc_html( $vh_l ); ?></option>
								<?php endforeach; ?>
							</select>
							<span class="vh-field-help"><?php esc_html_e( 'Widening the scope from one finding to a whole asset or vulnerability affects more findings — the count is shown after you save.', 'vulnhub' ); ?></span>
							<span class="vh-field-help"><?php esc_html_e( 'The bundled scope covers every library or file shipped inside the application, including ones found after approval. The application\'s own vulnerabilities are never included.', 'vulnhub' ); ?></span>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-exc-reason"><?php esc_html_e( 'Reason', 'vulnhub' ); ?></label></th>
						<td>
							<select id="vh-exc-reason" name="reason">
								<?php foreach ( Exceptions::reasons() as $vh_k => $vh_l ) : ?>
									<option value="<?php echo esc_attr( $vh_k ); ?>"><?php echo esc_html( $vh_l ); ?></option>
								<?php endforeach; ?>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-exc-just"><?php esc_html_e( 'Justification', 'vulnhub' ); ?></label></th>
						<td>
							<textarea id="vh-exc-just" name="justification" rows="5" class="large-text" required
								placeholder="<?php esc_attr_e( 'Why can this not be remediated? What is the plan and the timeframe?', 'vulnhub' ); ?>"></textarea>
							<span class="vh-field-help"><?php esc_html_e( 'At least 20 characters. This is the record an auditor reads.', 'vulnhub' ); ?></span>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-exc-controls"><?php esc_html_e( 'Compensating controls', 'vulnhub' ); ?></label></th>
						<td>
							<textarea id="vh-exc-controls" name="compensating_controls" rows="3" class="large-text"
								placeholder="<?php esc_attr_e( 'Network segmentation, WAF rule, host firewall, monitoring…', 'vulnhub' ); ?>"></textarea>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-exc-impact"><?php esc_html_e( 'Business impact if exploited', 'vulnhub' ); ?></label></th>
						<td><textarea id="vh-exc-impact" name="business_impact" rows="2" class="large-text"></textarea></td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-exc-expires"><?php esc_html_e( 'Expires', 'vulnhub' ); ?></label></th>
						<td>
							<input type="date" id="vh-exc-expires" name="expires_at"
								value="<?php echo esc_attr( wp_date( 'Y-m-d', time() + 90 * DAY_IN_SECONDS ) ); ?>" required>
							<span class="vh-field-help"><?php esc_html_e( 'Exceptions are always time-boxed. On expiry the findings return to the open count automatically.', 'vulnhub' ); ?></span>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="vh-exc-review"><?php esc_html_e( 'Review date', 'vulnhub' ); ?></label></th>
						<td><input type="date" id="vh-exc-review" name="review_at" value="<?php echo esc_attr( wp_date( 'Y-m-d', time() + 45 * DAY_IN_SECONDS ) ); ?>"></td>
					</tr>
				</table>

				<p class="submit">
					<button type="button" class="button button-primary" id="vh-exc-submit"><?php esc_html_e( 'Submit for approval', 'vulnhub' ); ?></button>
					<button type="button" class="button" id="vh-exc-draft"><?php esc_html_e( 'Save as draft', 'vulnhub' ); ?></button>
					<a class="button button-link" href="<?php echo esc_url( vh_admin_url( 'vulnhub-exceptions' ) ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
				</p>
			</form>
		</div>

		<?php if ( $vh_finding ) : ?>
			<div class="vh-card">
				<h2><?php esc_html_e( 'Finding being excepted', 'vulnhub' ); ?></h2>
				<p><?php echo wp_kses_post( vh_severity_pill( (string) $vh_finding['severity'] ) ); ?></p>
				<h3 style="margin:8px 0 12px;text-transform:none;letter-spacing:0;color:#1d2327;font-size:15px">
					<?php echo esc_html( (string) ( $vh_vuln['title'] ?? '' ) ); ?>
				</h3>
				<div class="vh-detail">
					<dl>
						<dt><?php esc_html_e( 'Asset', 'vulnhub' ); ?></dt>
						<dd class="vh-mono"><?php echo esc_html( (string) ( $vh_asset['hostname'] ?? '' ) ); ?></dd>
						<dt><?php esc_html_e( 'Plugin', 'vulnhub' ); ?></dt>
						<dd class="vh-mono"><?php echo esc_html( (string) ( $vh_vuln['plugin_id'] ?? '' ) ); ?></dd>
						<dt><?php esc_html_e( 'First found', 'vulnhub' ); ?></dt>
						<dd><?php echo esc_html( vh_date( (string) $vh_finding['first_found'] ) ); ?></dd>
						<dt><?php esc_html_e( 'Due', 'vulnhub' ); ?></dt>
						<dd><?php echo esc_html( $vh_finding['due_at'] ? vh_date( (string) $vh_finding['due_at'] ) : '—' ); ?></dd>
					</dl>
				</div>
				<?php if ( ! empty( $vh_vuln['solution'] ) ) : ?>
					<h2 style="margin-top:18px"><?php esc_html_e( 'Vendor remediation', 'vulnhub' ); ?></h2>
					<p style="line-height:1.6"><?php echo esc_html( (string) $vh_vuln['solution'] ); ?></p>
				<?php endif; ?>
			</div>
		<?php endif; ?>
	</div>

	<script>
	( function () {
		function submitException( submit ) {
			var form = document.getElementById( 'vh-exception-form' );
			var data = {};
			new FormData( form ).forEach( function ( value, key ) { data[ key ] = value; } );
			data.submit = submit;

			wp.apiFetch( { path: '/vulnhub/v1/exceptions', method: 'POST', data: data } )
				.then( function ( result ) {
					// Join with ? or &: in wp-admin the URL already has ?page=,
					// on the portal it is a clean permalink.
					var back = '<?php echo esc_url_raw( vh_admin_url( 'vulnhub-exceptions' ) ); ?>';
					window.location = back + ( back.indexOf( '?' ) === -1 ? '?' : '&' ) + 'vh_msg=' +
						encodeURIComponent( result.message );
				} )
				.catch( function ( error ) {
					window.alert( error.message || 'Could not save the exception.' );
				} );
		}
		document.getElementById( 'vh-exc-submit' ).addEventListener( 'click', function () { submitException( true ); } );
		document.getElementById( 'vh-exc-draft' ).addEventListener( 'click', function () { submitException( false ); } );
	}() );
	</script>
	<?php
	return;
endif;

/* ----------------------------------------------------------------- view. */
if ( $vh_view_id ) :
	$vh_e = Exceptions::get( $vh_view_id );
	if ( ! $vh_e ) {
		echo '<div class="vh-card vh-empty"><h2>' . esc_html__( 'Exception not found', 'vulnhub' ) . '</h2></div>';
		return;
	}
	?>
	<p style="margin:0 0 14px">
		<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-exceptions' ) ); ?>">&larr; <?php esc_html_e( 'Exception register', 'vulnhub' ); ?></a>
	</p>

	<div class="vh-grid vh-grid--2">
		<div class="vh-card">
			<h2><?php echo esc_html( (string) $vh_e['reference'] ); ?></h2>
			<h3 style="margin:0 0 12px;text-transform:none;letter-spacing:0;color:#1d2327;font-size:16px">
				<?php echo esc_html( (string) $vh_e['title'] ); ?>
			</h3>
			<p><span class="vh-state vh-state--<?php echo esc_attr( (string) $vh_e['status'] ); ?>"><?php echo esc_html( Exceptions::statuses()[ (string) $vh_e['status'] ] ?? (string) $vh_e['status'] ); ?></span></p>
			<div class="vh-detail" style="margin-top:12px">
				<dl>
					<dt><?php esc_html_e( 'Scope', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) $vh_e['scope_label'] ); ?></dd>
					<dt><?php esc_html_e( 'Findings affected', 'vulnhub' ); ?></dt>
					<dd><strong><?php echo esc_html( number_format_i18n( (int) $vh_e['affected_count'] ) ); ?></strong></dd>
					<dt><?php esc_html_e( 'Reason', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( Exceptions::reasons()[ (string) $vh_e['reason'] ] ?? (string) $vh_e['reason'] ); ?></dd>
					<dt><?php esc_html_e( 'Requested by', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) $vh_e['requested_by_name'] ); ?></dd>
					<dt><?php esc_html_e( 'Requested', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( vh_date( (string) $vh_e['requested_at'] ) ); ?></dd>
					<dt><?php esc_html_e( 'Expires', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( $vh_e['expires_at'] ? vh_date( (string) $vh_e['expires_at'], 'j M Y' ) : '—' ); ?></dd>
					<dt><?php esc_html_e( 'Approver', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_e['approver_name'] ?: '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Decided', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( $vh_e['decided_at'] ? vh_date( (string) $vh_e['decided_at'] ) : '—' ); ?></dd>
				</dl>
			</div>
		</div>

		<div class="vh-card">
			<h2><?php esc_html_e( 'Justification', 'vulnhub' ); ?></h2>
			<p style="line-height:1.7;white-space:pre-wrap"><?php echo esc_html( (string) $vh_e['justification'] ); ?></p>

			<?php if ( ! empty( $vh_e['compensating_controls'] ) ) : ?>
				<h2 style="margin-top:18px"><?php esc_html_e( 'Compensating controls', 'vulnhub' ); ?></h2>
				<p style="line-height:1.7;white-space:pre-wrap"><?php echo esc_html( (string) $vh_e['compensating_controls'] ); ?></p>
			<?php endif; ?>

			<?php if ( ! empty( $vh_e['business_impact'] ) ) : ?>
				<h2 style="margin-top:18px"><?php esc_html_e( 'Business impact', 'vulnhub' ); ?></h2>
				<p style="line-height:1.7;white-space:pre-wrap"><?php echo esc_html( (string) $vh_e['business_impact'] ); ?></p>
			<?php endif; ?>

			<?php if ( ! empty( $vh_e['decision_note'] ) ) : ?>
				<h2 style="margin-top:18px"><?php esc_html_e( 'Decision note', 'vulnhub' ); ?></h2>
				<p style="line-height:1.7;white-space:pre-wrap"><?php echo esc_html( (string) $vh_e['decision_note'] ); ?></p>
			<?php endif; ?>

			<?php if ( current_user_can( 'vulnhub_approve_exception' ) && in_array( (string) $vh_e['status'], array( 'pending', 'draft', 'approved' ), true ) ) : ?>
				<hr style="margin:20px 0;border:0;border-top:1px solid var(--vh-line)">
				<h2><?php esc_html_e( 'Decision', 'vulnhub' ); ?></h2>
				<textarea id="vh-decision-note" rows="3" class="large-text" placeholder="<?php esc_attr_e( 'Optional note recorded against the decision…', 'vulnhub' ); ?>"></textarea>
				<p class="vh-actions" style="margin-top:10px">
					<?php if ( 'approved' !== $vh_e['status'] ) : ?>
						<button type="button" class="button button-primary" data-vh-decide="approved"><?php esc_html_e( 'Approve', 'vulnhub' ); ?></button>
						<button type="button" class="button" data-vh-decide="rejected"><?php esc_html_e( 'Reject', 'vulnhub' ); ?></button>
					<?php else : ?>
						<button type="button" class="button button-link-delete" data-vh-decide="revoked"><?php esc_html_e( 'Revoke exception', 'vulnhub' ); ?></button>
					<?php endif; ?>
				</p>
				<script>
				document.querySelectorAll( '[data-vh-decide]' ).forEach( function ( button ) {
					button.addEventListener( 'click', function () {
						button.disabled = true;
						wp.apiFetch( {
							path: '/vulnhub/v1/exceptions/<?php echo (int) $vh_e['id']; ?>/decide',
							method: 'POST',
							data: {
								decision: button.dataset.vhDecide,
								note: document.getElementById( 'vh-decision-note' ).value
							}
						} ).then( function ( result ) {
							var back = '<?php echo esc_url_raw( vh_admin_url( 'vulnhub-exceptions' ) ); ?>';
							window.location = back + ( back.indexOf( '?' ) === -1 ? '?' : '&' ) + 'vh_msg=' +
								encodeURIComponent( result.message );
						} ).catch( function ( error ) {
							window.alert( error.message );
							button.disabled = false;
						} );
					} );
				} );
				</script>
			<?php endif; ?>
		</div>
	</div>
	<?php
	return;
endif;

/* ----------------------------------------------------------------- list. */
$vh_query = Exceptions::query(
	array(
		'status' => $vh_status,
		'limit'  => 100,
	)
);
$vh_sum = Repo::summary();
?>

<div class="vh-grid vh-grid--4">
	<div class="vh-card vh-card--warn">
		<h2><?php esc_html_e( 'Awaiting approval', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_sum['exceptions_open'] ) ); ?></p>
	</div>
	<div class="vh-card">
		<h2><?php esc_html_e( 'Active', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_sum['exceptions_active'] ) ); ?></p>
	</div>
	<div class="vh-card">
		<h2><?php esc_html_e( 'Findings suppressed', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_sum['excepted'] ) ); ?></p>
	</div>
	<div class="vh-card">
		<h2><?php esc_html_e( 'Expiring in 30 days', 'vulnhub' ); ?></h2>
		<p class="vh-card__value">
			<?php echo esc_html( number_format_i18n( (int) Exceptions::query( array( 'expiring_days' => 30, 'limit' => 1 ) )['total'] ) ); ?>
		</p>
	</div>
</div>

<form method="get" class="vh-filters">
	<input type="hidden" name="page" value="vulnhub-exceptions">
	<label>
		<?php esc_html_e( 'Status', 'vulnhub' ); ?>
		<select name="status" data-vh-autosubmit>
			<option value=""><?php esc_html_e( 'All', 'vulnhub' ); ?></option>
			<?php foreach ( Exceptions::statuses() as $vh_k => $vh_l ) : ?>
				<option value="<?php echo esc_attr( $vh_k ); ?>" <?php selected( $vh_status, $vh_k ); ?>><?php echo esc_html( $vh_l ); ?></option>
			<?php endforeach; ?>
		</select>
	</label>
	<button class="button"><?php esc_html_e( 'Filter', 'vulnhub' ); ?></button>
	<span style="flex:1"></span>
	<a class="button button-primary" href="<?php echo esc_url( vh_admin_url( 'vulnhub-findings' ) ); ?>">
		<?php esc_html_e( 'Find a vulnerability to except', 'vulnhub' ); ?>
	</a>
</form>

<?php if ( ! $vh_query['rows'] ) : ?>
	<div class="vh-card vh-empty">
		<span class="dashicons dashicons-shield"></span>
		<h2><?php esc_html_e( 'No exceptions on record', 'vulnhub' ); ?></h2>
		<p><?php esc_html_e( 'Raise one from a finding when remediation genuinely is not possible. Every exception is time-boxed, justified and auditable.', 'vulnhub' ); ?></p>
	</div>
<?php else : ?>
<div class="vh-table-wrap">
	<table class="wp-list-table widefat fixed striped">
		<thead>
			<tr>
				<th style="width:90px"><?php esc_html_e( 'Ref', 'vulnhub' ); ?></th>
				<th><?php esc_html_e( 'Title', 'vulnhub' ); ?></th>
				<th style="width:150px"><?php esc_html_e( 'Reason', 'vulnhub' ); ?></th>
				<th style="width:80px"><?php esc_html_e( 'Findings', 'vulnhub' ); ?></th>
				<th style="width:130px"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
				<th style="width:150px"><?php esc_html_e( 'Requested by', 'vulnhub' ); ?></th>
				<th style="width:110px"><?php esc_html_e( 'Expires', 'vulnhub' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $vh_query['rows'] as $vh_e ) : ?>
			<tr>
				<td>
					<a class="vh-mono" href="<?php echo esc_url( vh_admin_url( 'vulnhub-exceptions', array( 'exception' => (int) $vh_e['id'] ) ) ); ?>">
						<strong><?php echo esc_html( (string) $vh_e['reference'] ); ?></strong>
					</a>
				</td>
				<td><span class="vh-truncate"><?php echo esc_html( (string) $vh_e['title'] ); ?></span></td>
				<td class="vh-muted"><?php echo esc_html( Exceptions::reasons()[ (string) $vh_e['reason'] ] ?? '' ); ?></td>
				<td><?php echo esc_html( number_format_i18n( (int) $vh_e['affected_count'] ) ); ?></td>
				<td><span class="vh-state vh-state--<?php echo esc_attr( (string) $vh_e['status'] ); ?>"><?php echo esc_html( Exceptions::statuses()[ (string) $vh_e['status'] ] ?? '' ); ?></span></td>
				<td><?php echo esc_html( (string) $vh_e['requested_by_name'] ); ?></td>
				<td class="vh-nowrap vh-muted"><?php echo esc_html( $vh_e['expires_at'] ? vh_date( (string) $vh_e['expires_at'], 'j M Y' ) : '—' ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
</div>
<?php endif; ?>

