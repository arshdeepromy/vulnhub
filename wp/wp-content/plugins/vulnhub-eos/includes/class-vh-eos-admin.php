<?php
/**
 * Administration → Data → EOS remediation plan.
 *
 * Upload the workbook's Reconciled sheet, see exactly what it would do, then
 * commit it. The preview matters more than it looks: the import decides which
 * machines count as covered on the dashboard, and "34 hostnames match nothing
 * in the estate" is something to see before the numbers move, not after.
 *
 * @package VulnHub\EOS
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The programme's admin section.
 */
final class VH_EOS_Admin {

	public const SECTION     = 'eos_plan';
	public const UPLOAD_ACT  = 'vulnhub_eos_upload';
	public const COMMIT_ACT  = 'vulnhub_eos_commit';
	public const DISCARD_ACT = 'vulnhub_eos_discard';

	/** Transient holding a previewed-but-not-yet-imported upload. */
	private const PENDING_PREFIX = 'vulnhub_eos_pending_';

	public static function init(): void {
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'admin_post_' . self::UPLOAD_ACT, array( __CLASS__, 'handle_upload' ) );
		add_action( 'admin_post_' . self::COMMIT_ACT, array( __CLASS__, 'handle_commit' ) );
		add_action( 'admin_post_' . self::DISCARD_ACT, array( __CLASS__, 'handle_discard' ) );
	}

	/**
	 * @param array<string,array<string,mixed>> $sections Sections.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		$sections[ self::SECTION ] = array(
			'label'   => __( 'EOS remediation plan', 'vulnhub' ),
			'cap'     => Caps::MANAGE,
			'group'   => 'data',
			'order'   => 36,
			'summary' => __( 'Which end-of-life servers have a funded project and a date, from the programme\'s reconciliation workbook.', 'vulnhub' ),
		);

		return $sections;
	}

	/* =================================================================
	 * Screen
	 * ============================================================== */

	public static function render_section( string $section ): void {
		if ( self::SECTION !== $section ) {
			return;
		}

		$last    = VH_EOS_Repo::last_import();
		$pending = self::pending();
		?>
		<div class="vh-eos-admin">
			<?php self::render_tiles( $last ); ?>

			<?php if ( $pending ) : ?>
				<?php self::render_preview( $pending ); ?>
			<?php else : ?>
				<?php self::render_upload_form(); ?>
			<?php endif; ?>

			<?php if ( $last ) : ?>
				<?php self::render_last_import( $last ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * @param array<string,mixed> $last Last import report.
	 */
	private static function render_tiles( array $last ): void {
		$summary = VH_EOS_Repo::has_data()
			? VH_EOS_Repo::summary( array( 'include_unplanned' => true ) )
			: array(
				'covered'   => 0,
				'overdue'   => 0,
				'uncovered' => 0,
				'total'     => 0,
			);
		?>
		<div class="vh-tiles" style="margin-bottom:14px">
			<div class="vh-tile vh-tile--good">
				<span class="vh-tile__label"><?php esc_html_e( 'Covered by a project', 'vulnhub' ); ?></span>
				<span class="vh-tile__value"><?php echo esc_html( number_format_i18n( (int) $summary['covered'] ) ); ?></span>
				<span class="vh-tile__meta"><?php esc_html_e( 'remediated, or planned with a date still ahead', 'vulnhub' ); ?></span>
			</div>
			<div class="vh-tile vh-tile--warning">
				<span class="vh-tile__label"><?php esc_html_e( 'Past its planned date', 'vulnhub' ); ?></span>
				<span class="vh-tile__value"><?php echo esc_html( number_format_i18n( (int) $summary['overdue'] ) ); ?></span>
				<span class="vh-tile__meta"><?php esc_html_e( 'has a project; the quarter has gone', 'vulnhub' ); ?></span>
			</div>
			<div class="vh-tile vh-tile--critical">
				<span class="vh-tile__label"><?php esc_html_e( 'Not covered', 'vulnhub' ); ?></span>
				<span class="vh-tile__value"><?php echo esc_html( number_format_i18n( (int) $summary['uncovered'] ) ); ?></span>
				<span class="vh-tile__meta"><?php esc_html_e( 'no plan, no date, or not in the programme at all', 'vulnhub' ); ?></span>
			</div>
			<div class="vh-tile vh-tile--neutral">
				<span class="vh-tile__label"><?php esc_html_e( 'Data as at', 'vulnhub' ); ?></span>
				<span class="vh-tile__value" style="font-size:18px">
					<?php echo esc_html( $last && ! empty( $last['at'] ) ? vh_date( (string) $last['at'], 'j M Y' ) : __( 'never', 'vulnhub' ) ); ?>
				</span>
				<span class="vh-tile__meta">
					<?php
					echo $last && ! empty( $last['at'] )
						? esc_html( sprintf( /* translators: %s: relative time. */ __( 'imported %s', 'vulnhub' ), vh_ago( (string) $last['at'] ) ) )
						: esc_html__( 'the programme data has not been loaded yet', 'vulnhub' );
					?>
				</span>
			</div>
		</div>
		<?php
	}

	private static function render_upload_form(): void {
		?>
		<div class="vh-card">
			<h2><?php esc_html_e( 'Upload the reconciliation sheet', 'vulnhub' ); ?></h2>
			<p class="vh-card__meta" style="line-height:1.6;max-width:70ch">
				<?php esc_html_e( 'The workbook\'s "Reconciled" sheet, saved as CSV. Each row is matched to an existing asset by hostname — a hostname the estate does not hold is still imported and still counted, it simply has no asset to open. Nothing here creates or changes an asset.', 'vulnhub' ); ?>
			</p>
			<p class="vh-card__meta" style="line-height:1.6;max-width:70ch">
				<?php esc_html_e( 'Re-uploading is the normal case: rows are matched on hostname and updated in place, so a monthly refresh replaces the plan rather than duplicating it.', 'vulnhub' ); ?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data"
				style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px">
				<?php wp_nonce_field( self::UPLOAD_ACT ); ?>
				<input type="hidden" name="action" value="<?php echo esc_attr( self::UPLOAD_ACT ); ?>">
				<input type="hidden" name="vh_from_portal" value="1">
				<input type="file" name="eos_csv" accept=".csv,text/csv" required>
				<button type="submit" class="vh-btn vh-btn--primary"><?php esc_html_e( 'Preview import', 'vulnhub' ); ?></button>
			</form>
		</div>
		<?php
	}

	/**
	 * @param array<string,mixed> $pending Pending upload: token, path, report.
	 */
	private static function render_preview( array $pending ): void {
		$report    = (array) ( $pending['report'] ?? array() );
		$unmatched = (array) ( $report['unmatched'] ?? array() );
		$coverage  = (array) ( $report['coverage'] ?? array() );
		$counts    = (array) ( $report['report'] ?? array() );
		?>
		<div class="vh-card">
			<h2><?php esc_html_e( 'Preview — nothing has been imported yet', 'vulnhub' ); ?></h2>
			<p class="vh-card__meta">
				<?php
				printf(
					/* translators: %s: file name. */
					esc_html__( 'Read from %s. This is what importing it would do.', 'vulnhub' ),
					'<span class="vh-mono">' . esc_html( (string) ( $pending['filename'] ?? '' ) ) . '</span>'
				);
				?>
			</p>

			<div class="vh-tablewrap" style="margin-top:12px">
				<table class="vh-table">
					<tbody>
						<tr>
							<th scope="row"><?php esc_html_e( 'Plan rows in the file', 'vulnhub' ); ?></th>
							<td class="vh-mono"><?php echo esc_html( number_format_i18n( (int) ( $report['rows'] ?? 0 ) ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Matched to an asset', 'vulnhub' ); ?></th>
							<td class="vh-mono"><?php echo esc_html( number_format_i18n( (int) ( $report['matched'] ?? 0 ) ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'No matching asset', 'vulnhub' ); ?></th>
							<td class="vh-mono"><?php echo esc_html( number_format_i18n( count( $unmatched ) ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Covered / past date / not covered', 'vulnhub' ); ?></th>
							<td class="vh-mono">
								<?php
								echo esc_html(
									sprintf(
										'%s / %s / %s',
										number_format_i18n( (int) ( $coverage[ VH_EOS_Repo::COVERED ] ?? 0 ) ),
										number_format_i18n( (int) ( $coverage[ VH_EOS_Repo::OVERDUE ] ?? 0 ) ),
										number_format_i18n( (int) ( $coverage[ VH_EOS_Repo::UNCOVERED ] ?? 0 ) )
									)
								);
								?>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Rows skipped', 'vulnhub' ); ?></th>
							<td class="vh-mono">
								<?php
								echo esc_html(
									sprintf(
										/* translators: 1: blank rows, 2: rows with no assessed state, 3: duplicate hostnames. */
										__( '%1$s blank, %2$s with no assessed state, %3$s duplicate hostnames', 'vulnhub' ),
										number_format_i18n( (int) ( $counts['blank'] ?? 0 ) ),
										number_format_i18n( (int) ( $counts['no_state'] ?? 0 ) ),
										number_format_i18n( (int) ( $counts['duplicate'] ?? 0 ) )
									)
								);
								?>
							</td>
						</tr>
					</tbody>
				</table>
			</div>

			<?php if ( $unmatched ) : ?>
				<details style="margin-top:12px">
					<summary style="cursor:pointer">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: number of hostnames. */
								_n( '%s hostname with no asset in the estate', '%s hostnames with no asset in the estate', count( $unmatched ), 'vulnhub' ),
								number_format_i18n( count( $unmatched ) )
							)
						);
						?>
					</summary>
					<p class="vh-card__meta" style="margin-top:8px;line-height:1.7">
						<?php echo esc_html( implode( ', ', array_slice( $unmatched, 0, 200 ) ) ); ?>
					</p>
				</details>
			<?php endif; ?>

			<p class="vh-actions" style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap">
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( self::COMMIT_ACT ); ?>
					<input type="hidden" name="action" value="<?php echo esc_attr( self::COMMIT_ACT ); ?>">
					<input type="hidden" name="vh_from_portal" value="1">
					<input type="hidden" name="token" value="<?php echo esc_attr( (string) ( $pending['token'] ?? '' ) ); ?>">
					<button type="submit" class="vh-btn vh-btn--primary"><?php esc_html_e( 'Import this file', 'vulnhub' ); ?></button>
				</form>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( self::DISCARD_ACT ); ?>
					<input type="hidden" name="action" value="<?php echo esc_attr( self::DISCARD_ACT ); ?>">
					<input type="hidden" name="vh_from_portal" value="1">
					<input type="hidden" name="token" value="<?php echo esc_attr( (string) ( $pending['token'] ?? '' ) ); ?>">
					<button type="submit" class="vh-btn"><?php esc_html_e( 'Discard', 'vulnhub' ); ?></button>
				</form>
			</p>
		</div>
		<?php
	}

	/**
	 * @param array<string,mixed> $last Last import report.
	 */
	private static function render_last_import( array $last ): void {
		$unmatched = (array) ( $last['unmatched'] ?? array() );
		?>
		<div class="vh-card" style="margin-top:14px">
			<h2><?php esc_html_e( 'Last import', 'vulnhub' ); ?></h2>
			<div class="vh-tablewrap">
				<table class="vh-table">
					<tbody>
						<tr>
							<th scope="row"><?php esc_html_e( 'When', 'vulnhub' ); ?></th>
							<td class="vh-mono"><?php echo esc_html( vh_date( (string) ( $last['at'] ?? '' ) ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'File', 'vulnhub' ); ?></th>
							<td class="vh-mono"><?php echo esc_html( (string) ( $last['file'] ?? '—' ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Rows', 'vulnhub' ); ?></th>
							<td class="vh-mono">
								<?php
								echo esc_html(
									sprintf(
										/* translators: 1: rows created, 2: rows updated. */
										__( '%1$s new, %2$s updated', 'vulnhub' ),
										number_format_i18n( (int) ( $last['imported'] ?? 0 ) ),
										number_format_i18n( (int) ( $last['updated'] ?? 0 ) )
									)
								);
								?>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Matched to an asset', 'vulnhub' ); ?></th>
							<td class="vh-mono">
								<?php
								echo esc_html(
									sprintf(
										/* translators: 1: matched rows, 2: total rows. */
										__( '%1$s of %2$s', 'vulnhub' ),
										number_format_i18n( (int) ( $last['matched'] ?? 0 ) ),
										number_format_i18n( (int) ( $last['rows'] ?? 0 ) )
									)
								);
								?>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Batch', 'vulnhub' ); ?></th>
							<td class="vh-mono"><?php echo esc_html( (string) ( $last['batch'] ?? '—' ) ); ?></td>
						</tr>
					</tbody>
				</table>
			</div>

			<?php if ( $unmatched ) : ?>
				<details style="margin-top:12px">
					<summary style="cursor:pointer">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: number of hostnames. */
								_n( '%s hostname in the programme with no asset', '%s hostnames in the programme with no asset', count( $unmatched ), 'vulnhub' ),
								number_format_i18n( count( $unmatched ) )
							)
						);
						?>
					</summary>
					<p class="vh-card__meta" style="margin-top:8px;line-height:1.7">
						<?php echo esc_html( implode( ', ', array_slice( $unmatched, 0, 200 ) ) ); ?>
					</p>
					<p class="vh-card__meta">
						<?php esc_html_e( 'These are re-checked automatically after every sync, so a machine the scanner picks up later links itself.', 'vulnhub' ); ?>
					</p>
				</details>
			<?php endif; ?>
		</div>
		<?php
	}

	/* =================================================================
	 * Handlers
	 * ============================================================== */

	/**
	 * Back to this section with a message.
	 */
	private static function back( string $message, string $type = 'success' ): void {
		wp_safe_redirect(
			VulnHub_Dash_Portal::portal_url(
				VulnHub_Dash_Portal::ADMIN_VIEW,
				array(
					'section' => self::SECTION,
					'vh_msg'  => $message,
					'vh_type' => $type,
				)
			)
		);
		exit;
	}

	private static function guard( string $action ): void {
		if ( ! is_user_logged_in() || ! current_user_can( Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( $action );
	}

	/**
	 * Take the upload, park it, and show what it would do.
	 */
	public static function handle_upload(): void {
		self::guard( self::UPLOAD_ACT );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$file = isset( $_FILES['eos_csv'] ) ? (array) $_FILES['eos_csv'] : array();

		if ( empty( $file['tmp_name'] ) || ! is_uploaded_file( (string) $file['tmp_name'] ) ) {
			self::back( __( 'No file was uploaded.', 'vulnhub' ), 'error' );
		}

		if ( (int) ( $file['size'] ?? 0 ) > VH_EOS_Import::max_bytes() ) {
			self::back( __( 'That file is too large.', 'vulnhub' ), 'error' );
		}

		$filename = sanitize_file_name( (string) ( $file['name'] ?? 'upload.csv' ) );
		$parked   = self::park( (string) $file['tmp_name'], $filename );

		if ( isset( $parked['error'] ) ) {
			self::back( (string) $parked['error'], 'error' );
		}

		$report = VH_EOS_Import::dry_run( (string) $parked['path'], $filename );

		if ( isset( $report['error'] ) ) {
			self::forget( (string) $parked['token'] );
			self::back( (string) $report['error'], 'error' );
		}

		set_transient(
			self::PENDING_PREFIX . $parked['token'],
			array(
				'token'    => $parked['token'],
				'path'     => $parked['path'],
				'filename' => $filename,
				'report'   => $report,
			),
			HOUR_IN_SECONDS
		);

		update_user_meta( get_current_user_id(), 'vulnhub_eos_pending', (string) $parked['token'] );

		self::back( __( 'Read the file — check the preview, then import it.', 'vulnhub' ) );
	}

	/**
	 * Import the previewed file.
	 */
	public static function handle_commit(): void {
		self::guard( self::COMMIT_ACT );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() checked it.
		$token   = isset( $_POST['token'] ) ? sanitize_key( wp_unslash( (string) $_POST['token'] ) ) : '';
		$pending = $token ? (array) get_transient( self::PENDING_PREFIX . $token ) : array();

		if ( ! $pending || empty( $pending['path'] ) || ! is_readable( (string) $pending['path'] ) ) {
			self::back( __( 'That upload has expired — upload the file again.', 'vulnhub' ), 'error' );
		}

		$report = VH_EOS_Import::import_file( (string) $pending['path'], (string) ( $pending['filename'] ?? '' ) );

		self::forget( $token );

		if ( isset( $report['error'] ) ) {
			self::back( (string) $report['error'], 'error' );
		}

		self::back(
			sprintf(
				/* translators: 1: rows created, 2: rows updated, 3: rows with no matching asset. */
				__( 'Imported the programme data: %1$s new, %2$s updated, %3$s with no matching asset.', 'vulnhub' ),
				number_format_i18n( (int) $report['imported'] ),
				number_format_i18n( (int) $report['updated'] ),
				number_format_i18n( count( (array) $report['unmatched'] ) )
			)
		);
	}

	/**
	 * Throw the previewed file away.
	 */
	public static function handle_discard(): void {
		self::guard( self::DISCARD_ACT );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() checked it.
		$token = isset( $_POST['token'] ) ? sanitize_key( wp_unslash( (string) $_POST['token'] ) ) : '';

		self::forget( $token );
		self::back( __( 'Discarded that upload. Nothing was imported.', 'vulnhub' ) );
	}

	/* =================================================================
	 * Pending upload storage
	 * ============================================================== */

	/**
	 * The current user's previewed upload, if any.
	 *
	 * @return array<string,mixed>
	 */
	private static function pending(): array {
		$token = (string) get_user_meta( get_current_user_id(), 'vulnhub_eos_pending', true );

		if ( '' === $token ) {
			return array();
		}

		$pending = (array) get_transient( self::PENDING_PREFIX . $token );

		if ( ! $pending || empty( $pending['path'] ) || ! is_readable( (string) $pending['path'] ) ) {
			self::forget( $token );

			return array();
		}

		return $pending;
	}

	/**
	 * Move an upload somewhere it will survive the redirect.
	 *
	 * The directory is guarded the same way the sync staging area is: raw
	 * inventory data should never be fetchable over HTTP.
	 *
	 * @return array{token?:string,path?:string,error?:string}
	 */
	private static function park( string $tmp, string $filename ): array {
		$uploads = wp_upload_dir();

		if ( ! empty( $uploads['error'] ) ) {
			return array( 'error' => __( 'The uploads directory is not writable.', 'vulnhub' ) );
		}

		$dir = trailingslashit( (string) $uploads['basedir'] ) . 'vulnhub-eos';

		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return array( 'error' => __( 'Could not create the upload directory.', 'vulnhub' ) );
		}

		foreach ( array(
			'index.php' => "<?php\n// Silence is golden.\n",
			'.htaccess' => "Require all denied\n",
		) as $guard => $contents ) {
			if ( ! file_exists( $dir . '/' . $guard ) ) {
				file_put_contents( $dir . '/' . $guard, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}

		$token = wp_generate_password( 16, false, false );
		$path  = $dir . '/pending-' . $token . '.csv';

		if ( ! @move_uploaded_file( $tmp, $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return array( 'error' => __( 'Could not store the uploaded file.', 'vulnhub' ) );
		}

		unset( $filename );

		return array(
			'token' => $token,
			'path'  => $path,
		);
	}

	/**
	 * Drop a pending upload and its file.
	 */
	private static function forget( string $token ): void {
		if ( '' === $token ) {
			return;
		}

		$pending = (array) get_transient( self::PENDING_PREFIX . $token );

		if ( ! empty( $pending['path'] ) && is_file( (string) $pending['path'] ) ) {
			@unlink( (string) $pending['path'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		}

		delete_transient( self::PENDING_PREFIX . $token );
		delete_user_meta( get_current_user_id(), 'vulnhub_eos_pending' );
	}
}
