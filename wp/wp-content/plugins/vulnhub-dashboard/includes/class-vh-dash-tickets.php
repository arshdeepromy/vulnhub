<?php
/**
 * Scope tickets: "this list, as a request somebody else has to action".
 *
 * Most work that comes out of the asset list is not a vulnerability fix. It is
 * "get these 74 workstations into Tenable", "these CMDB rows are machines that
 * left years ago", "Intune has never heard of these". That work is raised in
 * Jira Service Management by hand, and until now the portal forgot about it
 * the moment the CSV downloaded.
 *
 * So the Raise ticket dialog does two things from one form: hands over the
 * CSV (the same file, and the same column picker, as Export CSV), and -- once
 * the JSM request exists -- records its key against a snapshot of exactly the
 * assets that were on screen. The ticket page then answers the only question
 * anybody asks of such a ticket: of the machines we asked about, which are
 * done, which are still outstanding, and which stopped mattering because they
 * were decommissioned.
 *
 * FUTURE JSM INTEGRATION
 *
 * Rows are written with provider `jsm` and the same status categories the Jira
 * poller uses (new / indeterminate / done), and nothing polls them yet -- the
 * Jira connector only refreshes provider `jira`. A JSM sync needs to refresh
 * provider `jsm` rows, and can start the moment one is recorded from the
 * `vulnhub_scope_ticket_recorded` action. See docs/TICKETS.md.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Coverage;
use VulnHub\Core\Agent_Coverage;
use VulnHub\Core\Defender_Coverage;
use VulnHub\Core\Repo;
use VulnHub\Core\Tickets;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The raise dialog, its handlers, and the ticket page.
 */
final class VulnHub_Dash_Tickets {

	public const ACTION_SCOPE  = 'vulnhub_ticket_scope';
	public const ACTION_STATUS = 'vulnhub_ticket_status';

	/**
	 * Most assets one ticket may snapshot.
	 *
	 * Refused above this rather than truncated: a ticket that silently holds
	 * the first 10,000 of 14,000 machines would report the other 4,000 as
	 * never having been asked about.
	 */
	private const MAX_ASSETS = 10000;

	/** Rows per repository call; the repository's own ceiling. */
	private const PAGE = 500;

	/** Asset rows per page on the ticket screen. */
	private const PER = 50;

	/**
	 * The query keys the assets screen reads. Stored with the ticket so the
	 * list can be reopened exactly as it was asked.
	 */
	private const ASSET_QUERY_KEYS = array(
		'search', 'asset_type', 'team_id', 'location_id', 'coverage', 'agent', 'defender', 'known',
		'hosting', 'life', 'needs_user', 'primary_source', 'operating_system', 'patch_group',
		'eol', 'has', 'missing', 'orderby', 'order',
	);

	public static function init(): void {
		add_action( 'admin_post_' . self::ACTION_SCOPE, array( __CLASS__, 'handle_scope' ) );
		add_action( 'admin_post_' . self::ACTION_STATUS, array( __CLASS__, 'handle_status' ) );

		// Asset-list tickets raised in Jira share the ticketer's review flow.
		// Priority 5 so this answers asset drafts before the finding drafter.
		add_filter( 'vulnhub_draft_ticket', array( __CLASS__, 'draft_assets' ), 5, 2 );
		add_filter( 'vulnhub_ticket_page_url', static fn( string $url, int $id ): string => $id ? self::page_url( 'tickets', array( 'ticket' => $id ) ) : $url, 10, 2 );
	}

	private static function page_url( string $view, array $args = array() ): string {
		$pages = (array) get_option( 'vulnhub_dash_pages', array() );
		$base  = ! empty( $pages[ $view ] ) ? (string) get_permalink( (int) $pages[ $view ] ) : home_url( '/' );

		return $args ? add_query_arg( $args, $base ) : $base;
	}

	private static function q( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET[ $key ] ) && ! is_array( $_GET[ $key ] ) ? sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) ) : '';
	}

	/**
	 * The assets screen's own filters from the current request.
	 *
	 * @return array<string,string>
	 */
	private static function asset_query(): array {
		$out = array();

		foreach ( self::ASSET_QUERY_KEYS as $key ) {
			$value = self::q( $key );

			if ( '' !== $value && ! ( 'team_id' === $key && '0' === $value ) ) {
				$out[ $key ] = $value;
			}
		}

		return $out;
	}

	/**
	 * The filters of an assets query, in words.
	 *
	 * @param array<string,string> $query Raw assets-screen query.
	 * @return array<int,string>
	 */
	public static function describe_filters( array $query ): array {
		$out     = array();
		$sources = vh_asset_sources();

		foreach ( $query as $key => $value ) {
			switch ( $key ) {
				case 'search':
					/* translators: %s: search text. */
					$out[] = sprintf( __( 'Matching "%s"', 'vulnhub' ), $value );
					break;
				case 'asset_type':
					$out[] = __( 'Type', 'vulnhub' ) . ': ' . vh_asset_type_label( $value );
					break;
				case 'team_id':
					$out[] = __( 'Team', 'vulnhub' ) . ': ' . (string) ( Repo::team( (int) $value )['name'] ?? $value );
					break;
				case 'location_id':
					$out[] = __( 'Site', 'vulnhub' ) . ': ' . ( 'none' === $value ? __( 'No site recorded', 'vulnhub' ) : (string) ( Repo::location( (int) $value )['name'] ?? $value ) );
					break;
				case 'coverage':
					$out[] = __( 'Scan coverage', 'vulnhub' ) . ': ' . ( 'gap' === $value ? __( 'Any coverage gap', 'vulnhub' ) : Coverage::label( $value ) );
					break;

				case 'agent':
					$out[] = __( 'Tenable agent', 'vulnhub' ) . ': ' . ( 'gap' === $value ? __( 'Needs an agent', 'vulnhub' ) : Agent_Coverage::label( $value ) );
					break;
				case 'defender':
					$out[] = __( 'Endpoint', 'vulnhub' ) . ': ' . ( 'gap' === $value ? __( 'No Defender sensor', 'vulnhub' ) : Defender_Coverage::label( $value ) );
					break;
				case 'known':
					$bare = (string) preg_replace( '/^(only|not):/', '', $value );
					$name = (string) ( $sources[ $bare ] ?? $bare );
					/* translators: %s: name of a source system. */
					$out[] = str_starts_with( $value, 'only:' ) ? sprintf( __( 'Known only by %s', 'vulnhub' ), $name )
						/* translators: %s: name of a source system. */
						: ( str_starts_with( $value, 'not:' ) ? sprintf( __( 'Not in %s', 'vulnhub' ), $name )
						/* translators: %s: name of a source system. */
						: sprintf( __( 'Known by %s', 'vulnhub' ), $name ) );
					break;
				case 'has':
				case 'missing':
					$names = array_map( static fn( string $s ): string => (string) ( $sources[ $s ] ?? $s ), Repo::source_slugs( $value ) );
					/* translators: %s: one or more source systems. */
					$out[] = sprintf( 'has' === $key ? __( 'In %s', 'vulnhub' ) : __( 'Not in %s', 'vulnhub' ), implode( ', ', $names ) );
					break;
				case 'life':
					$life = array(
						'reportable'     => __( 'Reporting scope', 'vulnhub' ),
						'in_service_all' => __( 'Everything with an owner expectation', 'vulnhub' ),
						'all'            => __( 'Everything, including retired', 'vulnhub' ),
						'not_reported'   => __( 'Outside the reporting scope', 'vulnhub' ),
						'retired_all'    => __( 'Out of service only', 'vulnhub' ),
					);
					$out[] = __( 'Lifecycle', 'vulnhub' ) . ': ' . (string) ( $life[ $value ] ?? ( vh_lifecycle_statuses()[ $value ]['label'] ?? $value ) );
					break;
				case 'needs_user':
					$out[] = __( 'Missing a user', 'vulnhub' );
					break;
				case 'hosting':
					$labels = class_exists( 'VulnHub_Hosting' ) ? VulnHub_Hosting::environment_labels() : array();
					$out[]  = __( 'Hosting', 'vulnhub' ) . ': ' . (string) ( $labels[ $value ] ?? $value );
					break;
				case 'primary_source':
					$out[] = __( 'Discovered by', 'vulnhub' ) . ': ' . (string) ( $sources[ $value ] ?? $value );
					break;
				case 'operating_system':
					$out[] = __( 'Operating system', 'vulnhub' ) . ': ' . $value;
					break;
				case 'patch_group':
					$out[] = __( 'Patch group', 'vulnhub' ) . ': ' . $value;
					break;
				case 'eol':
					$out[] = __( 'End-of-life release', 'vulnhub' ) . ': ' . $value;
					break;
			}
		}

		if ( ! isset( $query['life'] ) ) {
			$out[] = __( 'Lifecycle', 'vulnhub' ) . ': ' . __( 'Reporting scope', 'vulnhub' );
		}

		return $out;
	}

	/* =================================================================
	 * The button and dialog
	 * ============================================================== */

	/**
	 * Raise ticket: a button, and the dialog it opens.
	 *
	 * The button is a real link (?raise_ticket=1) and the dialog is rendered
	 * open when that parameter is present, so it works with scripting off --
	 * app.js only upgrades the link into showModal().
	 *
	 * @param array<string,mixed> $args  The assets query, as the list ran it.
	 * @param int                 $total Rows that query matches.
	 */
	public static function raise_button( array $args, int $total ): void {
		if ( ! current_user_can( Caps::VIEW ) ) {
			return;
		}

		$can_save = current_user_can( Caps::RAISE_TICKET );
		$open     = '1' === self::q( 'raise_ticket' );
		$error    = self::q( 'vh_ticket_err' );
		$filters  = self::describe_filters( self::asset_query() );
		$kinds    = array_filter( Tickets::kinds(), static fn( array $k ): bool => ! empty( $k['scope'] ) );
		$href     = add_query_arg( 'raise_ticket', '1' );
		?>
		<div class="vh-raise">
			<a class="vh-btn vh-btn--primary vh-btn--sm" href="<?php echo esc_url( $href ); ?>" data-vh-dialog="vh-raise-ticket">
				<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" width="14" height="14">
					<path d="M4 7a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 000 4v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2a2 2 0 000-4zM13 5v2m0 4v2m0 4v2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>
				<?php esc_html_e( 'Raise Jira ticket', 'vulnhub' ); ?>
			</a>
			<span class="vh-sub vh-muted">
				<?php
				printf(
					/* translators: %s: number of assets. */
					esc_html( _n( 'for the %s asset below', 'for the %s assets below', $total, 'vulnhub' ) ),
					esc_html( number_format_i18n( $total ) )
				);
				?>
			</span>
		</div>

		<dialog id="vh-raise-ticket" class="vh-modal vh-raise__dialog" <?php echo $open ? 'open' : ''; ?> aria-labelledby="vh-raise-title">
			<form method="dialog" class="vh-modal__x">
				<button aria-label="<?php esc_attr_e( 'Close', 'vulnhub' ); ?>">&times;</button>
			</form>

			<h2 id="vh-raise-title"><?php esc_html_e( 'Raise a Jira ticket for this list', 'vulnhub' ); ?></h2>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-raise__form">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_SCOPE ); ?>">
				<?php wp_nonce_field( self::ACTION_SCOPE ); ?>
				<input type="hidden" name="back" value="<?php echo esc_url( remove_query_arg( array( 'raise_ticket', 'vh_ticket_err', 'ap' ) ) ); ?>">
				<?php foreach ( VulnHub_Dash_Export::carried( $args ) as $vh_k => $vh_v ) : ?>
					<input type="hidden" name="f[<?php echo esc_attr( (string) $vh_k ); ?>]" value="<?php echo esc_attr( $vh_v ); ?>">
				<?php endforeach; ?>
				<?php foreach ( self::asset_query() as $vh_k => $vh_v ) : ?>
					<input type="hidden" name="q[<?php echo esc_attr( (string) $vh_k ); ?>]" value="<?php echo esc_attr( $vh_v ); ?>">
				<?php endforeach; ?>

				<?php if ( '' !== $error ) : ?>
					<p class="vh-notice vh-notice--warn" role="alert"><?php echo esc_html( $error ); ?></p>
				<?php endif; ?>

				<?php $vh_jira_on_step1 = function_exists( 'vulnhub_jira_connector' ) && vulnhub_jira_connector() && vulnhub_jira_connector()->is_enabled(); ?>

				<section class="vh-raise__step">
					<h3><span class="vh-raise__n">1</span> <?php esc_html_e( 'The list that gets attached', 'vulnhub' ); ?></h3>
					<p class="vh-export__scope">
						<?php
						printf(
							/* translators: %s: number of assets. */
							esc_html( _n( '%s asset matches these filters:', '%s assets match these filters:', $total, 'vulnhub' ) ),
							'<strong>' . esc_html( number_format_i18n( $total ) ) . '</strong>'
						);
						?>
						<?php echo esc_html( implode( ' · ', $filters ) ); ?>
					</p>

					<?php
					/*
					 * Say that the file is attached, here, where the columns
					 * are picked. The step read as "download it yourself and
					 * attach it by hand" -- the one thing it does not mean --
					 * because the only CSV on the screen was a button marked
					 * Download and nothing said what the ticks were for.
					 */
					if ( $vh_jira_on_step1 ) :
						?>
						<p class="vh-sub vh-muted">
							<?php
							printf(
								/* translators: %s: number of rows. */
								esc_html( _n( 'These columns are the CSV that VulnHub attaches when it raises the ticket in Jira: %s row, one per asset. You see the exact file, with a preview, and can still change the columns in the review before anything is sent. Download CSV here is only a copy for yourself.', 'These columns are the CSV that VulnHub attaches when it raises the ticket in Jira: %s rows, one per asset. You see the exact file, with a preview, and can still change the columns in the review before anything is sent. Download CSV here is only a copy for yourself.', $total, 'vulnhub' ) ),
								'<strong>' . esc_html( number_format_i18n( $total ) ) . '</strong>'
							);
							?>
						</p>
					<?php endif; ?>

					<div class="vh-export__head">
						<strong><?php esc_html_e( 'Columns to include', 'vulnhub' ); ?></strong>
						<span class="vh-export__toggles">
							<button type="button" class="vh-linkbtn" data-vh-cols="all"><?php esc_html_e( 'All', 'vulnhub' ); ?></button>
							<button type="button" class="vh-linkbtn" data-vh-cols="none"><?php esc_html_e( 'None', 'vulnhub' ); ?></button>
						</span>
						<button type="submit" name="do" value="download" class="vh-btn vh-btn--ghost vh-btn--sm" formnovalidate><?php esc_html_e( 'Download CSV', 'vulnhub' ); ?></button>
					</div>
					<?php VulnHub_Dash_Export::column_picker( 'assets' ); ?>
				</section>

				<?php if ( $can_save ) : ?>
					<?php
					$vh_jira_on = function_exists( 'vulnhub_jira_connector' ) && vulnhub_jira_connector() && vulnhub_jira_connector()->is_enabled();
					?>
					<section class="vh-raise__step">
						<h3><span class="vh-raise__n">2</span> <?php esc_html_e( 'Describe the request', 'vulnhub' ); ?></h3>
						<p class="vh-sub vh-muted"><?php esc_html_e( 'The assets above are saved with the ticket, so its page can show which are done, which are still outstanding and which were retired.', 'vulnhub' ); ?></p>

						<div class="vh-raise__grid">
							<label>
								<span><?php esc_html_e( 'Request type', 'vulnhub' ); ?></span>
								<select name="kind">
									<?php foreach ( $kinds as $vh_kind => $vh_def ) : ?>
										<option value="<?php echo esc_attr( (string) $vh_kind ); ?>" title="<?php echo esc_attr( (string) $vh_def['help'] ); ?>" <?php selected( self::guess_kind(), (string) $vh_kind ); ?>>
											<?php echo esc_html( (string) $vh_def['label'] ); ?>
										</option>
									<?php endforeach; ?>
								</select>
							</label>
							<label class="vh-raise__wide">
								<span><?php esc_html_e( 'Summary', 'vulnhub' ); ?></span>
								<input type="text" name="summary" maxlength="255" placeholder="<?php esc_attr_e( 'Defaults to the request type and the filters', 'vulnhub' ); ?>">
							</label>
							<label class="vh-raise__wide">
								<span><?php esc_html_e( 'Notes', 'vulnhub' ); ?></span>
								<textarea name="notes" rows="2"></textarea>
							</label>
						</div>

						<?php if ( $vh_jira_on ) : ?>
							<div class="vh-modal__foot">
								<button type="button" class="vh-btn vh-btn--primary" data-vh-raise-scope><?php esc_html_e( 'Review and create in Jira', 'vulnhub' ); ?></button>
								<span class="vh-sub vh-muted"><?php esc_html_e( 'Shows everything that will be sent, with the CSV above attached. Nothing is sent until you press Send.', 'vulnhub' ); ?></span>
							</div>
						<?php endif; ?>

						<details class="vh-raise__manual" <?php echo ( ! $vh_jira_on || '' !== self::q( 'vh_ticket_key' ) ) ? 'open' : ''; ?>>
							<summary><?php esc_html_e( 'I already raised it in JSM', 'vulnhub' ); ?></summary>
							<p class="vh-sub vh-muted"><?php esc_html_e( 'Raised the request by hand? Enter its key to track these assets against it. Nothing is sent to Jira.', 'vulnhub' ); ?></p>
							<div class="vh-raise__grid">
								<label>
									<span><?php esc_html_e( 'JSM ticket', 'vulnhub' ); ?> *</span>
									<input type="text" name="ticket_key" autocomplete="off" spellcheck="false" placeholder="SD-1234"
										pattern="\s*(https?://\S+/)?[A-Za-z][A-Za-z0-9_]*-[0-9]+\s*"
										title="<?php esc_attr_e( 'A Jira issue key such as SD-1234, or its link.', 'vulnhub' ); ?>"
										value="<?php echo esc_attr( self::q( 'vh_ticket_key' ) ); ?>">
								</label>
							</div>
							<div class="vh-modal__foot">
								<button type="submit" name="do" value="save" class="vh-btn"><?php esc_html_e( 'Save ticket', 'vulnhub' ); ?></button>
								<span class="vh-sub vh-muted"><?php esc_html_e( 'It will appear under Tickets.', 'vulnhub' ); ?></span>
							</div>
						</details>
					</section>
				<?php endif; ?>
			</form>
		</dialog>
		<?php
	}

	/**
	 * The request type the current filters most likely mean.
	 */
	private static function guess_kind(): string {
		$known = self::q( 'known' );

		return match ( true ) {
			'' !== self::q( 'agent' )      => 'tenable_agent',
			'' !== self::q( 'coverage' )   => 'tenable_coverage',
			'' !== self::q( 'defender' )   => 'defender_coverage',
			'not:cmdb' === $known, str_contains( self::q( 'missing' ), 'cmdb' ) => 'cmdb_gap',
			'not:intune' === $known, str_contains( self::q( 'missing' ), 'intune' ) => 'intune_gap',
			'not_reported' === self::q( 'life' ), str_starts_with( $known, 'only:' ) => 'cleanup',
			default                        => 'tenable_coverage',
		};
	}

	/* =================================================================
	 * The handlers
	 * ============================================================== */

	/**
	 * @return array<string,string>
	 */
	private static function posted_map( string $key ): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified by the caller.
		$raw = isset( $_POST[ $key ] ) && is_array( $_POST[ $key ] ) ? wp_unslash( $_POST[ $key ] ) : array();
		$out = array();

		foreach ( $raw as $k => $v ) {
			$name = sanitize_key( (string) $k );

			if ( '' !== $name && ! is_array( $v ) ) {
				$out[ $name ] = sanitize_text_field( (string) $v );
			}
		}

		return $out;
	}

	private static function posted( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified by the caller.
		return isset( $_POST[ $key ] ) && ! is_array( $_POST[ $key ] ) ? (string) wp_unslash( $_POST[ $key ] ) : '';
	}

	/**
	 * Every asset a set of Assets-screen filters matches, or why not.
	 *
	 * The whole list or nothing: paged to the repository's ceiling and
	 * compared against the total afterwards, because a short read saved as a
	 * ticket's scope would report the missing machines as never asked about.
	 *
	 * @param array<string,string> $filters Export arguments (resolved filters).
	 * @return array{ok:bool,message:string,total:int,assets:array<int,array<string,mixed>>}
	 */
	private static function collect_assets( array $filters ): array {
		$base  = array_filter( $filters, static fn( string $v ): bool => '' !== $v );
		$total = (int) ( Repo::assets( array_merge( $base, array( 'limit' => 1 ) ) )['total'] ?? 0 );
		$out   = array( 'ok' => false, 'message' => '', 'total' => $total, 'assets' => array() );

		if ( 0 === $total ) {
			$out['message'] = __( 'These filters match no assets, so there is nothing to attach the ticket to.', 'vulnhub' );
			return $out;
		}

		if ( $total > self::MAX_ASSETS ) {
			/* translators: 1: number of assets, 2: the limit. */
			$out['message'] = sprintf( __( 'These filters match %1$s assets; one ticket can hold at most %2$s. Narrow the list first.', 'vulnhub' ), number_format_i18n( $total ), number_format_i18n( self::MAX_ASSETS ) );
			return $out;
		}

		$assets = array();

		for ( $offset = 0; $offset < $total; $offset += self::PAGE ) {
			$page = (array) ( Repo::assets( array_merge( $base, array( 'limit' => self::PAGE, 'offset' => $offset ) ) )['rows'] ?? array() );

			if ( ! $page ) {
				break;
			}

			foreach ( $page as $row ) {
				$assets[ (int) $row['id'] ] = $row;
			}
		}

		if ( count( $assets ) !== $total ) {
			/* translators: 1: rows read, 2: rows expected. */
			$out['message'] = sprintf( __( 'The asset list changed while it was being read (%1$s of %2$s). Nothing was saved; try again.', 'vulnhub' ), number_format_i18n( count( $assets ) ), number_format_i18n( $total ) );
			return $out;
		}

		$out['ok']     = true;
		$out['assets'] = array_values( $assets );

		return $out;
	}

	/**
	 * A ticket summary when the operator gave none.
	 *
	 * @param string[] $words Filters in words.
	 */
	private static function default_summary( string $kind_label, int $total, array $words ): string {
		return vh_trim(
			sprintf(
				/* translators: 1: request type, 2: number of assets, 3: the filters in words. */
				_n( '%1$s: %2$s asset (%3$s)', '%1$s: %2$s assets (%3$s)', $total, 'vulnhub' ),
				$kind_label,
				number_format_i18n( $total ),
				implode( ', ', $words )
			),
			250
		);
	}

	/**
	 * Answer `vulnhub_draft_ticket` for an asset list: build the Jira ticket
	 * and its asset CSV for review. Nothing is sent.
	 *
	 * @param array<string,mixed>|null $result Result so far.
	 * @param array<string,mixed>      $params scope=assets, kind, filters, query, cols, summary, notes.
	 * @return array<string,mixed>|null
	 */
	public static function draft_assets( ?array $result, array $params ): ?array {
		if ( null !== $result || 'assets' !== ( $params['scope'] ?? '' ) ) {
			return $result;
		}

		$fail = static fn( string $message ): array => array( 'ok' => false, 'message' => $message );

		if ( ! function_exists( 'vulnhub_jira_connector' ) || ! vulnhub_jira_connector() || ! vulnhub_jira_connector()->is_enabled() ) {
			return $fail( __( 'Jira is not enabled, so this can only be recorded by hand: use "I already raised it in JSM".', 'vulnhub' ) );
		}

		$kinds = Tickets::kinds();
		$kind  = sanitize_key( (string) ( $params['kind'] ?? '' ) );

		if ( empty( $kinds[ $kind ]['scope'] ) ) {
			return $fail( __( 'Choose a request type.', 'vulnhub' ) );
		}

		$due_date = vh_valid_due_date( (string) ( $params['due_date'] ?? '' ) );

		if ( '' !== (string) ( $params['due_date'] ?? '' ) && '' === $due_date ) {
			return $fail( __( 'The due date must be a real date, today or later.', 'vulnhub' ) );
		}

		$clean = static function ( $raw, array $allow = array() ): array {
			$out = array();

			foreach ( (array) $raw as $k => $v ) {
				$name = sanitize_key( (string) $k );

				if ( '' !== $name && is_scalar( $v ) && ( ! $allow || in_array( $name, $allow, true ) ) ) {
					$out[ $name ] = sanitize_text_field( (string) $v );
				}
			}

			return $out;
		};

		$filters = $clean( $params['filters'] ?? array() );
		$query   = $clean( $params['query'] ?? array(), self::ASSET_QUERY_KEYS );
		$found   = self::collect_assets( $filters );

		if ( ! $found['ok'] ) {
			return $fail( $found['message'] );
		}

		$words   = self::describe_filters( $query );
		$total   = $found['total'];
		$summary = trim( sanitize_text_field( (string) ( $params['summary'] ?? '' ) ) );
		$summary = '' !== $summary ? $summary : self::default_summary( (string) $kinds[ $kind ]['label'], $total, $words );
		$notes   = sanitize_textarea_field( (string) ( $params['notes'] ?? '' ) );
		$ids     = array_map( static fn( array $a ): int => (int) $a['id'], $found['assets'] );
		$cols    = array_map( 'sanitize_key', (array) ( $params['cols'] ?? array() ) );
		$csv     = VulnHub_Dash_Export::assets_csv( $ids, $cols );

		$csv['name'] = sprintf( 'assets-%s-%s.csv', str_replace( '_', '-', $kind ), wp_date( 'Y-m-d-Hi' ) );

		// Names for the assets the description lists; the rest are in the file.
		$described = array();
		$locations = array_column( Repo::locations(), 'name', 'id' );

		foreach ( array_slice( $found['assets'], 0, 30 ) as $a ) {
			$described[] = array(
				'id'               => (int) $a['id'],
				'hostname'         => (string) $a['hostname'],
				'ipv4'             => (string) $a['ipv4'],
				'asset_type'       => (string) $a['asset_type'],
				'operating_system' => (string) $a['operating_system'],
				'site'             => (string) ( $locations[ (int) $a['location_id'] ] ?? '' ),
				'owner'            => (string) ( Repo::person( (int) $a['owner_person_id'] )['display_name'] ?? '' ),
				'team'             => (string) ( Repo::team( (int) $a['team_id'] )['name'] ?? '' ),
			);
		}

		$built = vulnhub_jira_ticketer()->build_scope_issue(
			array(
				'kind'       => $kind,
				'kind_label' => (string) $kinds[ $kind ]['label'],
				'kind_help'  => (string) $kinds[ $kind ]['help'],
				'summary'    => $summary,
				'notes'      => $notes,
				'filters'    => $words,
				'total'      => $total,
				'assets'     => $described,
				'attachment' => $csv['name'],
				'due_date'   => $due_date,
				'priority'   => VulnHub_Jira_Ticketer::priority_choice( $params )['value'],
			)
		);

		if ( empty( $built['ok'] ) ) {
			return $fail( (string) $built['message'] );
		}

		// The whole snapshot, for the per-asset tracking the ticket page shows.
		$built['group_key'] = 'assets:' . md5( implode( ',', $ids ) );
		$built              = vulnhub_jira_ticketer()->apply_review_selects( vulnhub_jira_connector(), $built, $params );
		$built              = vulnhub_jira_ticketer()->apply_description_edit( $built, $params );

		$warnings = array();

		if ( $csv['rows'] !== $total ) {
			/* translators: 1: rows in the file, 2: assets on the ticket. */
			$warnings[] = sprintf( __( 'The attachment has %1$d rows but the ticket covers %2$d assets. Review again before sending.', 'vulnhub' ), $csv['rows'], $total );
		}

		$snapshot = array_map(
			static fn( array $a ): array => array(
				'id'                      => (int) $a['id'],
				'hostname'                => (string) $a['hostname'],
				'asset_type'              => (string) $a['asset_type'],
				'coverage_state'          => (string) $a['coverage_state'],
				'defender_coverage_state' => (string) $a['defender_coverage_state'],
				'lifecycle_status'        => (string) $a['lifecycle_status'],
				'sources_json'            => (string) $a['sources_json'],
			),
			$found['assets']
		);

		return vulnhub_jira_ticketer()->present_draft(
			vulnhub_jira_connector(),
			$built,
			$csv,
			array(
				'kind'       => 'assets',
				'selected'   => $total,
				'eligible'   => $total,
				'skipped'    => 0,
				'on_tickets' => array(),
				'assets'     => $total,
				'request'    => (string) $kinds[ $kind ]['label'],
			),
			$warnings,
			array(
				'type'    => 'assets',
				'kind'    => $kind,
				'notes'   => $notes,
				'team_id' => (int) ( $query['team_id'] ?? 0 ),
				'assets'  => $snapshot,
				'scope'   => array(
					'view'    => 'assets',
					'args'    => $filters,
					'query'   => $query,
					'cols'    => array_keys( $csv['columns'] ),
					'filters' => $words,
				),
			),
			'assets'
		);
	}

	public static function handle_scope(): void {
		if ( ! is_user_logged_in() || ! current_user_can( Caps::VIEW ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION_SCOPE );

		$filters = self::posted_map( 'f' );
		$query   = array_intersect_key( self::posted_map( 'q' ), array_flip( self::ASSET_QUERY_KEYS ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$cols    = isset( $_POST['cols'] ) && is_array( $_POST['cols'] ) ? array_values( array_intersect( array_keys( VulnHub_Dash_Export::columns( 'assets' ) ), array_map( 'sanitize_key', wp_unslash( $_POST['cols'] ) ) ) ) : array();
		$back    = wp_validate_redirect( esc_url_raw( self::posted( 'back' ) ), self::page_url( 'assets' ) );

		/*
		 * Download: hand over to the export handler rather than streaming
		 * from here, so the file is byte-for-byte what Export CSV gives for
		 * the same filters and columns -- and is audited the same way.
		 */
		if ( 'save' !== self::posted( 'do' ) ) {
			wp_safe_redirect( self::export_url( $filters, $cols ) );
			exit;
		}

		if ( ! current_user_can( Caps::RAISE_TICKET ) ) {
			wp_die( esc_html__( 'You do not have permission to record tickets.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		$fail = static function ( string $message, string $key = '' ) use ( $back ): void {
			wp_safe_redirect(
				add_query_arg(
					array_filter(
						array(
							'raise_ticket'  => '1',
							'vh_ticket_err' => rawurlencode( $message ),
							'vh_ticket_key' => rawurlencode( $key ),
						)
					),
					$back
				)
			);
			exit;
		};

		$typed = trim( self::posted( 'ticket_key' ) );
		$key   = preg_match( '/([A-Za-z][A-Za-z0-9_]*-[1-9][0-9]*)\s*$/', $typed, $m ) ? strtoupper( $m[1] ) : '';

		if ( '' === $key || strlen( $key ) > 64 ) {
			$fail( __( 'Enter the JSM ticket key, for example SD-1234.', 'vulnhub' ), $typed );
		}

		$existing = Tickets::by_key( $key, Tickets::PROVIDER_JSM );

		if ( $existing ) {
			/* translators: %s: ticket key. */
			$fail( sprintf( __( '%s is already recorded. Open it from Tickets to see its assets.', 'vulnhub' ), $key ), $typed );
		}

		$kinds = Tickets::kinds();
		$kind  = sanitize_key( self::posted( 'kind' ) );

		if ( empty( $kinds[ $kind ]['scope'] ) ) {
			$fail( __( 'Choose a request type.', 'vulnhub' ), $typed );
		}

		$found = self::collect_assets( $filters );

		if ( ! $found['ok'] ) {
			$fail( $found['message'], $typed );
		}

		$assets = $found['assets'];
		$total  = $found['total'];

		$words   = self::describe_filters( $query );
		$summary = trim( sanitize_text_field( self::posted( 'summary' ) ) );

		if ( '' === $summary ) {
			$summary = self::default_summary( (string) $kinds[ $kind ]['label'], $total, $words );
		}

		$saved = Tickets::upsert(
			array(
				'provider'        => Tickets::PROVIDER_JSM,
				'external_key'    => $key,
				'project_key'     => (string) strtok( $key, '-' ),
				'url'             => self::browse_url( $key, $typed ),
				'issue_type'      => (string) $kinds[ $kind ]['label'],
				'summary'         => $summary,
				'status'          => Tickets::manual_statuses()['new'],
				'status_category' => 'new',
				'reporter'        => wp_get_current_user()->display_name,
				'team_id'         => (int) ( $query['team_id'] ?? 0 ),
				'created_by'      => get_current_user_id(),
				'created_via'     => 'manual',
				'kind'            => $kind,
				'source_view'     => 'assets',
				'notes'           => sanitize_textarea_field( self::posted( 'notes' ) ),
				'scope'           => array(
					'view'    => 'assets',
					'args'    => $filters,
					'query'   => $query,
					'cols'    => $cols,
					'filters' => $words,
				),
			)
		);

		Tickets::attach_assets( (int) $saved['id'], array_values( $assets ) );

		vulnhub()->logger->audit(
			'ticket.scope_recorded',
			sprintf(
				/* translators: 1: ticket key, 2: request type, 3: number of assets. */
				__( 'Recorded %1$s (%2$s) against %3$d assets', 'vulnhub' ),
				$key,
				(string) $kinds[ $kind ]['label'],
				$total
			),
			'ticket',
			(int) $saved['id'],
			array(
				'kind'    => $kind,
				'query'   => $query,
				'assets'  => $total,
			)
		);

		/**
		 * A scope ticket was recorded. The hook a JSM integration uses to
		 * fetch the request's real status, assignee and summary straight away.
		 *
		 * @param int $ticket_id Ticket row id.
		 */
		do_action( 'vulnhub_scope_ticket_recorded', (int) $saved['id'] );

		wp_safe_redirect(
			self::page_url(
				'tickets',
				array(
					'ticket' => (int) $saved['id'],
					'vh_msg' => rawurlencode(
						sprintf(
							/* translators: 1: ticket key, 2: number of assets. */
							_n( '%1$s recorded with %2$s asset.', '%1$s recorded with %2$s assets.', $total, 'vulnhub' ),
							$key,
							number_format_i18n( $total )
						)
					),
				)
			)
		);
		exit;
	}

	public static function handle_status(): void {
		if ( ! is_user_logged_in() || ! current_user_can( Caps::RAISE_TICKET ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION_STATUS );

		$id       = (int) self::posted( 'ticket' );
		$category = sanitize_key( self::posted( 'status_category' ) );
		$before   = Tickets::get( $id );
		$ok       = Tickets::set_manual_status( $id, $category, sanitize_textarea_field( self::posted( 'notes' ) ) );

		if ( $ok && $before && (string) $before['status_category'] !== $category ) {
			vulnhub()->logger->audit(
				'ticket.status_changed',
				sprintf(
					/* translators: 1: ticket key, 2: new status. */
					__( '%1$s moved to %2$s', 'vulnhub' ),
					(string) $before['external_key'],
					Tickets::manual_statuses()[ $category ] ?? $category
				),
				'ticket',
				$id,
				array( 'from' => (string) $before['status_category'], 'to' => $category )
			);
		}

		wp_safe_redirect(
			self::page_url(
				'tickets',
				array(
					'ticket' => $id,
					'vh_msg' => rawurlencode( $ok ? __( 'Ticket updated.', 'vulnhub' ) : __( 'That ticket cannot be edited here.', 'vulnhub' ) ),
				)
			)
		);
		exit;
	}

	/**
	 * @param array<string,string> $filters Export arguments.
	 * @param string[]             $cols    Chosen columns.
	 */
	private static function export_url( array $filters, array $cols ): string {
		// wp_nonce_url() escapes its ampersands for HTML. Right inside an
		// href, wrong in a Location header, where `&amp;view=` is a parameter
		// named `amp;view` and the export handler finds no view at all.
		$url = str_replace( '&amp;', '&', VulnHub_Dash_Export::url( 'assets', $filters ) );

		return $cols ? add_query_arg( array( 'cols' => $cols ), $url ) : $url;
	}

	/**
	 * Where a human opens the request.
	 *
	 * A pasted link wins, because it is the address the operator actually
	 * used (a JSM customer portal URL, say). Otherwise the Jira site the
	 * Jira connector is configured for, which serves JSM issues at /browse
	 * too. With neither, no link rather than a guessed one.
	 */
	private static function browse_url( string $key, string $typed ): string {
		if ( preg_match( '#^https?://#i', $typed ) ) {
			return esc_url_raw( $typed );
		}

		$jira = vulnhub()->connectors->get( 'jira' );

		if ( $jira && method_exists( $jira, 'client' ) ) {
			try {
				$site = (string) $jira->client()->site_url();

				if ( '' !== $site ) {
					return esc_url_raw( $jira->client()->browse_url( $key ) );
				}
			} catch ( \Throwable $e ) {
				return '';
			}
		}

		return '';
	}

	/* =================================================================
	 * Checking tickets
	 * ============================================================== */

	/**
	 * Whether this person can start a check, and something can answer it.
	 */
	public static function can_check(): bool {
		return current_user_can( Caps::RAISE_TICKET ) && has_filter( 'vulnhub_start_ticket_check' );
	}

	/**
	 * Does pressing Verify launch a scan on this site?
	 *
	 * Asked of whatever scanner is installed, so the copy on the screen is
	 * the behaviour rather than a description of the default.
	 */
	public static function rescan_allowed(): bool {
		/**
		 * Filters whether Verify may launch a scan.
		 *
		 * @param bool $allowed Default false: launching is opt-in.
		 */
		return (bool) apply_filters( 'vulnhub_ticket_rescan_allowed', false );
	}

	/**
	 * What Verify does, in the words that match what it will actually do.
	 */
	public static function verify_blurb(): string {
		$common = __( 'Tickets already verified fixed are skipped. Without anyone pressing Verify, each ticket is checked at 10:00 the morning after its assets\' scheduled Tenable scan runs, and on its due date.', 'vulnhub' );

		return self::rescan_allowed()
			? __( 'Verify reads each ticket\'s status, assignee and latest comment from Jira, rescans its network-scanned workstations in Tenable and re-checks its findings. Servers are never rescanned from here, and agent-based machines are checked on their latest results.', 'vulnhub' ) . ' ' . $common
			: __( 'Verify reads each ticket\'s status, assignee and latest comment from Jira and re-checks its findings against what Tenable already holds. No scan is launched: scanning from Verify is off in the Tenable settings.', 'vulnhub' ) . ' ' . $common;
	}

	/**
	 * The Verify button for one ticket.
	 *
	 * @param array<string,mixed> $t Ticket row.
	 */
	public static function verify_button( array $t, string $extra_class = '' ): string {
		if ( ! self::can_check() ) {
			return '';
		}

		$title = self::rescan_allowed()
			? __( 'Read the status, assignee and latest comment from Jira, rescan this ticket\'s network-scanned workstations in Tenable, then re-check. Servers are never rescanned from here, and agent-based machines are checked on their latest results.', 'vulnhub' )
			: __( 'Read the status, assignee and latest comment from Jira, then re-check the findings against what Tenable already holds. No scan is launched.', 'vulnhub' );

		return sprintf(
			'<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm %1$s" data-vh-check="%2$d" title="%3$s">%4$s</button>',
			esc_attr( $extra_class ),
			(int) $t['id'],
			esc_attr( $title ),
			esc_html__( 'Verify', 'vulnhub' )
		);
	}

	/**
	 * Who the ticket is with, as a line.
	 *
	 * A service desk that routes by team leaves Jira's assignee null, so a
	 * column that only reads `assignee` reports every ticket as unassigned
	 * while people are actively working them. The team is the answer there,
	 * and is labelled as a team so it is not mistaken for a person.
	 *
	 * @param array<string,mixed> $t Ticket row.
	 */
	public static function assigned_html( array $t ): string {
		$who = class_exists( 'VulnHub_Jira_Connector' )
			? VulnHub_Jira_Connector::assigned_to( $t )
			: array( 'name' => trim( (string) ( $t['assignee'] ?? '' ) ), 'is_team' => false );

		if ( '' === $who['name'] ) {
			return '<span class="vh-meta">&mdash;</span>';
		}

		return '<span class="vh-assigned">' . esc_html( $who['name'] ) . '</span>'
			. ( $who['is_team'] ? '<span class="vh-meta">' . esc_html__( 'team', 'vulnhub' ) . '</span>' : '' );
	}

	/**
	 * The newest comment on the ticket, in a line.
	 *
	 * Shown from what the last refresh stored rather than read live: a list of
	 * twenty tickets would otherwise be twenty calls to Jira to draw one
	 * column. It carries its own "seen" time for that reason.
	 *
	 * @param array<string,mixed> $t Ticket row.
	 */
	public static function last_comment_html( array $t ): string {
		$c = Tickets::last_comment( $t );

		if ( ! $c || '' === trim( (string) ( $c['body'] ?? '' ) ) ) {
			return '<span class="vh-meta">' . esc_html__( 'No comments yet', 'vulnhub' ) . '</span>';
		}

		return '<span class="vh-lastcomment">'
			. '<span class="vh-chip vh-chip--' . ( empty( $c['public'] ) ? 'neutral' : 'good' ) . ' vh-chip--xs">'
			. esc_html( empty( $c['public'] ) ? __( 'internal', 'vulnhub' ) : __( 'reply', 'vulnhub' ) )
			. '</span> '
			. '<strong>' . esc_html( (string) $c['author'] ) . '</strong> '
			. '<span class="vh-meta">' . esc_html( vh_ago( (string) $c['created'] ) ) . '</span>'
			. '<span class="vh-lastcomment__body">' . esc_html( vh_trim( (string) $c['body'], 120 ) ) . '</span>'
			. '</span>';
	}

	/**
	 * The View button: opens the comments for one ticket without leaving here.
	 *
	 * @param array<string,mixed> $t Ticket row.
	 */
	public static function view_button( array $t ): string {
		return sprintf(
			'<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-comments="%1$d" data-vh-comments-key="%2$s" title="%3$s">%4$s</button>',
			(int) $t['id'],
			esc_attr( (string) $t['external_key'] ),
			esc_attr__( 'Read the comments on this ticket and reply, without opening Jira.', 'vulnhub' ),
			esc_html__( 'View', 'vulnhub' )
		);
	}

	/**
	 * Whether this user may add a comment to a ticket.
	 */
	public static function can_comment(): bool {
		return current_user_can( Caps::RAISE_TICKET ) && has_filter( 'vulnhub_post_ticket_comment' );
	}

	/**
	 * The comments component: a list JavaScript fills, and a reply box.
	 *
	 * Rendered both inside the dialog on the list and inline on the ticket
	 * page, from one function, so the two cannot drift apart.
	 *
	 * @param int  $id     Ticket id, or 0 for the dialog, which is told later.
	 * @param bool $inline True on the ticket page.
	 */
	public static function comments_body( int $id = 0, bool $inline = false, ?array $ticket = null ): string {
		$out = '<div class="vh-comments' . ( $inline ? ' vh-comments--inline' : '' ) . '"'
			. ( $id > 0 ? ' data-vh-comments-for="' . (int) $id . '"' : '' ) . '>';

		/*
		 * Reading the conversation is a round trip to Jira -- the better part
		 * of a second -- and until it lands the panel used to be an empty
		 * "Loading…". The newest comment is already on the ticket row from the
		 * last refresh, so show that, dated, and let the fetch replace it.
		 */
		$seed = $ticket ? Tickets::last_comment( $ticket ) : null;

		$out .= '<div class="vh-comments__list" data-vh-comments-list role="status" aria-live="polite">';

		if ( $seed && '' !== trim( (string) ( $seed['body'] ?? '' ) ) ) {
			$public = ! array_key_exists( 'public', $seed ) || (bool) $seed['public'];

			$out .= '<ul class="vh-comments__items">'
				. '<li class="vh-comment' . ( $public ? '' : ' vh-comment--internal' ) . '">'
				. '<div class="vh-comment__head"><strong>' . esc_html( (string) ( $seed['author'] ?: __( 'Unknown', 'vulnhub' ) ) ) . '</strong>'
				. '<span class="vh-chip vh-chip--xs vh-chip--' . ( $public ? 'good' : 'neutral' ) . '">'
				. esc_html( $public ? __( 'reply', 'vulnhub' ) : __( 'internal', 'vulnhub' ) ) . '</span>'
				. '<span class="vh-meta">' . esc_html( vh_ago( (string) ( $seed['created'] ?? '' ) ) ) . '</span></div>'
				. '<div class="vh-comment__body">' . esc_html( vh_trim( (string) $seed['body'], 400 ) ) . '</div>'
				. '</li></ul>'
				. '<p class="vh-meta">' . esc_html__( 'Reading the rest from Jira…', 'vulnhub' ) . '</p>';
		} else {
			$out .= '<p class="vh-meta">' . esc_html__( 'Loading the comments…', 'vulnhub' ) . '</p>';
		}

		$out .= '</div>';

		if ( self::can_comment() ) {
			$out .= '<div class="vh-comments__reply">'
				. '<label class="screen-reader-text" for="vh-comment-body-' . (int) $id . '">' . esc_html__( 'Your comment', 'vulnhub' ) . '</label>'
				. '<textarea id="vh-comment-body-' . (int) $id . '" class="vh-comments__text" data-vh-comment-body rows="3" placeholder="'
				. esc_attr__( 'Write a comment…', 'vulnhub' ) . '"></textarea>'
				/*
				 * Internal first, and checked. A reply goes to whoever raised
				 * the request and cannot be taken back, so the quiet option is
				 * the one a misclick lands on.
				 */
				. '<div class="vh-comments__vis">'
				. '<label><input type="radio" name="vh-comment-vis-' . (int) $id . '" value="internal" checked> '
				. esc_html__( 'Internal note', 'vulnhub' ) . '</label>'
				. '<label><input type="radio" name="vh-comment-vis-' . (int) $id . '" value="public"> '
				. esc_html__( 'Reply to customer', 'vulnhub' ) . '</label>'
				. '<span class="vh-comments__hint" data-vh-comment-hint>' . esc_html__( 'Only agents see an internal note.', 'vulnhub' ) . '</span>'
				. '<button type="button" class="vh-btn vh-btn--primary vh-btn--sm" data-vh-comment-post>' . esc_html__( 'Post', 'vulnhub' ) . '</button>'
				. '</div>'
				. '<p class="vh-comments__status" data-vh-comment-status role="status"></p>'
				. '</div>';
		}

		return $out . '</div>';
	}

	/**
	 * The dialog the list opens. One per page, filled per ticket.
	 */
	public static function comments_dialog(): string {
		return '<dialog id="vh-ticket-comments" class="vh-review vh-comments__dialog" aria-labelledby="vh-comments-title">'
			. '<form method="dialog" class="vh-modal__x"><button aria-label="' . esc_attr__( 'Close', 'vulnhub' ) . '">&times;</button></form>'
			. '<h2 id="vh-comments-title">' . esc_html__( 'Ticket', 'vulnhub' ) . '</h2>'
			. '<p class="vh-review__lede" data-vh-comments-lede></p>'
			. '<div class="vh-review__body">' . self::comments_body() . '</div>'
			. '<div class="vh-review__foot">'
			. '<span class="vh-review__status" data-vh-comments-foot role="status"></span>'
			. '<a class="vh-btn vh-btn--ghost" data-vh-comments-jira target="_blank" rel="noopener noreferrer" hidden>' . esc_html__( 'Open in Jira', 'vulnhub' ) . '</a>'
			. '<button type="button" class="vh-btn" data-vh-comments-close>' . esc_html__( 'Close', 'vulnhub' ) . '</button>'
			. '</div></dialog>';
	}

	/**
	 * Can this person move a ticket through its workflow from here?
	 *
	 * The same bar as commenting -- writing to somebody else's ticket -- plus
	 * an ITSM plugin that actually offers the moves.
	 */
	public static function can_transition(): bool {
		return current_user_can( Caps::RAISE_TICKET ) && has_filter( 'vulnhub_apply_ticket_transition' );
	}

	/**
	 * The button that opens the status dialog, for a Jira-backed ticket.
	 *
	 * @param array<string,mixed> $t Ticket row.
	 */
	public static function transition_button( array $t ): string {
		if ( ! self::can_transition() || 'jira' !== (string) $t['provider'] ) {
			return '';
		}

		return '<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-move="' . (int) $t['id'] . '"'
			. ' data-vh-move-key="' . esc_attr( (string) $t['external_key'] ) . '">'
			. esc_html__( 'Change status', 'vulnhub' ) . '</button>';
	}

	/**
	 * The dialog the button opens.
	 *
	 * Everything inside it is filled by JavaScript from
	 * `GET /tickets/{id}/transitions`, because what a workflow offers depends
	 * on the issue's current status and on what the connecting account may do
	 * -- neither of which is knowable when the page is rendered. Asking Jira
	 * on open also keeps the round trip off the page load.
	 */
	public static function transition_dialog(): string {
		if ( ! self::can_transition() ) {
			return '';
		}

		return '<dialog id="vh-ticket-move" class="vh-review vh-move__dialog" aria-labelledby="vh-move-title">'
			. '<form method="dialog" class="vh-modal__x"><button aria-label="' . esc_attr__( 'Close', 'vulnhub' ) . '">&times;</button></form>'
			. '<h2 id="vh-move-title">' . esc_html__( 'Change status', 'vulnhub' ) . '</h2>'
			. '<p class="vh-review__lede" data-vh-move-lede>' . esc_html__( 'Reading what the workflow offers…', 'vulnhub' ) . '</p>'
			. '<div class="vh-review__body">'
				. '<div class="vh-move__form" data-vh-move-form hidden>'
					. '<label class="vh-move__row"><span>' . esc_html__( 'Move to', 'vulnhub' ) . '</span>'
					. '<select data-vh-move-to></select></label>'
					// Required fields are built here, from what Jira says the
					// chosen transition's screen demands.
					. '<div data-vh-move-fields></div>'
					. '<div class="vh-notice vh-notice--warn" data-vh-move-warn hidden></div>'
					. '<label class="vh-move__row vh-move__row--wide"><span>' . esc_html__( 'Comment (optional)', 'vulnhub' ) . '</span>'
					. '<textarea data-vh-move-note rows="2" placeholder="'
					. esc_attr__( 'Posted on the ticket with the move.', 'vulnhub' ) . '"></textarea></label>'
				. '</div>'
			. '</div>'
			. '<div class="vh-review__foot">'
				. '<span class="vh-review__status" data-vh-move-status role="status"></span>'
				// Shown when the workflow is a dead end here: the move still
				// has to be possible somewhere.
				. '<a class="vh-btn vh-btn--ghost" data-vh-move-jira target="_blank" rel="noopener noreferrer" hidden>'
				. esc_html__( 'Open in Jira', 'vulnhub' ) . '</a>'
				. '<button type="button" class="vh-btn vh-btn--ghost" data-vh-move-cancel>' . esc_html__( 'Cancel', 'vulnhub' ) . '</button>'
				. '<button type="button" class="vh-btn vh-btn--primary" data-vh-move-go disabled>' . esc_html__( 'Move ticket', 'vulnhub' ) . '</button>'
			. '</div></dialog>';
	}

	/**
	 * How much of a ticket is actually done, as a bar.
	 *
	 * Assets, not findings: a ticket is handed to somebody as a list of
	 * machines to touch, so "6 of 10 hosts clear" is the sentence they are
	 * working to. A host counts only when every finding the ticket raised
	 * against it is fixed -- one outstanding patch and the machine is not done.
	 *
	 * The numbers come from the finding rows, which every sync refreshes, so
	 * the bar is current even when the last verification run is days old. That
	 * is deliberate: see the stale note in last_check_html().
	 *
	 * @param array<string,mixed>      $t        Ticket row.
	 * @param array<string,int|string> $progress Row from Tickets::progress(), or
	 *                                           null to look it up.
	 */
	public static function progress_html( array $t, ?array $progress = null ): string {
		$scope = (int) $t['asset_count'] > 0 || 'assets' === (string) $t['source_view'];

		if ( $scope ) {
			$counts = Tickets::asset_outcomes( $t );
			$total  = (int) $counts['total'];
			$done   = (int) $counts['resolved'];
			$label  = static fn( int $d, int $n ): string => sprintf(
				/* translators: 1: assets done, 2: assets on the ticket. */
				__( '%1$d of %2$d assets done', 'vulnhub' ),
				$d,
				$n
			);
			$meta   = $total > 0 && ( (int) $counts['retired'] + (int) $counts['removed'] ) > 0
				? sprintf(
					/* translators: %d: number of assets. */
					__( '%d no longer relevant', 'vulnhub' ),
					(int) $counts['retired'] + (int) $counts['removed']
				)
				: '';
		} else {
			$progress = $progress ?? Tickets::progress_for( (int) $t['id'] );

			if ( ! $progress ) {
				return '';
			}

			$total = (int) $progress['assets'];
			$done  = (int) $progress['assets_fixed'];
			$label = static fn( int $d, int $n ): string => sprintf(
				/* translators: 1: assets fixed, 2: assets on the ticket. */
				__( '%1$d of %2$d assets fixed', 'vulnhub' ),
				$d,
				$n
			);
			$meta  = sprintf(
				/* translators: 1: findings fixed, 2: findings on the ticket. */
				__( '%1$d of %2$d findings', 'vulnhub' ),
				(int) $progress['findings_fixed'],
				(int) $progress['findings']
			);
		}

		if ( $total < 1 ) {
			return '';
		}

		$pct  = (int) round( $done / $total * 100 );
		$tone = 0 === $done ? 'none' : ( $done >= $total ? 'good' : 'part' );

		// As of when, so the bar is never read as a live scan.
		$as_of = (string) ( $progress['as_of'] ?? '' );
		$title = '' !== $as_of
			? sprintf(
				/* translators: 1: the bar's label, 2: time ago, e.g. "13 hours ago". */
				__( '%1$s — scanner data %2$s', 'vulnhub' ),
				$label( $done, $total ),
				vh_ago( $as_of )
			)
			: $label( $done, $total );

		return '<div class="vh-tprog vh-tprog--' . esc_attr( $tone ) . '" title="' . esc_attr( $title ) . '">'
			. '<div class="vh-tprog__track" role="img" aria-label="' . esc_attr( $title ) . '">'
			. '<span style="width:' . (int) $pct . '%"></span></div>'
			. '<span class="vh-tprog__label">' . esc_html( $label( $done, $total ) ) . '</span>'
			. ( '' !== $meta ? '<span class="vh-tprog__meta">' . esc_html( $meta ) . '</span>' : '' )
			. '</div>';
	}

	/**
	 * Has the scanner answered again since this check, and differently?
	 *
	 * A verification verdict is frozen at the moment it was reached, and a
	 * sync lands every night. SD-1234 read "3 of 10 findings fixed" above a
	 * table showing all ten fixed, and both were true -- of different days.
	 * Leaving the older sentence on top made the newer one look like the
	 * mistake, so when the two disagree this returns the pair, and the caller
	 * leads with `now` and files `was` underneath its own date.
	 *
	 * Null when there is nothing to reconcile: a scope ticket, a ticket with
	 * no findings, no sync since the check, or a sync that did not change the
	 * count. In that case the verdict stands on its own, as it should.
	 *
	 * @param array<string,mixed>           $t        Ticket row.
	 * @param array<string,mixed>           $last     Stored last check.
	 * @param array<string,int|string>|null $progress Row from Tickets::progress().
	 * @return array{now:string,was:string,tone:string}|null
	 */
	private static function superseded( array $t, array $last, ?array $progress ): ?array {
		if ( (int) $t['asset_count'] > 0 || 'assets' === (string) $t['source_view'] ) {
			return null;
		}

		$progress = $progress ?? Tickets::progress_for( (int) $t['id'] );

		if ( ! $progress || ! isset( $last['fixed'] ) ) {
			return null;
		}

		$checked = strtotime( (string) ( $last['checked_at'] ?? '' ) . ' UTC' );
		$as_of   = strtotime( (string) ( $progress['as_of'] ?? '' ) . ' UTC' );

		if ( ! $checked || ! $as_of || $as_of <= $checked ) {
			return null;
		}
		if ( (int) $last['fixed'] === (int) $progress['findings_fixed'] ) {
			return null;
		}

		$fixed = (int) $progress['findings_fixed'];
		$total = (int) $progress['findings'];
		$done  = $fixed >= $total;

		/*
		 * What the scanner holds now, and only that. The remainder is not
		 * split into "still detected" and "not rescanned": that distinction
		 * comes from comparing each asset's scan time against the ticket, and
		 * it is the verification run's to make, not a stored state's.
		 */
		$now = $done
			? sprintf(
				/* translators: 1: number of findings, 2: time ago, e.g. "14 hours ago". */
				__( 'Tenable shows all %1$d findings fixed — scan data %2$s', 'vulnhub' ),
				$total,
				vh_ago( (string) $progress['as_of'] )
			)
			: sprintf(
				/* translators: 1: findings fixed, 2: findings on the ticket, 3: time ago. */
				__( 'Tenable shows %1$d of %2$d findings fixed — scan data %3$s', 'vulnhub' ),
				$fixed,
				$total,
				vh_ago( (string) $progress['as_of'] )
			);

		// The verdict, in its own numbers, under its own date.
		$was = sprintf(
			/* translators: 1: time ago, 2: fixed, 3: total, 4: still detected, 5: not rescanned. */
			__( 'the check %1$s said %2$d of %3$d fixed, %4$d still detected, %5$d not rescanned', 'vulnhub' ),
			vh_ago( (string) ( $last['checked_at'] ?? '' ) ),
			(int) $last['fixed'],
			$total,
			(int) ( $last['open'] ?? 0 ),
			(int) ( $last['unknown'] ?? 0 )
		);

		return array(
			'now'  => $now,
			'was'  => $was,
			'tone' => $done ? 'good' : 'neutral',
		);
	}

	/**
	 * The last check, in a line.
	 *
	 * @param array<string,mixed> $t Ticket row.
	 */
	public static function last_check_html( array $t, ?array $progress = null ): string {
		$last = Tickets::last_check( $t );
		$due  = Tickets::due_date( $t );
		$out  = '';

		if ( $last ) {
			$since = self::superseded( $t, $last, $progress );

			if ( $since ) {
				/*
				 * The scanner has answered again since this check ran, and
				 * differently. Today's answer leads; the verdict keeps its own
				 * words but moves below its own date, where it reads as the
				 * record it is rather than as a claim about now.
				 */
				$out .= '<span class="vh-check-last__head vh-tone--' . esc_attr( $since['tone'] ) . '">'
					. esc_html( $since['now'] ) . '</span>';
				$out .= '<span class="vh-meta vh-check-last__was">' . esc_html( $since['was'] ) . '</span>';
			} else {
				$state = (string) ( $last['state'] ?? '' );
				$tone  = match ( $state ) {
					Tickets::VERIFY_CONFIRMED  => 'good',
					Tickets::VERIFY_STILL_OPEN => 'bad',
					default                    => 'neutral',
				};
				$out .= '<span class="vh-check-last__head vh-tone--' . esc_attr( $tone ) . '">' . esc_html( vh_trim( (string) ( $last['headline'] ?? '' ), 110 ) ) . '</span>';
				/* translators: %s: time ago. */
				$out .= '<span class="vh-meta">' . esc_html( sprintf( __( 'checked %s', 'vulnhub' ), vh_ago( (string) ( $last['checked_at'] ?? '' ) ) ) ) . '</span>';
			}
		} else {
			$out .= '<span class="vh-meta">' . esc_html__( 'Not checked yet', 'vulnhub' ) . '</span>';
		}

		$next = Tickets::next_check( $t );

		if ( $next && ! empty( $next['at'] ) && Tickets::VERIFY_CONFIRMED !== (string) $t['verification_state'] ) {
			$out .= '<span class="vh-meta">' . esc_html(
				sprintf(
					/* translators: 1: date and time, 2: why. */
					__( 'next check %1$s, %2$s', 'vulnhub' ),
					wp_date( 'D j M H:i', (int) strtotime( (string) $next['at'] . ' UTC' ) ),
					(string) $next['reason']
				)
			) . '</span>';
		} elseif ( '' !== $due ) {
			/* translators: %s: date. */
			$out .= '<span class="vh-meta">' . esc_html( sprintf( __( 'due %s', 'vulnhub' ), $due ) ) . '</span>';
		}

		return '<div class="vh-check-last" data-vh-check-last="' . (int) $t['id'] . '">' . $out . '</div>';
	}

	/**
	 * What "Verify all tickets" is about to do, in one sentence.
	 *
	 * Said before it runs, and it has to be true: the browser's own confirm()
	 * used to promise "this launches one Tenable rescan of their
	 * network-scanned workstations" whatever the settings said, which on an
	 * agent-based estate described something that never happens.
	 */
	public static function verify_all_question(): string {
		return self::rescan_allowed()
			? __( 'Verify every ticket that is not yet verified fixed? Each ticket\'s status, assignee and latest comment are read from Jira, one Tenable rescan of their network-scanned workstations is launched, and the findings are re-checked. Servers and agent-based machines are never rescanned.', 'vulnhub' )
			: __( 'Verify every ticket that is not yet verified fixed? Each ticket\'s status, assignee and latest comment are read from Jira and the findings are re-checked against what Tenable already holds. No scan is launched.', 'vulnhub' );
	}

	/**
	 * The dialog that asks, then reports.
	 *
	 * One dialog for both halves: the question and the progress of the run it
	 * starts. A check over every ticket is minutes of work with a result per
	 * ticket, and a browser confirm() can neither say that honestly nor show
	 * it afterwards.
	 */
	public static function check_dialog(): string {
		if ( ! self::can_check() ) {
			return '';
		}

		return '<dialog id="vh-verify-all" class="vh-review vh-verify__dialog" aria-labelledby="vh-verify-title">'
			. '<form method="dialog" class="vh-modal__x"><button aria-label="' . esc_attr__( 'Close', 'vulnhub' ) . '">&times;</button></form>'
			. '<h2 id="vh-verify-title">' . esc_html__( 'Verify all tickets', 'vulnhub' ) . '</h2>'
			. '<p class="vh-review__lede" data-vh-verify-lede>' . esc_html( self::verify_all_question() ) . '</p>'
			. '<div class="vh-review__body">'
				. '<div class="vh-verify__progress" data-vh-verify-progress hidden>'
					. '<div class="vh-verify__bar"><span data-vh-verify-fill></span></div>'
					. '<p class="vh-verify__count" data-vh-verify-count role="status" aria-live="polite"></p>'
				. '</div>'
				. '<ul class="vh-check-panel__list vh-verify__list" data-vh-verify-list></ul>'
			. '</div>'
			. '<div class="vh-review__foot">'
				. '<span class="vh-review__status" data-vh-verify-status role="status"></span>'
				. '<button type="button" class="vh-btn vh-btn--ghost" data-vh-verify-cancel>' . esc_html__( 'Cancel', 'vulnhub' ) . '</button>'
				. '<button type="button" class="vh-btn vh-btn--primary" data-vh-verify-go>' . esc_html__( 'Verify all tickets', 'vulnhub' ) . '</button>'
			. '</div></dialog>';
	}

	/**
	 * The progress panel a check reports into.
	 */
	public static function check_panel(): string {
		if ( ! self::can_check() ) {
			return '';
		}

		return '<div class="vh-check-panel" data-vh-check-panel hidden role="status" aria-live="polite">'
			. '<div class="vh-check-panel__head"><strong data-vh-check-msg></strong>'
			. '<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-check-close hidden>' . esc_html__( 'Close', 'vulnhub' ) . '</button></div>'
			. '<ul class="vh-check-panel__list" data-vh-check-list></ul>'
			. '</div>';
	}

	/* =================================================================
	 * The ticket page
	 * ============================================================== */

	public static function render_detail( int $id ): void {
		$t = Tickets::get( $id );

		echo '<p><a class="vh-back" href="' . esc_url( self::page_url( 'tickets' ) ) . '">&larr; ' . esc_html__( 'All tickets', 'vulnhub' ) . '</a></p>';

		if ( ! $t ) {
			echo '<p class="vh-chart-empty">' . esc_html__( 'Ticket not found.', 'vulnhub' ) . '</p>';
			return;
		}

		$scope    = json_decode( (string) ( $t['scope_json'] ?? '' ), true );
		$scope    = is_array( $scope ) ? $scope : array();
		$is_scope = (int) $t['asset_count'] > 0 || 'assets' === (string) $t['source_view'];
		$raiser   = (int) $t['created_by'] ? get_userdata( (int) $t['created_by'] ) : null;
		$msg      = self::q( 'vh_msg' );
		?>
		<div class="vh-page-head">
			<div>
				<h1 class="vh-mono"><?php echo esc_html( (string) $t['external_key'] ); ?></h1>
				<p class="vh-sub"><?php echo esc_html( (string) $t['summary'] ); ?></p>
			</div>
			<div class="vh-page-head__actions">
				<?php echo self::verify_button( $t ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
				<?php if ( '' !== (string) $t['url'] ) : ?>
					<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( (string) $t['url'] ); ?>" target="_blank" rel="noopener noreferrer">
						<?php echo esc_html( Tickets::PROVIDER_JSM === (string) $t['provider'] ? __( 'Open in JSM', 'vulnhub' ) : __( 'Open in Jira', 'vulnhub' ) ); ?> &nearr;
					</a>
				<?php endif; ?>
			</div>
		</div>
		<?php echo self::check_panel(); // phpcs:ignore WordPress.Security.EscapeOutput ?>
		<?php $vh_prog = Tickets::progress_for( (int) $t['id'] ); ?>
		<?php echo self::progress_html( $t, $vh_prog ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
		<?php echo self::last_check_html( $t, $vh_prog ); // phpcs:ignore WordPress.Security.EscapeOutput ?>

		<?php if ( '' !== $msg ) : ?>
			<p class="vh-flash vh-flash--good" role="status"><?php echo esc_html( $msg ); ?></p>
		<?php endif; ?>

		<div class="vh-grid vh-grid--2">
			<section class="vh-panel">
				<header class="vh-panel__head"><h2><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></h2></header>
				<dl class="vh-dl">
					<dt><?php esc_html_e( 'Request type', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( Tickets::kind_label( (string) $t['kind'] ) ); ?></dd>
					<dt><?php esc_html_e( 'Status', 'vulnhub' ); ?></dt>
					<dd class="vh-dd--act">
						<span class="vh-chip vh-chip--<?php echo 'done' === $t['status_category'] ? 'good' : 'neutral'; ?>"><?php echo esc_html( (string) ( $t['status'] ?: '—' ) ); ?></span>
						<?php echo self::transition_button( $t ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
					</dd>
					<dt><?php esc_html_e( 'Tracked in', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( Tickets::PROVIDER_JSM === (string) $t['provider'] ? __( 'Jira Service Management, updated by hand', 'vulnhub' ) : __( 'Jira, synced', 'vulnhub' ) ); ?></dd>
					<dt><?php esc_html_e( 'Raised', 'vulnhub' ); ?></dt>
					<dd>
						<?php echo esc_html( vh_date( (string) $t['created_at'] ) ); ?>
						<?php if ( $raiser ) : ?>
							· <?php echo esc_html( (string) $raiser->display_name ); ?>
						<?php endif; ?>
					</dd>
					<?php
					$vh_who = class_exists( 'VulnHub_Jira_Connector' )
						? VulnHub_Jira_Connector::assigned_to( $t )
						: array( 'name' => trim( (string) ( $t['assignee'] ?? '' ) ), 'is_team' => false );
					?>
					<?php if ( '' !== $vh_who['name'] ) : ?>
						<dt><?php echo esc_html( $vh_who['is_team'] ? __( 'Assigned team', 'vulnhub' ) : __( 'Assignee', 'vulnhub' ) ); ?></dt>
						<dd><?php echo esc_html( $vh_who['name'] ); ?></dd>
					<?php endif; ?>
					<?php if ( '' !== trim( (string) ( $t['notes'] ?? '' ) ) ) : ?>
						<dt><?php esc_html_e( 'Notes', 'vulnhub' ); ?></dt>
						<dd class="vh-prewrap"><?php echo esc_html( (string) $t['notes'] ); ?></dd>
					<?php endif; ?>
				</dl>

				<?php if ( 'jira' === (string) $t['provider'] ) : ?>
					<div class="vh-panel__sub">
						<h3><?php esc_html_e( 'Comments', 'vulnhub' ); ?></h3>
						<?php echo self::comments_body( (int) $t['id'], true, $t ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
					</div>
				<?php endif; ?>

				<?php if ( Tickets::PROVIDER_JSM === (string) $t['provider'] && current_user_can( Caps::RAISE_TICKET ) ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-raise__status">
						<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_STATUS ); ?>">
						<input type="hidden" name="ticket" value="<?php echo esc_attr( (string) $id ); ?>">
						<?php wp_nonce_field( self::ACTION_STATUS ); ?>
						<label>
							<span><?php esc_html_e( 'Status', 'vulnhub' ); ?></span>
							<select name="status_category">
								<?php foreach ( Tickets::manual_statuses() as $vh_cat => $vh_label ) : ?>
									<option value="<?php echo esc_attr( $vh_cat ); ?>" <?php selected( (string) $t['status_category'], $vh_cat ); ?>><?php echo esc_html( $vh_label ); ?></option>
								<?php endforeach; ?>
							</select>
						</label>
						<label class="vh-raise__wide">
							<span><?php esc_html_e( 'Notes', 'vulnhub' ); ?></span>
							<textarea name="notes" rows="2"><?php echo esc_textarea( (string) ( $t['notes'] ?? '' ) ); ?></textarea>
						</label>
						<button class="vh-btn vh-btn--sm"><?php esc_html_e( 'Update', 'vulnhub' ); ?></button>
					</form>
				<?php endif; ?>
			</section>

			<?php if ( $is_scope ) : ?>
				<section class="vh-panel">
					<header class="vh-panel__head"><h2><?php esc_html_e( 'Raised from', 'vulnhub' ); ?></h2></header>
					<p class="vh-sub">
						<?php
						printf(
							/* translators: %s: number of assets. */
							esc_html( _n( 'Assets & owners, %s asset matching:', 'Assets & owners, %s assets matching:', (int) $t['asset_count'], 'vulnhub' ) ),
							esc_html( number_format_i18n( (int) $t['asset_count'] ) )
						);
						?>
					</p>
					<ul class="vh-raise__filters">
						<?php foreach ( (array) ( $scope['filters'] ?? array() ) as $vh_f ) : ?>
							<li><?php echo esc_html( (string) $vh_f ); ?></li>
						<?php endforeach; ?>
					</ul>
					<p class="vh-raise__links">
						<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::page_url( 'assets', array_map( 'rawurlencode', (array) ( $scope['query'] ?? array() ) ) ) ); ?>">
							<?php esc_html_e( 'Open this filter as it is today', 'vulnhub' ); ?>
						</a>
						<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::export_url( array_map( 'strval', (array) ( $scope['args'] ?? array() ) ), array_map( 'strval', (array) ( $scope['cols'] ?? array() ) ) ) ); ?>">
							<?php esc_html_e( 'Download that list as it is today', 'vulnhub' ); ?>
						</a>
					</p>
					<p class="vh-sub vh-muted"><?php esc_html_e( 'The filter can match different assets now. The table below is the assets the ticket was raised about, whatever the filter says today.', 'vulnhub' ); ?></p>
				</section>
			<?php endif; ?>
		</div>

		<?php
		if ( $is_scope ) {
			self::render_assets( $t );
		} else {
			self::render_findings( $t );
		}

		echo self::transition_dialog(); // phpcs:ignore WordPress.Security.EscapeOutput
	}

	/**
	 * @param array<string,mixed> $t Ticket row.
	 */
	private static function render_assets( array $t ): void {
		$counts   = Tickets::asset_outcomes( $t );
		$outcomes = Tickets::outcomes();
		$filter   = self::q( 'outcome' );
		$filter   = isset( $outcomes[ $filter ] ) ? $filter : '';
		$page     = max( 1, (int) self::q( 'tap' ) );
		$list     = Tickets::assets_for( $t, array( 'outcome' => $filter, 'limit' => self::PER, 'offset' => ( $page - 1 ) * self::PER ) );
		$pages    = max( 1, (int) ceil( (int) $list['total'] / self::PER ) );
		$base     = self::page_url( 'tickets', array( 'ticket' => (int) $t['id'] ) );
		$has_test = '' !== (string) ( Tickets::kinds()[ (string) $t['kind'] ]['resolved'] ?? '' );
		$sources  = vh_asset_sources();
		$life     = vh_lifecycle_statuses();

		$names = static function ( string $stored ) use ( $sources ): string {
			$seen = array_keys( Repo::source_map( $stored ) );

			return $seen ? implode( ', ', array_map( static fn( string $s ): string => (string) ( $sources[ $s ] ?? $s ), $seen ) ) : '—';
		};

		$state = static function ( string $was, string $now, callable $label, callable $tone ): string {
			$out = '<span class="vh-chip vh-chip--' . esc_attr( $tone( $now ) ) . '">' . esc_html( '' === $now ? '—' : $label( $now ) ) . '</span>';

			if ( '' !== $was && $was !== $now ) {
				/* translators: %s: the state when the ticket was raised. */
				$out .= '<span class="vh-meta">' . esc_html( sprintf( __( 'was %s', 'vulnhub' ), $label( $was ) ) ) . '</span>';
			}

			return $out;
		};

		$tone_map = static fn( string $tone ): string => 'muted' === $tone ? 'neutral' : $tone;
		?>
		<section class="vh-tiles">
			<?php
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Assets on this ticket', 'vulnhub' ), 'value' => $counts['total'], 'tone' => 'neutral', 'href' => $base ) ); // phpcs:ignore
			echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore
				array(
					'label' => $outcomes['open']['label'],
					'value' => $counts['open'],
					'tone'  => $counts['open'] > 0 ? 'critical' : 'good',
					'meta'  => $has_test ? __( 'the ask is not met yet', 'vulnhub' ) : __( 'this request type is not checked automatically', 'vulnhub' ),
					'href'  => add_query_arg( 'outcome', 'open', $base ),
				)
			);
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => $outcomes['resolved']['label'], 'value' => $counts['resolved'], 'tone' => 'good', 'meta' => __( 'checked against the latest sync', 'vulnhub' ), 'href' => add_query_arg( 'outcome', 'resolved', $base ) ) ); // phpcs:ignore
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => $outcomes['retired']['label'], 'value' => $counts['retired'] + $counts['removed'], 'tone' => 'neutral', 'meta' => __( 'decommissioned, out of scope, or gone', 'vulnhub' ), 'href' => add_query_arg( 'outcome', 'retired', $base ) ) ); // phpcs:ignore
			?>
		</section>

		<nav class="vh-chips" aria-label="<?php esc_attr_e( 'Show', 'vulnhub' ); ?>">
			<a class="vh-chip <?php echo '' === $filter ? 'vh-chip--filter is-active' : ''; ?>" href="<?php echo esc_url( $base ); ?>"><?php esc_html_e( 'All', 'vulnhub' ); ?> <?php echo esc_html( number_format_i18n( $counts['total'] ) ); ?></a>
			<?php foreach ( $outcomes as $vh_o => $vh_def ) : ?>
				<?php if ( 0 === $counts[ $vh_o ] && $filter !== $vh_o ) : continue; endif; ?>
				<a class="vh-chip <?php echo $filter === $vh_o ? 'vh-chip--filter is-active' : ''; ?>" href="<?php echo esc_url( add_query_arg( 'outcome', $vh_o, $base ) ); ?>">
					<?php echo esc_html( (string) $vh_def['label'] ); ?> <?php echo esc_html( number_format_i18n( $counts[ $vh_o ] ) ); ?>
				</a>
			<?php endforeach; ?>
		</nav>

		<?php if ( ! $list['rows'] ) : ?>
			<p class="vh-chart-empty"><?php esc_html_e( 'No assets in this group.', 'vulnhub' ); ?></p>
			<?php return; ?>
		<?php endif; ?>

		<div class="vh-tablewrap vh-tablewrap--cards">
			<table class="vh-table vh-table--ticket-assets">
				<thead><tr>
					<th><?php esc_html_e( 'Host', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Outcome', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Scan coverage', 'vulnhub' ); ?><span class="vh-th__src"><?php esc_html_e( 'Tenable', 'vulnhub' ); ?></span></th>
					<th><?php esc_html_e( 'EDR coverage', 'vulnhub' ); ?><span class="vh-th__src"><?php esc_html_e( 'Defender', 'vulnhub' ); ?></span></th>
					<th><?php esc_html_e( 'Known by', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Lifecycle', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Last Tenable scan', 'vulnhub' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $list['rows'] as $r ) : ?>
					<?php
					$vh_live    = (int) $r['live_id'] > 0;
					$vh_outcome = (string) $r['outcome'];
					$vh_was_src = $names( (string) $r['was_sources'] );
					$vh_now_src = $vh_live ? $names( (string) $r['now_sources'] ) : '—';
					?>
					<tr>
						<td data-label="<?php esc_attr_e( 'Host', 'vulnhub' ); ?>">
							<?php if ( $vh_live ) : ?>
								<a class="vh-mono" href="<?php echo esc_url( self::page_url( 'assets', array( 'asset' => (int) $r['asset_id'] ) ) ); ?>"><strong><?php echo esc_html( (string) $r['hostname'] ); ?></strong></a>
								<span class="vh-meta"><?php echo esc_html( trim( vh_asset_type_label( (string) $r['asset_type'] ) . ' · ' . (string) $r['ipv4'], ' ·' ) ); ?></span>
							<?php else : ?>
								<span class="vh-mono"><strong><?php echo esc_html( (string) $r['hostname'] ); ?></strong></span>
							<?php endif; ?>
						</td>
						<td data-label="<?php esc_attr_e( 'Outcome', 'vulnhub' ); ?>">
							<span class="vh-chip vh-chip--<?php echo esc_attr( (string) $outcomes[ $vh_outcome ]['tone'] ); ?>"><?php echo esc_html( (string) $outcomes[ $vh_outcome ]['label'] ); ?></span>
						</td>
						<td data-label="<?php esc_attr_e( 'Scan coverage', 'vulnhub' ); ?>">
							<?php echo $vh_live ? $state( (string) $r['was_coverage'], (string) $r['now_coverage'], array( Coverage::class, 'label' ), static fn( string $s ): string => $tone_map( Coverage::tone( $s ) ) ) : '—'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
						</td>
						<td data-label="<?php esc_attr_e( 'EDR coverage', 'vulnhub' ); ?>">
							<?php echo $vh_live ? $state( (string) $r['was_defender'], (string) $r['now_defender'], array( Defender_Coverage::class, 'label' ), static fn( string $s ): string => $tone_map( Defender_Coverage::tone( $s ) ) ) : '—'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
						</td>
						<td data-label="<?php esc_attr_e( 'Known by', 'vulnhub' ); ?>">
							<?php echo esc_html( $vh_now_src ); ?>
							<?php if ( $vh_live && $vh_was_src !== $vh_now_src ) : ?>
								<?php /* translators: %s: sources when the ticket was raised. */ ?>
								<span class="vh-meta"><?php echo esc_html( sprintf( __( 'was %s', 'vulnhub' ), $vh_was_src ) ); ?></span>
							<?php endif; ?>
						</td>
						<td data-label="<?php esc_attr_e( 'Lifecycle', 'vulnhub' ); ?>">
							<?php if ( $vh_live ) : ?>
								<?php echo esc_html( (string) ( $life[ (string) $r['now_lifecycle'] ]['label'] ?? $r['now_lifecycle'] ) ); ?>
								<?php if ( (string) $r['was_lifecycle'] !== (string) $r['now_lifecycle'] && '' !== (string) $r['was_lifecycle'] ) : ?>
									<?php /* translators: %s: lifecycle status when the ticket was raised. */ ?>
									<span class="vh-meta"><?php echo esc_html( sprintf( __( 'was %s', 'vulnhub' ), (string) ( $life[ (string) $r['was_lifecycle'] ]['label'] ?? $r['was_lifecycle'] ) ) ); ?></span>
								<?php endif; ?>
							<?php else : ?>
								<span class="vh-muted"><?php esc_html_e( 'No longer in the inventory', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
						<td data-label="<?php esc_attr_e( 'Last Tenable scan', 'vulnhub' ); ?>">
							<?php echo esc_html( $vh_live && ! empty( $r['tenable_last_scan'] ) ? vh_ago( (string) $r['tenable_last_scan'] ) : '—' ); ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>

		<?php if ( $pages > 1 ) : ?>
			<nav class="vh-pager" aria-label="<?php esc_attr_e( 'Pagination', 'vulnhub' ); ?>">
				<?php $vh_here = $filter ? add_query_arg( 'outcome', $filter, $base ) : $base; ?>
				<?php if ( $page > 1 ) : ?>
					<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( add_query_arg( 'tap', $page - 1, $vh_here ) ); ?>">&larr; <?php esc_html_e( 'Previous', 'vulnhub' ); ?></a>
				<?php endif; ?>
				<?php /* translators: 1: current page, 2: total pages. */ ?>
				<span class="vh-pager__count"><?php echo esc_html( sprintf( __( 'Page %1$d of %2$d', 'vulnhub' ), $page, $pages ) ); ?></span>
				<?php if ( $page < $pages ) : ?>
					<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( add_query_arg( 'tap', $page + 1, $vh_here ) ); ?>"><?php esc_html_e( 'Next', 'vulnhub' ); ?> &rarr;</a>
				<?php endif; ?>
			</nav>
		<?php endif; ?>
		<?php
	}

	/**
	 * A vulnerability ticket: the findings it covers.
	 *
	 * @param array<string,mixed> $t Ticket row.
	 */
	private static function render_findings( array $t ): void {
		$rows = array_slice( Tickets::findings_for( (int) $t['id'] ), 0, 200 );

		if ( ! $rows ) {
			echo '<p class="vh-chart-empty">' . esc_html__( 'This ticket covers no findings.', 'vulnhub' ) . '</p>';
			return;
		}
		?>
		<div class="vh-tablewrap">
			<table class="vh-table">
				<thead><tr>
					<th><?php esc_html_e( 'Host', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Vulnerability', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'State', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Verification', 'vulnhub' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $rows as $f ) : ?>
					<tr>
						<td><a class="vh-mono" href="<?php echo esc_url( self::page_url( 'assets', array( 'asset' => (int) $f['asset_id'] ) ) ); ?>"><?php echo esc_html( (string) $f['hostname'] ); ?></a></td>
						<td><?php echo esc_html( vh_trim( (string) $f['vuln_title'], 90 ) ); ?></td>
						<td><?php echo esc_html( (string) $f['state'] ); ?></td>
						<td><?php echo esc_html( Tickets::verification_labels()[ (string) ( $f['verification_state'] ?? '' ) ] ?? '—' ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}
}
