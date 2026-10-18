<?php
/**
 * Supplier assessments: the portal page.
 *
 * Three tabs:
 *
 *   - Supplier assessments: third-party information security assessments,
 *     both those inherited with a register handed over by a previous team
 *     and those done here since, with who reviewed, who decided, any
 *     conditions and when to look again.
 *   - Security exceptions are NOT kept here. The same request type also
 *     carries exception requests (a firewall allow-list, offshore working, a
 *     legacy cipher); those are recorded in the portal's Exception register
 *     as `policy` exceptions through core's Exceptions::record(), from a
 *     form this page serves (?exc=new|<id>) and links to from that register.
 *   - Not yet in the register: assessment requests the Jira inbox holds that
 *     no row links to and nobody has set aside, each with the newest comment
 *     that reads as a decision. This is how the register stays complete
 *     without anybody re-reading the service desk.
 *
 * Reading needs the portal's view permission. Adding, editing, deleting and
 * setting tickets aside needs the manage permission (filter
 * `vulnhub_assess_edit_cap`), is nonce-checked and audited, and is refused on
 * a read-only copy of another instance.
 *
 * @package VulnHub\Assessments
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VH_Assess_View {

	public const VIEW = 'assessments';
	public const SLUG = 'supplier-assessments';

	public const ACTION_SAVE     = 'vulnhub_assess_save';
	public const ACTION_DELETE   = 'vulnhub_assess_delete';
	public const ACTION_DISMISS  = 'vulnhub_assess_dismiss';
	public const ACTION_RESTORE  = 'vulnhub_assess_restore';
	public const ACTION_CSV      = 'vulnhub_assess_csv';
	public const ACTION_EXC_SAVE = 'vulnhub_assess_exc_save';

	/** Tabs, in order. */
	private const TABS = array( 'supplier', 'inbox' );

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ), 30 );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 21 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );

		add_action( 'admin_post_' . self::ACTION_SAVE, array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_DELETE, array( __CLASS__, 'handle_delete' ) );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( __CLASS__, 'handle_dismiss' ) );
		add_action( 'admin_post_' . self::ACTION_RESTORE, array( __CLASS__, 'handle_restore' ) );
		add_action( 'admin_post_' . self::ACTION_CSV, array( __CLASS__, 'handle_csv' ) );
		add_action( 'admin_post_' . self::ACTION_EXC_SAVE, array( __CLASS__, 'handle_exc_save' ) );

		// The Exception register links here to record and edit security
		// exceptions decided in Jira.
		add_action( 'vulnhub_exceptions_page_actions', array( __CLASS__, 'exceptions_page_button' ) );
		add_filter( 'vulnhub_exception_edit_url', array( __CLASS__, 'exception_edit_url' ), 10, 2 );
	}

	public static function exceptions_page_button(): void {
		if ( ! self::can_edit() || ! self::core_exceptions() ) {
			return;
		}
		printf(
			'<a class="vh-btn vh-btn--ghost" href="%s">%s</a>',
			esc_url( self::url( array( 'exc' => 'new' ) ) ),
			esc_html__( 'Record a security exception', 'vulnhub' )
		);
	}

	/**
	 * @param string              $url Current URL.
	 * @param array<string,mixed> $e   Exception row.
	 */
	public static function exception_edit_url( $url, $e ): string {
		if ( ! is_array( $e ) || 'policy' !== (string) ( $e['scope_type'] ?? '' ) || ! self::can_edit() ) {
			return (string) $url;
		}

		return self::url( array( 'exc' => (int) $e['id'] ) );
	}

	/** Core's register supports security (policy) exceptions. */
	public static function core_exceptions(): bool {
		return class_exists( '\\VulnHub\\Core\\Exceptions' ) && method_exists( '\\VulnHub\\Core\\Exceptions', 'record' );
	}

	/** The portal's Exception register, optionally filtered. */
	public static function exceptions_url( array $args = array() ): string {
		return class_exists( 'VulnHub_Dash_Portal' ) ? VulnHub_Dash_Portal::portal_url( 'exceptions', $args ) : home_url( '/exceptions/' );
	}

	/* =================================================================
	 * Registration
	 * ============================================================== */

	/**
	 * Straight after Exceptions: the other register of risk decisions.
	 *
	 * @param array<string,array<string,mixed>> $views Existing views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$def = array(
			'title' => __( 'Supplier assessments', 'vulnhub' ),
			'slug'  => self::SLUG,
			'menu'  => __( 'Assessments', 'vulnhub' ),
			// A clipboard with a tick: something checked and signed off.
			'icon'  => 'M9 4h6v3H9zM7 5H5v16h14V5h-2M9 13l2 2 4-4',
		);
		$out = array();

		foreach ( $views as $key => $view ) {
			$out[ $key ] = $view;
			if ( 'exceptions' === $key ) {
				$out[ self::VIEW ] = $def;
			}
		}

		if ( ! isset( $out[ self::VIEW ] ) ) {
			$out[ self::VIEW ] = $def;
		}

		return $out;
	}

	public static function ensure_page(): void {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );

		if ( ! empty( $map[ self::VIEW ] ) ) {
			$existing = get_post( (int) $map[ self::VIEW ] );
			if ( $existing && 'trash' !== $existing->post_status ) {
				return;
			}
		}

		$page = get_page_by_path( self::SLUG );

		if ( $page ) {
			$id = (int) $page->ID;
		} else {
			$id = wp_insert_post(
				array(
					'post_title'     => __( 'Supplier assessments', 'vulnhub' ),
					'post_name'      => self::SLUG,
					'post_content'   => '<!-- wp:shortcode -->[vulnhub_app view="' . self::VIEW . '"]<!-- /wp:shortcode -->',
					'post_status'    => 'publish',
					'post_type'      => 'page',
					'comment_status' => 'closed',
					'ping_status'    => 'closed',
				)
			);
		}

		if ( ! is_wp_error( $id ) && $id ) {
			$map[ self::VIEW ] = (int) $id;
			update_option( 'vulnhub_dash_pages', $map, false );
		}
	}

	public static function url( array $args = array() ): string {
		if ( class_exists( 'VulnHub_Dash_Portal' ) ) {
			return VulnHub_Dash_Portal::portal_url( self::VIEW, $args );
		}

		return add_query_arg( $args, home_url( '/' . self::SLUG . '/' ) );
	}

	public static function assets(): void {
		if ( ! is_singular() || ! class_exists( 'VulnHub_Dash_App' ) ) {
			return;
		}
		if ( self::VIEW !== VulnHub_Dash_App::view_for_post( get_post() ) ) {
			return;
		}

		$rel   = 'assets/assessments.css';
		$mtime = @filemtime( VULNHUB_ASSESS_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		wp_enqueue_style( 'vulnhub-assessments', VULNHUB_ASSESS_URL . $rel, array( 'vulnhub-app' ), $mtime ? VULNHUB_ASSESS_VERSION . '.' . $mtime : VULNHUB_ASSESS_VERSION );
	}

	/* =================================================================
	 * Permissions
	 * ============================================================== */

	public static function can_edit(): bool {
		$cap = (string) apply_filters( 'vulnhub_assess_edit_cap', \VulnHub\Core\Caps::MANAGE );

		return is_user_logged_in() && current_user_can( $cap ) && ! self::is_copy();
	}

	/** A read-only copy of another instance takes its rows from the source. */
	public static function is_copy(): bool {
		return class_exists( 'VulnHub_Replica_Guard' ) && VulnHub_Replica_Guard::active();
	}

	/* =================================================================
	 * Query string
	 * ============================================================== */

	private static function q( string $key, string $default = '' ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET[ $key ] ) ? sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) ) : $default;
	}

	/** @return array{kind:string,source:string,outcome:string,group:string,q:string,due:string} */
	private static function filters( string $tab ): array {
		return array(
			'kind'    => 'exception' === $tab ? 'exception' : 'supplier',
			'source'  => in_array( self::q( 'src' ), VH_Assess_Repo::SOURCES, true ) ? self::q( 'src' ) : '',
			'outcome' => isset( VH_Assess_Repo::outcomes()[ self::q( 'outcome' ) ] ) ? self::q( 'outcome' ) : '',
			'group'   => isset( VH_Assess_Repo::groups()[ self::q( 'group' ) ] ) ? self::q( 'group' ) : '',
			'q'       => mb_substr( self::q( 'aq' ), 0, 100 ),
			'due'     => '1' === self::q( 'due' ) ? '1' : '',
		);
	}

	private static function tab(): string {
		$t = sanitize_key( self::q( 'tab' ) );

		return in_array( $t, self::TABS, true ) ? $t : 'supplier';
	}

	/* =================================================================
	 * Page
	 * ============================================================== */

	public static function render(): void {
		$tab = self::tab();

		echo '<div class="vh-assess">';
		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'Supplier assessments', 'vulnhub' ) . '</h1>';
		echo '<p class="vh-sub">' . esc_html__( 'Third-party information security assessments and security exceptions: who reviewed each one, who decided, on what conditions, and when it needs looking at again. Jira tickets open from each row.', 'vulnhub' ) . '</p>';
		echo '</div></div>';

		self::notices();

		if ( '' !== self::q( 'exc' ) ) {
			self::render_exception_form( 'new' === self::q( 'exc' ) ? 0 : absint( self::q( 'exc' ) ) );
			echo '</div>';
			return;
		}

		$id = absint( self::q( 'edit' ) );

		if ( $id || '1' === self::q( 'add' ) ) {
			self::render_form( $id );
			echo '</div>';
			return;
		}

		self::render_tiles( $tab );
		self::render_tabs( $tab );

		if ( 'inbox' === $tab ) {
			self::render_inbox();
		} else {
			self::render_list( $tab );
		}

		echo '</div>';
	}

	private static function notices(): void {
		$msg = sanitize_key( self::q( 'vh_msg' ) );
		$map = array(
			'saved'      => array( 'info', __( 'Saved.', 'vulnhub' ) ),
			'deleted'    => array( 'info', __( 'Deleted.', 'vulnhub' ) ),
			'dismissed'  => array( 'info', __( 'Set aside. It will not be listed as missing from the register again.', 'vulnhub' ) ),
			'restored'   => array( 'info', __( 'Put back on the list of tickets not yet in the register.', 'vulnhub' ) ),
			'invalid'    => array( 'warn', __( 'Nothing was saved: a record needs a name.', 'vulnhub' ) ),
			'denied'     => array( 'warn', __( 'You do not have permission to change the register.', 'vulnhub' ) ),
			'copy'       => array( 'warn', __( 'This is a read-only copy. Change the register on the source instance.', 'vulnhub' ) ),
			'notfound'   => array( 'warn', __( 'That record no longer exists.', 'vulnhub' ) ),
		);

		$err = self::q( 'vh_err' );
		if ( '' !== $err ) {
			printf( '<div class="vh-notice vh-notice--warn" role="alert">%s</div>', esc_html( mb_substr( $err, 0, 300 ) ) );
		}

		if ( isset( $map[ $msg ] ) ) {
			printf( '<div class="vh-notice vh-notice--%s" role="status">%s</div>', esc_attr( $map[ $msg ][0] ), esc_html( $map[ $msg ][1] ) );
		}
	}

	/* ------------------------------------------------------------ tiles */

	private static function render_tiles( string $tab ): void {
		if ( ! class_exists( 'VulnHub_Dash_Charts' ) ) {
			return;
		}

		$kind  = 'exception' === $tab ? 'exception' : 'supplier';
		$c     = VH_Assess_Repo::counts( $kind );
		$base  = array( 'tab' => $kind );
		$tiles = array();

		if ( 'supplier' === $kind ) {
			$meta    = VH_Assess_Repo::meta();
			$tiles[] = array(
				'label' => __( 'Supplier records', 'vulnhub' ),
				'value' => $c['all'],
				'tone'  => 'neutral',
				'meta'  => sprintf( /* translators: 1: inherited, 2: done here */ __( '%1$s inherited · %2$s since', 'vulnhub' ), number_format_i18n( $c['inherited'] ), number_format_i18n( $c['internal'] ) ),
				'href'  => self::url( $base ),
			);
			$tiles[] = array(
				'label' => '' !== $meta['inherited_label'] ? sprintf( /* translators: %s: previous team */ __( 'Inherited from %s', 'vulnhub' ), $meta['inherited_label'] ) : __( 'Inherited', 'vulnhub' ),
				'value' => $c['inherited'],
				'tone'  => 'neutral',
				'meta'  => sprintf( /* translators: 1: approved, 2: rejected */ __( '%1$s approved · %2$s rejected', 'vulnhub' ), number_format_i18n( $c['inherited_approved'] ), number_format_i18n( $c['inherited_declined'] ) ),
				'href'  => self::url( $base + array( 'src' => 'inherited' ) ),
			);
			$tiles[] = array(
				'label' => __( 'Assessed by us', 'vulnhub' ),
				'value' => $c['internal'],
				'tone'  => 'neutral',
				'meta'  => sprintf( /* translators: 1: approved, 2: declined */ __( '%1$s approved · %2$s rejected or not approved', 'vulnhub' ), number_format_i18n( $c['internal_approved'] ), number_format_i18n( $c['internal_declined'] ) ),
				'href'  => self::url( $base + array( 'src' => 'internal' ) ),
			);
		} else {
			$tiles[] = array(
				'label' => __( 'Exceptions recorded', 'vulnhub' ),
				'value' => $c['all'],
				'tone'  => 'neutral',
				'meta'  => sprintf( /* translators: %s: approved */ __( '%s approved, with or without conditions', 'vulnhub' ), number_format_i18n( $c['approved'] ) ),
				'href'  => self::url( $base ),
			);
		}

		$tiles[] = array(
			'label' => __( 'Waiting on a decision', 'vulnhub' ),
			'value' => $c['open'],
			'tone'  => $c['open'] > 0 ? 'warning' : 'good',
			'meta'  => __( 'Awaiting review, questionnaire or approver', 'vulnhub' ),
			'href'  => self::url( $base + array( 'group' => 'open' ) ),
		);
		$tiles[] = array(
			'label' => __( 'Review date passed or near', 'vulnhub' ),
			'value' => $c['overdue'] + $c['due'],
			'tone'  => $c['overdue'] > 0 ? 'critical' : ( $c['due'] > 0 ? 'warning' : 'good' ),
			'meta'  => sprintf( /* translators: 1: overdue, 2: due within 60 days */ __( '%1$s passed · %2$s within 60 days', 'vulnhub' ), number_format_i18n( $c['overdue'] ), number_format_i18n( $c['due'] ) ),
			'href'  => self::url( $base + array( 'due' => '1' ) ),
		);

		$missing = count( VH_Assess_Jira::unregistered() );
		$tiles[] = array(
			'label' => __( 'Tickets not in the register', 'vulnhub' ),
			'value' => $missing,
			'tone'  => $missing > 0 ? 'warning' : 'good',
			'meta'  => __( 'Assessment requests in Jira with no record', 'vulnhub' ),
			'href'  => self::url( array( 'tab' => 'inbox' ) ),
		);

		echo '<div class="vh-tiles vh-assess__tiles">';
		foreach ( $tiles as $t ) {
			echo VulnHub_Dash_Charts::stat_tile( $t ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		echo '</div>';
	}

	private static function render_tabs( string $tab ): void {
		$labels = array(
			'supplier' => array( __( 'Supplier assessments', 'vulnhub' ), VH_Assess_Repo::counts( 'supplier' )['all'], '' ),
			'inbox'    => array( __( 'Not yet recorded', 'vulnhub' ), count( VH_Assess_Jira::unregistered() ), ' vh-tabs__n--warn' ),
		);

		echo '<nav class="vh-tabs vh-tabs--count vh-assess__tabs" aria-label="' . esc_attr__( 'Register views', 'vulnhub' ) . '">';
		foreach ( $labels as $key => $l ) {
			printf(
				'<a class="vh-tabs__tab%s" href="%s"%s>%s <span class="vh-tabs__n%s">%s</span></a>',
				$key === $tab ? ' is-active' : '',
				esc_url( self::url( array( 'tab' => $key ) ) ),
				$key === $tab ? ' aria-current="page"' : '',
				esc_html( $l[0] ),
				$l[1] > 0 ? esc_attr( $l[2] ) : '',
				esc_html( number_format_i18n( (int) $l[1] ) )
			);
		}
		printf(
			'<a class="vh-tabs__tab" href="%s">%s <span aria-hidden="true">→</span></a>',
			esc_url( self::exceptions_url( array( 'etype' => 'policy' ) ) ),
			esc_html__( 'Security exceptions', 'vulnhub' )
		);
		echo '</nav>';
	}

	/* ------------------------------------------------------------- list */

	private static function render_list( string $tab ): void {
		$f    = self::filters( $tab );
		$rows = VH_Assess_Repo::rows( $f );
		$sup  = 'supplier' === $f['kind'];

		self::filter_form( $tab, $f, count( $rows ) );

		if ( $sup ) {
			self::reconcile_callout( $f );
		}

		if ( ! $rows ) {
			echo '<div class="vh-panel"><p class="vh-empty">' . esc_html__( 'Nothing in the register matches.', 'vulnhub' ) . '</p></div>';
			return;
		}

		$heads = $sup
			? array( __( 'Supplier', 'vulnhub' ), __( 'Raised', 'vulnhub' ), __( 'Review', 'vulnhub' ), __( 'Decision', 'vulnhub' ), __( 'Look again', 'vulnhub' ), __( 'Jira', 'vulnhub' ) )
			: array( __( 'Exception', 'vulnhub' ), __( 'Raised', 'vulnhub' ), __( 'Review', 'vulnhub' ), __( 'Decision', 'vulnhub' ), __( 'Look again', 'vulnhub' ), __( 'Jira', 'vulnhub' ) );

		$edit = self::can_edit();

		echo '<div class="vh-tablewrap"><table class="vh-table vh-assess__table"><thead><tr>';
		foreach ( $heads as $h ) {
			printf( '<th scope="col">%s</th>', esc_html( $h ) );
		}
		echo '</tr></thead><tbody>';

		foreach ( $rows as $r ) {
			echo '<tr>';

			// Subject.
			echo '<td class="vh-assess__subject">';
			printf( '<strong>%s</strong>', esc_html( (string) $r['subject'] ) );
			// Source only matters for suppliers: exceptions are all ours.
			if ( $sup || 'inherited' === $r['source'] ) {
				echo '<div class="vh-assess__tags">';
				if ( 'inherited' === $r['source'] ) {
					printf( '<span class="vh-chip vh-chip--muted">%s</span>', esc_html( '' !== (string) $r['origin'] ? sprintf( /* translators: %s: previous team */ __( 'Inherited · %s', 'vulnhub' ), (string) $r['origin'] ) : __( 'Inherited', 'vulnhub' ) ) );
				} else {
					printf( '<span class="vh-chip vh-assess__chip--ours">%s</span>', esc_html__( 'Assessed by us', 'vulnhub' ) );
				}
				echo '</div>';
			}
			if ( '' !== (string) $r['requested_by'] ) {
				printf( '<div class="vh-meta">%s</div>', esc_html( sprintf( /* translators: %s: person */ __( 'Requested by %s', 'vulnhub' ), (string) $r['requested_by'] ) ) );
			}
			if ( $edit ) {
				printf( '<a class="vh-linkbtn vh-assess__edit" href="%s">%s</a>', esc_url( self::url( array( 'tab' => $tab, 'edit' => (int) $r['id'] ) ) ), esc_html__( 'Edit', 'vulnhub' ) );
			}
			echo '</td>';

			// Raised.
			echo '<td class="vh-assess__date">';
			if ( $r['raised_on'] ) {
				printf( '<span>%s</span>', esc_html( self::d( (string) $r['raised_on'] ) ) );
				$age = self::months_since( (string) $r['raised_on'] );
				printf( '<span class="vh-meta">%s</span>', esc_html( sprintf( /* translators: %s: months */ _n( '%s month ago', '%s months ago', $age, 'vulnhub' ), number_format_i18n( $age ) ) ) );
			} elseif ( '' !== (string) $r['period_text'] ) {
				printf( '<span>%s</span>', esc_html( (string) $r['period_text'] ) );
			} else {
				echo '<span class="vh-meta">—</span>';
			}
			echo '</td>';

			// Review.
			echo '<td class="vh-assess__review">';
			if ( '' !== (string) $r['reviewer'] || $r['reviewed_on'] ) {
				printf(
					'<span>%s</span>',
					esc_html( trim( (string) $r['reviewer'] . ( $r['reviewed_on'] ? ' · ' . self::d( (string) $r['reviewed_on'] ) : '' ), ' ·' ) )
				);
			} else {
				printf( '<span class="vh-meta">%s</span>', esc_html( 'inherited' === $r['source'] ? __( 'Not in the transferred register', 'vulnhub' ) : ( $sup ? __( 'No review recorded', 'vulnhub' ) : '—' ) ) );
			}
			if ( '' !== (string) $r['review_summary'] ) {
				printf( '<div class="vh-meta vh-assess__text">%s</div>', esc_html( vh_trim( (string) $r['review_summary'], 220 ) ) );
			}
			echo '</td>';

			// Decision.
			echo '<td class="vh-assess__decision">';
			echo self::pill( (string) $r['outcome'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			if ( '' !== (string) $r['approver'] || $r['decided_on'] ) {
				printf(
					'<div class="vh-assess__by">%s</div>',
					esc_html( trim( ( '' !== (string) $r['approver'] ? sprintf( /* translators: %s: person */ __( 'by %s', 'vulnhub' ), (string) $r['approver'] ) : '' ) . ( $r['decided_on'] ? ' · ' . self::d( (string) $r['decided_on'] ) : '' ), ' ·' ) )
				);
			}
			if ( '' !== (string) $r['conditions'] ) {
				printf( '<div class="vh-meta vh-assess__text">%s</div>', esc_html( vh_trim( (string) $r['conditions'], 260 ) ) );
			}
			if ( '' !== (string) $r['notes'] ) {
				printf( '<div class="vh-meta vh-assess__text vh-assess__note">%s</div>', esc_html( vh_trim( (string) $r['notes'], 260 ) ) );
			}
			if ( 'open' === $r['group'] && $r['keys'] ) {
				$h = VH_Assess_Jira::hint_for_keys( $r['keys'], (string) $r['requested_by'], (string) $r['reviewer'] );
				if ( $h ) {
					self::hint_line( $h, $edit ? self::url( array( 'tab' => $tab, 'edit' => (int) $r['id'] ) ) : '' );
				}
			}
			echo '</td>';

			// Look again.
			echo '<td class="vh-assess__due">';
			echo self::due_cell( $r ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '</td>';

			// Jira.
			echo '<td class="vh-assess__jira">';
			echo self::keys_cell( $r['keys'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '</td>';

			echo '</tr>';
		}

		echo '</tbody></table></div>';

		if ( $sup ) {
			self::register_notes();
		}
	}

	private static function filter_form( string $tab, array $f, int $n ): void {
		?>
		<form class="vh-filters vh-assess__filters" method="get" action="<?php echo esc_url( self::url() ); ?>">
			<input type="hidden" name="tab" value="<?php echo esc_attr( $tab ); ?>">
			<label><?php esc_html_e( 'Search', 'vulnhub' ); ?>
				<input type="search" name="aq" value="<?php echo esc_attr( $f['q'] ); ?>" placeholder="<?php esc_attr_e( 'name, person, ticket, condition…', 'vulnhub' ); ?>">
			</label>
			<?php if ( 'supplier' === $f['kind'] ) : ?>
			<label><?php esc_html_e( 'Source', 'vulnhub' ); ?>
				<select name="src">
					<option value=""><?php esc_html_e( 'Inherited and ours', 'vulnhub' ); ?></option>
					<option value="inherited" <?php selected( $f['source'], 'inherited' ); ?>><?php esc_html_e( 'Inherited', 'vulnhub' ); ?></option>
					<option value="internal" <?php selected( $f['source'], 'internal' ); ?>><?php esc_html_e( 'Assessed by us', 'vulnhub' ); ?></option>
				</select>
			</label>
			<?php endif; ?>
			<label><?php esc_html_e( 'Decision', 'vulnhub' ); ?>
				<select name="group">
					<option value=""><?php esc_html_e( 'Any', 'vulnhub' ); ?></option>
					<?php foreach ( VH_Assess_Repo::groups() as $k => $label ) : ?>
						<option value="<?php echo esc_attr( $k ); ?>" <?php selected( $f['group'], $k ); ?>><?php echo esc_html( $label ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label><?php esc_html_e( 'Exact outcome', 'vulnhub' ); ?>
				<select name="outcome">
					<option value=""><?php esc_html_e( 'Any', 'vulnhub' ); ?></option>
					<?php foreach ( VH_Assess_Repo::outcomes() as $k => $o ) : ?>
						<option value="<?php echo esc_attr( $k ); ?>" <?php selected( $f['outcome'], $k ); ?>><?php echo esc_html( $o['label'] ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label class="vh-assess__check"><input type="checkbox" name="due" value="1" <?php checked( $f['due'], '1' ); ?>> <?php esc_html_e( 'Has a review date', 'vulnhub' ); ?></label>
			<button class="vh-btn vh-btn--primary" type="submit"><?php esc_html_e( 'Apply', 'vulnhub' ); ?></button>
			<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( self::url( array( 'tab' => $tab ) ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
		</form>
		<div class="vh-assess__bar">
			<p class="vh-meta"><?php echo esc_html( sprintf( /* translators: %s: rows */ _n( '%s record', '%s records', $n, 'vulnhub' ), number_format_i18n( $n ) ) ); ?></p>
			<div class="vh-assess__actions">
				<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::csv_url( $tab, $f ) ); ?>"><?php esc_html_e( 'Export CSV', 'vulnhub' ); ?></a>
				<?php if ( self::can_edit() ) : ?>
					<a class="vh-btn vh-btn--primary vh-btn--sm" href="<?php echo esc_url( self::url( array( 'tab' => $tab, 'add' => '1', 'kind' => $f['kind'] ) ) ); ?>"><?php echo esc_html( 'exception' === $f['kind'] ? __( 'Add an exception', 'vulnhub' ) : __( 'Add an assessment', 'vulnhub' ) ); ?></a>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * When the inherited register's own summary disagrees with its supplier
	 * list, say so on the page rather than quietly picking one.
	 */
	private static function reconcile_callout( array $f ): void {
		if ( 'internal' === $f['source'] ) {
			return;
		}

		$meta = VH_Assess_Repo::meta();
		$sum  = $meta['inherited_summary'];

		if ( ! $sum ) {
			return;
		}

		$have = array();
		foreach ( VH_Assess_Repo::rows( array( 'kind' => 'supplier', 'source' => 'inherited' ) ) as $r ) {
			$have[ $r['outcome'] ] = ( $have[ $r['outcome'] ] ?? 0 ) + 1;
		}

		$diff = array();
		foreach ( $sum as $o => $n ) {
			if ( (int) ( $have[ $o ] ?? 0 ) !== (int) $n ) {
				$diff[] = sprintf( /* translators: 1: outcome, 2: summary count, 3: list count */ __( '%1$s: %2$d in its summary, %3$d in its list', 'vulnhub' ), VH_Assess_Repo::outcome_label( (string) $o ), (int) $n, (int) ( $have[ $o ] ?? 0 ) );
			}
		}

		if ( ! $diff ) {
			return;
		}

		echo '<div class="vh-notice vh-notice--warn vh-assess__recon">';
		printf( '<strong>%s</strong> ', esc_html__( 'The inherited register disagrees with itself.', 'vulnhub' ) );
		echo esc_html( implode( '; ', $diff ) . '. ' . __( 'This page counts from the supplier list. Confirm against the source register.', 'vulnhub' ) );
		echo '</div>';
	}

	private static function register_notes(): void {
		$meta  = VH_Assess_Repo::meta();
		$lines = array();

		if ( '' !== $meta['inherited_label'] ) {
			$lines[] = '' !== $meta['inherited_as_at']
				? sprintf( /* translators: 1: team, 2: date */ __( 'Inherited rows come from the register transferred from %1$s, position as at %2$s.', 'vulnhub' ), $meta['inherited_label'], self::d( $meta['inherited_as_at'] ) )
				: sprintf( /* translators: %s: team */ __( 'Inherited rows come from the register transferred from %s.', 'vulnhub' ), $meta['inherited_label'] );
		}
		foreach ( $meta['notes'] as $n ) {
			$lines[] = $n;
		}
		$lines[] = __( 'Decisions on rows assessed by us are taken from the approver\'s own comment on the Jira ticket. A "decision" suggestion on an open row is the newest comment that reads like one; it is not recorded until someone saves it.', 'vulnhub' );

		echo '<div class="vh-panel vh-assess__notes"><h2 class="vh-panel__title">' . esc_html__( 'About this register', 'vulnhub' ) . '</h2><ul>';
		foreach ( $lines as $l ) {
			echo '<li>' . esc_html( $l ) . '</li>';
		}
		echo '</ul></div>';
	}

	/* ------------------------------------------------------------ inbox */

	private static function render_inbox(): void {
		if ( ! VH_Assess_Jira::available() ) {
			echo '<div class="vh-notice vh-notice--info">' . esc_html__( 'The Jira plugin is not active, so there is no list of assessment requests to compare the register with.', 'vulnhub' ) . '</div>';
			return;
		}

		$rows = VH_Assess_Jira::unregistered();
		$edit = self::can_edit();

		echo '<p class="vh-meta vh-assess__lead">' . esc_html__( 'Assessment requests on the service desk that are neither in this register nor in the Exception register. Add each one as a supplier assessment, record it as a security exception, or set it aside if it is neither (a test, an access request, a question). The suggested decision is the newest comment that reads like one.', 'vulnhub' ) . '</p>';

		if ( ! $rows ) {
			echo '<div class="vh-panel"><p class="vh-empty">' . esc_html__( 'Every assessment request is in the register or set aside.', 'vulnhub' ) . '</p></div>';
		} else {
			echo '<div class="vh-tablewrap"><table class="vh-table vh-assess__table"><thead><tr>';
			foreach ( array( __( 'Ticket', 'vulnhub' ), __( 'Raised', 'vulnhub' ), __( 'Status', 'vulnhub' ), __( 'Suggested decision', 'vulnhub' ), '' ) as $h ) {
				printf( '<th scope="col">%s</th>', esc_html( $h ) );
			}
			echo '</tr></thead><tbody>';

			foreach ( $rows as $r ) {
				echo '<tr>';
				echo '<td class="vh-assess__subject">' . self::keys_cell( array( (string) $r['key'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				printf( '<div><strong>%s</strong></div>', esc_html( (string) $r['summary'] ) );
				if ( '' !== (string) $r['reporter'] ) {
					printf( '<div class="vh-meta">%s</div>', esc_html( sprintf( /* translators: %s: person */ __( 'Requested by %s', 'vulnhub' ), (string) $r['reporter'] ) ) );
				}
				echo '</td>';
				printf( '<td class="vh-assess__date">%s</td>', esc_html( $r['created_at'] ? self::d( substr( (string) $r['created_at'], 0, 10 ) ) : '—' ) );
				printf( '<td>%s</td>', esc_html( (string) $r['status'] ) );
				echo '<td class="vh-assess__decision">';
				if ( $r['hint'] ) {
					echo self::pill( (string) $r['hint']['outcome'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					printf( '<div class="vh-assess__by">%s</div>', esc_html( sprintf( /* translators: 1: person, 2: date */ __( '%1$s · %2$s', 'vulnhub' ), (string) $r['hint']['by'], self::d( substr( (string) $r['hint']['at'], 0, 10 ) ) ) ) );
					printf( '<div class="vh-meta vh-assess__text">“%s”</div>', esc_html( vh_trim( (string) $r['hint']['text'], 200 ) ) );
				} else {
					echo '<span class="vh-meta">' . esc_html__( 'No decision found in the comments read so far', 'vulnhub' ) . '</span>';
				}
				echo '</td>';
				echo '<td class="vh-assess__rowact">';
				if ( $edit ) {
					printf( '<a class="vh-btn vh-btn--primary vh-btn--sm" href="%s">%s</a> ', esc_url( self::url( array( 'tab' => 'supplier', 'add' => '1', 'jira' => (string) $r['key'], 'kind' => 'supplier' ) ) ), esc_html__( 'Add as assessment', 'vulnhub' ) );
					if ( self::core_exceptions() ) {
						printf( '<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>', esc_url( self::url( array( 'exc' => 'new', 'jira' => (string) $r['key'] ) ) ), esc_html__( 'Record as security exception', 'vulnhub' ) );
					}
					self::dismiss_form( (string) $r['key'] );
				}
				echo '</td>';
				echo '</tr>';
			}

			echo '</tbody></table></div>';
		}

		$aside = VH_Assess_Jira::set_aside();
		if ( $aside ) {
			echo '<details class="vh-panel vh-assess__aside"><summary>' . esc_html( sprintf( /* translators: %s: count */ __( 'Set aside as not register items (%s)', 'vulnhub' ), number_format_i18n( count( $aside ) ) ) ) . '</summary>';
			echo '<div class="vh-tablewrap"><table class="vh-table"><thead><tr>';
			foreach ( array( __( 'Ticket', 'vulnhub' ), __( 'Summary', 'vulnhub' ), __( 'Why', 'vulnhub' ), '' ) as $h ) {
				printf( '<th scope="col">%s</th>', esc_html( $h ) );
			}
			echo '</tr></thead><tbody>';
			foreach ( $aside as $a ) {
				echo '<tr><td>' . self::keys_cell( array( (string) $a['key'] ) ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				printf( '<td>%s</td><td class="vh-meta">%s</td><td>', esc_html( '' !== $a['summary'] ? $a['summary'] : '—' ), esc_html( $a['reason'] ) );
				if ( $edit ) {
					?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-assess__inline">
						<?php wp_nonce_field( self::ACTION_RESTORE ); ?>
						<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_RESTORE ); ?>">
						<input type="hidden" name="key" value="<?php echo esc_attr( (string) $a['key'] ); ?>">
						<button class="vh-linkbtn" type="submit"><?php esc_html_e( 'Put back', 'vulnhub' ); ?></button>
					</form>
					<?php
				}
				echo '</td></tr>';
			}
			echo '</tbody></table></div></details>';
		}
	}

	private static function dismiss_form( string $key ): void {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-assess__inline vh-assess__dismiss">
			<?php wp_nonce_field( self::ACTION_DISMISS ); ?>
			<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_DISMISS ); ?>">
			<input type="hidden" name="key" value="<?php echo esc_attr( $key ); ?>">
			<label class="screen-reader-text" for="vh-assess-why-<?php echo esc_attr( $key ); ?>"><?php esc_html_e( 'Why it is not a register item', 'vulnhub' ); ?></label>
			<select name="reason" id="vh-assess-why-<?php echo esc_attr( $key ); ?>">
				<?php foreach ( self::dismiss_reasons() as $r ) : ?>
					<option value="<?php echo esc_attr( $r ); ?>"><?php echo esc_html( $r ); ?></option>
				<?php endforeach; ?>
			</select>
			<button class="vh-linkbtn" type="submit"><?php esc_html_e( 'Set aside', 'vulnhub' ); ?></button>
		</form>
		<?php
	}

	/** @return array<int,string> */
	private static function dismiss_reasons(): array {
		return (array) apply_filters(
			'vulnhub_assess_dismiss_reasons',
			array(
				__( 'Not an assessment or exception', 'vulnhub' ),
				__( 'Test ticket', 'vulnhub' ),
				__( 'Raised in error or cancelled', 'vulnhub' ),
				__( 'Duplicate of another ticket', 'vulnhub' ),
				__( 'Customer assessing us, not a supplier', 'vulnhub' ),
			)
		);
	}

	/* ------------------------------------------------------------- form */

	private static function render_form( int $id ): void {
		if ( ! self::can_edit() ) {
			echo '<div class="vh-notice vh-notice--warn">' . esc_html( self::is_copy() ? __( 'This is a read-only copy. Change the register on the source instance.', 'vulnhub' ) : __( 'You do not have permission to change the register.', 'vulnhub' ) ) . '</div>';
			return;
		}

		$row  = $id ? VH_Assess_Repo::get( $id ) : null;
		$hint = null;

		if ( $id && ! $row ) {
			echo '<div class="vh-notice vh-notice--warn">' . esc_html__( 'That record no longer exists.', 'vulnhub' ) . '</div>';
			return;
		}

		if ( ! $row ) {
			$row = self::prefill();
		}

		$keys = VH_Assess_Repo::split_keys( (string) $row['jira_keys'] );
		if ( $keys ) {
			$hint = VH_Assess_Jira::hint_for_keys( $keys, (string) $row['requested_by'], (string) $row['reviewer'] );
		}

		// An open row with a decision in Jira: offer it, pre-filled, unsaved.
		$offered = false;
		if ( $hint && 'open' === VH_Assess_Repo::group_of( (string) $row['outcome'] ) ) {
			$row['outcome']    = $hint['outcome'];
			$row['approver']   = '' !== (string) $row['approver'] ? $row['approver'] : $hint['by'];
			$row['decided_on'] = $row['decided_on'] ?: substr( (string) $hint['at'], 0, 10 );
			if ( '' === trim( (string) $row['conditions'] ) && 'approved' !== $hint['outcome'] ) {
				$row['conditions'] = $hint['text'];
			}
			$offered = true;
		}

		$tab    = 'exception' === $row['kind'] ? 'exception' : 'supplier';
		$people = VH_Assess_Repo::people();
		$back   = self::url( array( 'tab' => $tab ) );

		echo '<div class="vh-panel vh-assess__form">';
		printf( '<h2 class="vh-panel__title">%s</h2>', esc_html( $id ? __( 'Edit record', 'vulnhub' ) : __( 'New record', 'vulnhub' ) ) );

		if ( $hint ) {
			echo '<div class="vh-notice vh-notice--info">';
			printf(
				'%s <strong>%s</strong> — “%s”',
				esc_html( sprintf( /* translators: 1: person, 2: date, 3: key */ __( '%1$s commented on %3$s on %2$s:', 'vulnhub' ), (string) $hint['by'], self::d( substr( (string) $hint['at'], 0, 10 ) ), (string) $hint['key'] ) ),
				esc_html( VH_Assess_Repo::outcome_label( (string) $hint['outcome'] ) ),
				esc_html( vh_trim( (string) $hint['text'], 300 ) )
			);
			if ( $offered ) {
				echo ' ' . esc_html__( 'The decision fields below are filled in from it. Check them, then save.', 'vulnhub' );
			}
			echo '</div>';
		}
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-assess__grid">
			<?php wp_nonce_field( self::ACTION_SAVE ); ?>
			<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_SAVE ); ?>">
			<input type="hidden" name="id" value="<?php echo esc_attr( (string) $id ); ?>">

			<fieldset class="vh-assess__set">
				<legend><?php esc_html_e( 'What', 'vulnhub' ); ?></legend>
				<input type="hidden" name="kind" value="supplier">
				<label class="vh-assess__wide"><?php esc_html_e( 'Supplier', 'vulnhub' ); ?>
					<input type="text" name="subject" required maxlength="255" value="<?php echo esc_attr( (string) $row['subject'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Source', 'vulnhub' ); ?>
					<select name="source">
						<option value="internal" <?php selected( $row['source'], 'internal' ); ?>><?php esc_html_e( 'Assessed by us', 'vulnhub' ); ?></option>
						<option value="inherited" <?php selected( $row['source'], 'inherited' ); ?>><?php esc_html_e( 'Inherited register', 'vulnhub' ); ?></option>
					</select>
				</label>
				<label><?php esc_html_e( 'Inherited from', 'vulnhub' ); ?>
					<input type="text" name="origin" maxlength="190" value="<?php echo esc_attr( (string) $row['origin'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Jira tickets', 'vulnhub' ); ?>
					<input type="text" name="jira_keys" maxlength="255" value="<?php echo esc_attr( (string) $row['jira_keys'] ); ?>" placeholder="<?php esc_attr_e( 'KEY-123, KEY-456', 'vulnhub' ); ?>">
				</label>
				<label><?php esc_html_e( 'Requested by', 'vulnhub' ); ?>
					<input type="text" name="requested_by" maxlength="190" value="<?php echo esc_attr( (string) $row['requested_by'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Raised on', 'vulnhub' ); ?>
					<input type="date" name="raised_on" value="<?php echo esc_attr( (string) $row['raised_on'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Or a period, when no exact date is known', 'vulnhub' ); ?>
					<input type="text" name="period_text" maxlength="80" value="<?php echo esc_attr( (string) $row['period_text'] ); ?>">
				</label>
			</fieldset>

			<fieldset class="vh-assess__set">
				<legend><?php esc_html_e( 'Review', 'vulnhub' ); ?></legend>
				<label><?php esc_html_e( 'Reviewed by', 'vulnhub' ); ?>
					<input type="text" name="reviewer" maxlength="190" list="vh-assess-reviewers" value="<?php echo esc_attr( (string) $row['reviewer'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Reviewed on', 'vulnhub' ); ?>
					<input type="date" name="reviewed_on" value="<?php echo esc_attr( (string) $row['reviewed_on'] ); ?>">
				</label>
				<label class="vh-assess__wide"><?php esc_html_e( 'Reviewer\'s summary and recommendation', 'vulnhub' ); ?>
					<textarea name="review_summary" rows="3"><?php echo esc_textarea( (string) $row['review_summary'] ); ?></textarea>
				</label>
			</fieldset>

			<fieldset class="vh-assess__set">
				<legend><?php esc_html_e( 'Decision', 'vulnhub' ); ?></legend>
				<label><?php esc_html_e( 'Outcome', 'vulnhub' ); ?>
					<select name="outcome">
						<?php foreach ( VH_Assess_Repo::outcomes() as $k => $o ) : ?>
							<option value="<?php echo esc_attr( $k ); ?>" <?php selected( $row['outcome'], $k ); ?>><?php echo esc_html( $o['label'] ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<label><?php esc_html_e( 'Decided by', 'vulnhub' ); ?>
					<input type="text" name="approver" maxlength="190" list="vh-assess-approvers" value="<?php echo esc_attr( (string) $row['approver'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Decided on', 'vulnhub' ); ?>
					<input type="date" name="decided_on" value="<?php echo esc_attr( (string) $row['decided_on'] ); ?>">
				</label>
				<label class="vh-assess__wide"><?php esc_html_e( 'Conditions', 'vulnhub' ); ?>
					<textarea name="conditions" rows="3"><?php echo esc_textarea( (string) $row['conditions'] ); ?></textarea>
				</label>
				<label><?php esc_html_e( 'Look at again by', 'vulnhub' ); ?>
					<input type="date" name="review_due" value="<?php echo esc_attr( (string) $row['review_due'] ); ?>">
				</label>
				<label><?php esc_html_e( 'No longer in force from', 'vulnhub' ); ?>
					<input type="date" name="ended_on" value="<?php echo esc_attr( (string) $row['ended_on'] ); ?>">
				</label>
				<label class="vh-assess__wide"><?php esc_html_e( 'Notes', 'vulnhub' ); ?>
					<textarea name="notes" rows="3"><?php echo esc_textarea( (string) $row['notes'] ); ?></textarea>
				</label>
			</fieldset>

			<datalist id="vh-assess-reviewers"><?php foreach ( $people['reviewers'] as $p ) { printf( '<option value="%s">', esc_attr( $p ) ); } ?></datalist>
			<datalist id="vh-assess-approvers"><?php foreach ( $people['approvers'] as $p ) { printf( '<option value="%s">', esc_attr( $p ) ); } ?></datalist>

			<div class="vh-assess__formbar">
				<button class="vh-btn vh-btn--primary" type="submit"><?php esc_html_e( 'Save', 'vulnhub' ); ?></button>
				<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( $back ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
			</div>
		</form>
		<?php
		if ( $id ) {
			?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-assess__delete" onsubmit="return confirm('<?php echo esc_js( __( 'Delete this record? This cannot be undone.', 'vulnhub' ) ); ?>');">
				<?php wp_nonce_field( self::ACTION_DELETE ); ?>
				<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_DELETE ); ?>">
				<input type="hidden" name="id" value="<?php echo esc_attr( (string) $id ); ?>">
				<button class="vh-linkbtn vh-assess__danger" type="submit"><?php esc_html_e( 'Delete this record', 'vulnhub' ); ?></button>
			</form>
			<?php
		}
		echo '</div>';
	}

	/**
	 * A new row, filled from the Jira inbox when `jira=KEY` names one.
	 *
	 * @return array<string,mixed>
	 */
	private static function prefill(): array {
		$kind = 'exception' === self::q( 'kind' ) ? 'exception' : 'supplier';
		$user = wp_get_current_user();
		$row  = array(
			'kind'           => $kind,
			'subject'        => '',
			'source'         => 'internal',
			'origin'         => '',
			'raised_on'      => '',
			'period_text'    => '',
			'requested_by'   => '',
			'outcome'        => 'in_review',
			'reviewer'       => $user && $user->exists() ? (string) $user->display_name : '',
			'reviewed_on'    => '',
			'review_summary' => '',
			'approver'       => '',
			'decided_on'     => '',
			'conditions'     => '',
			'review_due'     => '',
			'ended_on'       => '',
			'jira_keys'      => '',
			'notes'          => '',
		);

		$key = VH_Assess_Repo::norm_key( self::q( 'jira' ) );

		if ( '' !== $key ) {
			$r                   = VH_Assess_Jira::inbox()[ $key ] ?? array();
			$row['jira_keys']    = $key;
			$row['subject']      = (string) ( $r['summary'] ?? '' );
			$row['requested_by'] = (string) ( $r['reporter'] ?? '' );
			$row['raised_on']    = ! empty( $r['created_at'] ) ? substr( (string) $r['created_at'], 0, 10 ) : '';
		}

		return $row;
	}

	/* =================================================================
	 * Handlers
	 * ============================================================== */

	private static function guard( string $nonce ): void {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( $nonce );

		if ( self::is_copy() ) {
			self::back( array( 'vh_msg' => 'copy' ) );
		}
		if ( ! self::can_edit() ) {
			self::back( array( 'vh_msg' => 'denied' ) );
		}
	}

	/**
	 * @param array<string,mixed> $args Query args.
	 * @return never
	 */
	private static function back( array $args, string $url = '' ): void {
		if ( '' === $url ) {
			$ref = wp_get_referer();
			$url = $ref && str_starts_with( (string) $ref, home_url() ) ? (string) $ref : self::url();
			$url = remove_query_arg( array( 'vh_msg', 'edit', 'add', 'jira' ), $url );
		}

		wp_safe_redirect( add_query_arg( $args, $url ) );
		exit;
	}

	public static function handle_save(): void {
		self::guard( self::ACTION_SAVE );

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- checked in guard().
		$id   = isset( $_POST['id'] ) ? absint( wp_unslash( $_POST['id'] ) ) : 0;
		$data = array();
		foreach ( array( 'kind', 'subject', 'source', 'origin', 'raised_on', 'period_text', 'requested_by', 'outcome', 'reviewer', 'reviewed_on', 'review_summary', 'approver', 'decided_on', 'conditions', 'review_due', 'ended_on', 'jira_keys', 'notes' ) as $f ) {
			$data[ $f ] = isset( $_POST[ $f ] ) ? (string) wp_unslash( $_POST[ $f ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- VH_Assess_Repo::clean().
		}
		// phpcs:enable

		if ( $id && ! VH_Assess_Repo::get( $id ) ) {
			self::back( array( 'vh_msg' => 'notfound' ) );
		}

		$before = $id ? VH_Assess_Repo::get( $id ) : null;
		$saved  = VH_Assess_Repo::save( $data, $id );
		$tab    = 'exception' === $data['kind'] ? 'exception' : 'supplier';

		if ( ! $saved ) {
			self::back( array( 'vh_msg' => 'invalid' ) );
		}

		$after = VH_Assess_Repo::get( $saved );

		vulnhub()->logger->audit(
			$id ? 'assessment.updated' : 'assessment.created',
			sprintf( '%s %s: %s (%s)', $id ? 'Updated' : 'Added', 'exception' === $tab ? 'exception' : 'supplier assessment', (string) ( $after['subject'] ?? '' ), VH_Assess_Repo::outcome_label( (string) ( $after['outcome'] ?? '' ) ) ),
			'assessment',
			(string) $saved,
			array(
				'outcome_before' => $before['outcome'] ?? '',
				'outcome'        => $after['outcome'] ?? '',
				'approver'       => $after['approver'] ?? '',
				'jira'           => $after['jira_keys'] ?? '',
			)
		);

		self::back( array( 'vh_msg' => 'saved' ), self::url( array( 'tab' => $tab ) ) );
	}

	public static function handle_delete(): void {
		self::guard( self::ACTION_DELETE );

		$id  = isset( $_POST['id'] ) ? absint( wp_unslash( $_POST['id'] ) ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$row = $id ? VH_Assess_Repo::get( $id ) : null;

		if ( ! $row ) {
			self::back( array( 'vh_msg' => 'notfound' ) );
		}

		VH_Assess_Repo::delete( $id );

		vulnhub()->logger->audit( 'assessment.deleted', sprintf( 'Deleted %s: %s', (string) $row['kind'], (string) $row['subject'] ), 'assessment', (string) $id, array( 'jira' => $row['jira_keys'] ) );

		self::back( array( 'vh_msg' => 'deleted' ), self::url( array( 'tab' => 'exception' === $row['kind'] ? 'exception' : 'supplier' ) ) );
	}

	public static function handle_dismiss(): void {
		self::guard( self::ACTION_DISMISS );

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$key    = VH_Assess_Repo::norm_key( isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '' );
		$reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
		// phpcs:enable

		if ( '' !== $key ) {
			VH_Assess_Repo::dismiss( $key, $reason );
			vulnhub()->logger->audit( 'assessment.ticket_set_aside', sprintf( 'Set %s aside as not a register item (%s)', $key, $reason ), 'jira_issue', $key );
		}

		self::back( array( 'vh_msg' => 'dismissed' ), self::url( array( 'tab' => 'inbox' ) ) );
	}

	public static function handle_restore(): void {
		self::guard( self::ACTION_RESTORE );

		$key = VH_Assess_Repo::norm_key( isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

		if ( '' !== $key ) {
			VH_Assess_Repo::undismiss( $key );
			vulnhub()->logger->audit( 'assessment.ticket_restored', sprintf( 'Put %s back on the not-yet-registered list', $key ), 'jira_issue', $key );
		}

		self::back( array( 'vh_msg' => 'restored' ), self::url( array( 'tab' => 'inbox' ) ) );
	}

	/* ------------------------------------------------- security exception */

	/**
	 * Record (or correct) a security exception in the core register.
	 *
	 * Pre-filled from the Jira inbox when `jira=KEY` names a request, with
	 * the newest decision-like comment offered as the decision. Saved through
	 * Exceptions::record(), which only writes the `policy` scope, so nothing
	 * here can take a finding out of the open counts.
	 */
	private static function render_exception_form( int $id ): void {
		if ( ! self::core_exceptions() ) {
			echo '<div class="vh-notice vh-notice--warn">' . esc_html__( 'This version of the core plugin cannot hold security exceptions yet.', 'vulnhub' ) . '</div>';
			return;
		}
		if ( ! self::can_edit() ) {
			echo '<div class="vh-notice vh-notice--warn">' . esc_html( self::is_copy() ? __( 'This is a read-only copy. Change the register on the source instance.', 'vulnhub' ) : __( 'You do not have permission to change the register.', 'vulnhub' ) ) . '</div>';
			return;
		}

		$E    = '\\VulnHub\\Core\\Exceptions';
		$back = self::exceptions_url( array( 'etype' => 'policy' ) );
		$row  = array(
			'title'                 => '',
			'reason'                => 'accepted_risk',
			'justification'         => '',
			'compensating_controls' => '',
			'business_impact'       => '',
			'status'                => 'pending',
			'requested_by_name'     => '',
			'approver_name'         => '',
			'decision_note'         => '',
			'jira_key'              => '',
			'expires_at'            => '',
			'review_at'             => '',
			'requested_at'          => '',
			'decided_at'            => '',
			'revoked_at'            => '',
			'reference'             => '',
		);

		if ( $id ) {
			$got = $E::get( $id );
			if ( ! $got || 'policy' !== (string) $got['scope_type'] ) {
				echo '<div class="vh-notice vh-notice--warn">' . esc_html__( 'That is not a security exception, or it no longer exists. Finding exceptions are decided on their own screen.', 'vulnhub' ) . '</div>';
				return;
			}
			foreach ( $row as $k => $v ) {
				$row[ $k ] = (string) ( $got[ $k ] ?? '' );
			}
		} else {
			$key = VH_Assess_Repo::norm_key( self::q( 'jira' ) );
			if ( '' !== $key ) {
				$r                        = VH_Assess_Jira::inbox()[ $key ] ?? array();
				$row['jira_key']          = $key;
				$row['title']             = (string) ( $r['summary'] ?? '' );
				$row['requested_by_name'] = (string) ( $r['reporter'] ?? '' );
				$row['requested_at']      = (string) ( $r['created_at'] ?? '' );
			}
		}

		foreach ( array( 'expires_at', 'review_at', 'requested_at', 'decided_at', 'revoked_at' ) as $d ) {
			$row[ $d ] = '' !== $row[ $d ] ? substr( $row[ $d ], 0, 10 ) : '';
		}

		$hint    = null;
		$offered = false;
		$keys    = VH_Assess_Repo::split_keys( $row['jira_key'] );
		if ( $keys ) {
			$hint = VH_Assess_Jira::hint_for_keys( $keys, $row['requested_by_name'] );
		}
		if ( $hint && in_array( $row['status'], array( 'pending', 'draft' ), true ) ) {
			$map               = array( 'approved' => 'approved', 'conditional' => 'approved', 'rejected' => 'rejected', 'not_approved' => 'rejected' );
			$row['status']     = $map[ $hint['outcome'] ] ?? $row['status'];
			$row['approver_name'] = '' !== $row['approver_name'] ? $row['approver_name'] : $hint['by'];
			$row['decided_at']    = '' !== $row['decided_at'] ? $row['decided_at'] : substr( (string) $hint['at'], 0, 10 );
			if ( '' === trim( $row['decision_note'] ) ) {
				$row['decision_note'] = $hint['text'];
			}
			$offered = true;
		}

		$people = VH_Assess_Repo::people();

		echo '<div class="vh-panel vh-assess__form">';
		printf(
			'<h2 class="vh-panel__title">%s</h2>',
			esc_html( $id ? sprintf( /* translators: %s: reference */ __( 'Edit security exception %s', 'vulnhub' ), $row['reference'] ) : __( 'Record a security exception', 'vulnhub' ) )
		);
		echo '<p class="vh-meta" style="margin:-6px 0 14px">' . esc_html__( 'Saved in the Exception register as a security exception. It does not suppress any finding.', 'vulnhub' ) . '</p>';

		if ( $hint ) {
			echo '<div class="vh-notice vh-notice--info">';
			printf(
				'%s <strong>%s</strong> — “%s”',
				esc_html( sprintf( /* translators: 1: person, 2: date, 3: key */ __( '%1$s commented on %3$s on %2$s:', 'vulnhub' ), (string) $hint['by'], self::d( substr( (string) $hint['at'], 0, 10 ) ), (string) $hint['key'] ) ),
				esc_html( VH_Assess_Repo::outcome_label( (string) $hint['outcome'] ) ),
				esc_html( vh_trim( (string) $hint['text'], 300 ) )
			);
			if ( $offered ) {
				echo ' ' . esc_html__( 'The decision fields below are filled in from it. Check them, then save.', 'vulnhub' );
			}
			echo '</div>';
		}
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-assess__grid">
			<?php wp_nonce_field( self::ACTION_EXC_SAVE ); ?>
			<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_EXC_SAVE ); ?>">
			<input type="hidden" name="id" value="<?php echo esc_attr( (string) $id ); ?>">

			<fieldset class="vh-assess__set">
				<legend><?php esc_html_e( 'Request', 'vulnhub' ); ?></legend>
				<label class="vh-assess__wide"><?php esc_html_e( 'What is being excepted', 'vulnhub' ); ?>
					<input type="text" name="title" required maxlength="250" value="<?php echo esc_attr( $row['title'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Reason', 'vulnhub' ); ?>
					<select name="reason">
						<?php foreach ( $E::reasons() as $k => $l ) : ?>
							<option value="<?php echo esc_attr( (string) $k ); ?>" <?php selected( $row['reason'], (string) $k ); ?>><?php echo esc_html( (string) $l ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<label><?php esc_html_e( 'Jira tickets', 'vulnhub' ); ?>
					<input type="text" name="jira_key" maxlength="64" value="<?php echo esc_attr( $row['jira_key'] ); ?>" placeholder="<?php esc_attr_e( 'KEY-123', 'vulnhub' ); ?>">
				</label>
				<label><?php esc_html_e( 'Requested by', 'vulnhub' ); ?>
					<input type="text" name="requested_by_name" maxlength="190" value="<?php echo esc_attr( $row['requested_by_name'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Requested on', 'vulnhub' ); ?>
					<input type="date" name="requested_at" value="<?php echo esc_attr( $row['requested_at'] ); ?>">
				</label>
				<label class="vh-assess__wide"><?php esc_html_e( 'Justification (at least 20 characters)', 'vulnhub' ); ?>
					<textarea name="justification" rows="4" required minlength="20"><?php echo esc_textarea( $row['justification'] ); ?></textarea>
				</label>
				<label class="vh-assess__wide"><?php esc_html_e( 'Compensating controls', 'vulnhub' ); ?>
					<textarea name="compensating_controls" rows="2"><?php echo esc_textarea( $row['compensating_controls'] ); ?></textarea>
				</label>
			</fieldset>

			<fieldset class="vh-assess__set">
				<legend><?php esc_html_e( 'Decision', 'vulnhub' ); ?></legend>
				<label><?php esc_html_e( 'Status', 'vulnhub' ); ?>
					<select name="status">
						<?php foreach ( $E::statuses() as $k => $l ) : ?>
							<option value="<?php echo esc_attr( (string) $k ); ?>" <?php selected( $row['status'], (string) $k ); ?>><?php echo esc_html( (string) $l ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<label><?php esc_html_e( 'Decided by', 'vulnhub' ); ?>
					<input type="text" name="approver_name" maxlength="190" list="vh-assess-approvers" value="<?php echo esc_attr( $row['approver_name'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Decided on', 'vulnhub' ); ?>
					<input type="date" name="decided_at" value="<?php echo esc_attr( $row['decided_at'] ); ?>">
				</label>
				<label class="vh-assess__wide"><?php esc_html_e( 'Decision and conditions, as the approver wrote them', 'vulnhub' ); ?>
					<textarea name="decision_note" rows="3" maxlength="900"><?php echo esc_textarea( $row['decision_note'] ); ?></textarea>
				</label>
				<label><?php esc_html_e( 'Review by', 'vulnhub' ); ?>
					<input type="date" name="review_at" value="<?php echo esc_attr( $row['review_at'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Expires', 'vulnhub' ); ?>
					<input type="date" name="expires_at" value="<?php echo esc_attr( $row['expires_at'] ); ?>">
				</label>
				<label><?php esc_html_e( 'Withdrawn or revoked on', 'vulnhub' ); ?>
					<input type="date" name="revoked_at" value="<?php echo esc_attr( $row['revoked_at'] ); ?>">
				</label>
			</fieldset>

			<datalist id="vh-assess-approvers"><?php foreach ( $people['approvers'] as $p ) { printf( '<option value="%s">', esc_attr( $p ) ); } ?></datalist>

			<div class="vh-assess__formbar">
				<button class="vh-btn vh-btn--primary" type="submit"><?php esc_html_e( 'Save to the Exception register', 'vulnhub' ); ?></button>
				<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( $back ); ?>"><?php esc_html_e( 'Cancel', 'vulnhub' ); ?></a>
			</div>
		</form>
		<?php
		echo '</div>';
	}

	public static function handle_exc_save(): void {
		self::guard( self::ACTION_EXC_SAVE );

		if ( ! self::core_exceptions() ) {
			self::back( array( 'vh_msg' => 'invalid' ) );
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- checked in guard().
		$id   = isset( $_POST['id'] ) ? absint( wp_unslash( $_POST['id'] ) ) : 0;
		$data = array();
		foreach ( array( 'title', 'reason', 'justification', 'compensating_controls', 'status', 'requested_by_name', 'approver_name', 'decision_note', 'jira_key', 'expires_at', 'review_at', 'requested_at', 'decided_at', 'revoked_at' ) as $f ) {
			$data[ $f ] = isset( $_POST[ $f ] ) ? (string) wp_unslash( $_POST[ $f ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Exceptions::record() sanitises.
		}
		// phpcs:enable

		$res = \VulnHub\Core\Exceptions::record( $data, $id );

		if ( empty( $res['ok'] ) ) {
			$ref = wp_get_referer();
			$url = $ref && str_starts_with( (string) $ref, home_url() ) ? remove_query_arg( array( 'vh_msg', 'vh_err' ), (string) $ref ) : self::url( array( 'exc' => $id ?: 'new' ) );
			wp_safe_redirect( add_query_arg( 'vh_err', rawurlencode( (string) $res['message'] ), $url ) );
			exit;
		}

		wp_safe_redirect( self::exceptions_url( array( 'exception' => (int) $res['id'] ) ) );
		exit;
	}

	/* ------------------------------------------------------------- CSV */

	private static function csv_url( string $tab, array $f ): string {
		return wp_nonce_url(
			add_query_arg(
				array_filter(
					array(
						'action'  => self::ACTION_CSV,
						'tab'     => $tab,
						'src'     => $f['source'],
						'outcome' => $f['outcome'],
						'group'   => $f['group'],
						'aq'      => $f['q'],
						'due'     => $f['due'],
					)
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION_CSV
		);
	}

	/**
	 * The same rows the table shows, under the same filters.
	 */
	public static function handle_csv(): void {
		if ( ! is_user_logged_in() || ! current_user_can( \VulnHub\Core\Caps::VIEW ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_CSV );

		$tab  = self::tab();
		$tab  = 'inbox' === $tab ? 'supplier' : $tab;
		$rows = VH_Assess_Repo::rows( self::filters( $tab ) );

		vulnhub()->logger->audit( 'assessment.export', sprintf( 'Exported %d %s rows', count( $rows ), $tab ), 'assessment', '', array() );

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . ( 'exception' === $tab ? 'security-exceptions' : 'supplier-assessments' ) . '-' . wp_date( 'Y-m-d' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' );
		fwrite( $out, "\xEF\xBB\xBF" ); // Excel reads UTF-8 only with a BOM.
		fputcsv( $out, array( 'exception' === $tab ? 'Exception' : 'Supplier', 'Source', 'Inherited from', 'Raised on', 'Period', 'Requested by', 'Reviewed by', 'Reviewed on', 'Review summary', 'Outcome', 'Decided by', 'Decided on', 'Conditions', 'Look again by', 'No longer in force from', 'Jira tickets', 'Jira links', 'Notes' ) );

		foreach ( $rows as $r ) {
			fputcsv(
				$out,
				array_map(
					array( __CLASS__, 'csv_safe' ),
					array(
						$r['subject'],
						'inherited' === $r['source'] ? 'Inherited' : 'Assessed by us',
						$r['origin'],
						$r['raised_on'],
						$r['period_text'],
						$r['requested_by'],
						$r['reviewer'],
						$r['reviewed_on'],
						$r['review_summary'],
						VH_Assess_Repo::outcome_label( (string) $r['outcome'] ),
						$r['approver'],
						$r['decided_on'],
						$r['conditions'],
						$r['review_due'],
						$r['ended_on'],
						implode( ', ', $r['keys'] ),
						implode( ' ', array_filter( array_map( array( 'VH_Assess_Jira', 'browse_url' ), $r['keys'] ) ) ),
						$r['notes'],
					)
				)
			);
		}

		fclose( $out );
		exit;
	}

	/** Keep a spreadsheet from running a cell as a formula. */
	public static function csv_safe( $v ): string {
		$v = (string) $v;

		return '' !== $v && in_array( $v[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ? "'" . $v : $v;
	}

	/* =================================================================
	 * Cells
	 * ============================================================== */

	private static function pill( string $outcome ): string {
		$o    = VH_Assess_Repo::outcomes()[ $outcome ] ?? array( 'label' => $outcome, 'tone' => 'muted' );
		$tone = (string) $o['tone'];

		return sprintf( '<span class="vh-assess__pill vh-assess__pill--%s">%s</span>', esc_attr( $tone ), esc_html( (string) $o['label'] ) );
	}

	/** @param array<int,string> $keys */
	private static function keys_cell( array $keys ): string {
		if ( ! $keys ) {
			return '<span class="vh-meta">' . esc_html__( 'No ticket', 'vulnhub' ) . '</span>';
		}

		$out = '<ul class="vh-assess__keys">';
		foreach ( $keys as $k ) {
			$jira   = VH_Assess_Jira::browse_url( $k );
			$portal = VH_Assess_Jira::portal_url( $k );
			$out   .= '<li>';
			$out   .= $jira
				? sprintf( '<a class="vh-mono" href="%s" target="_blank" rel="noopener noreferrer" title="%s">%s<span aria-hidden="true"> ↗</span></a>', esc_url( $jira ), esc_attr__( 'Open in Jira', 'vulnhub' ), esc_html( $k ) )
				: sprintf( '<span class="vh-mono">%s</span>', esc_html( $k ) );
			if ( $portal ) {
				$out .= sprintf( ' <a class="vh-meta vh-assess__here" href="%s">%s</a>', esc_url( $portal ), esc_html__( 'open here', 'vulnhub' ) );
			}
			$out .= '</li>';
		}

		return $out . '</ul>';
	}

	/** @param array<string,mixed> $r */
	private static function due_cell( array $r ): string {
		if ( $r['ended_on'] ) {
			return '<span class="vh-meta">' . esc_html( sprintf( /* translators: %s: date */ __( 'No longer in force from %s', 'vulnhub' ), self::d( (string) $r['ended_on'] ) ) ) . '</span>';
		}
		if ( ! $r['review_due'] ) {
			return '<span class="vh-meta">—</span>';
		}

		$today = gmdate( 'Y-m-d' );
		$cls   = $r['review_due'] < $today ? 'bad' : ( $r['review_due'] <= gmdate( 'Y-m-d', time() + 60 * DAY_IN_SECONDS ) ? 'warn' : 'ok' );
		$word  = 'bad' === $cls ? __( 'passed', 'vulnhub' ) : ( 'warn' === $cls ? __( 'soon', 'vulnhub' ) : '' );

		return sprintf( '<span class="vh-assess__due--%s">%s</span>%s', esc_attr( $cls ), esc_html( self::d( (string) $r['review_due'] ) ), '' !== $word ? '<span class="vh-meta">' . esc_html( $word ) . '</span>' : '' );
	}

	/** @param array<string,string> $h */
	private static function hint_line( array $h, string $record_url ): void {
		echo '<div class="vh-assess__hint">';
		printf(
			'<span>%s</span> ',
			esc_html( sprintf( /* translators: 1: person, 2: date, 3: outcome */ __( 'In Jira: %1$s, %2$s — reads as %3$s.', 'vulnhub' ), $h['by'], self::d( substr( $h['at'], 0, 10 ) ), mb_strtolower( VH_Assess_Repo::outcome_label( $h['outcome'] ) ) ) )
		);
		if ( '' !== $record_url ) {
			printf( '<a href="%s">%s</a>', esc_url( $record_url ), esc_html__( 'Record it', 'vulnhub' ) );
		}
		echo '</div>';
	}

	private static function d( string $ymd ): string {
		$ts = strtotime( $ymd . ' 00:00:00 UTC' );

		return $ts ? wp_date( 'j M Y', $ts, new \DateTimeZone( 'UTC' ) ) : $ymd;
	}

	private static function months_since( string $ymd ): int {
		$ts = strtotime( $ymd . ' 00:00:00 UTC' );

		return $ts ? max( 0, (int) round( ( time() - $ts ) / ( 30.44 * DAY_IN_SECONDS ) ) ) : 0;
	}
}

