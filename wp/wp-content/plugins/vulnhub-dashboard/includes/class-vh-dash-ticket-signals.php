<?php
/**
 * What on the Tickets list is waiting on *you*.
 *
 * Four signals, each worked out for whoever is looking, on open tickets only:
 *
 * - **Mentioned you.** Somebody @mentioned your Jira account, or wrote your
 *   name, in a comment and you have not commented since.
 * - **Your reply.** Somebody has mentioned you (as above) since you last
 *   commented. Being the newest comment on a ticket you raised is not enough:
 *   routing notes and status updates are not asking you anything. Your next
 *   comment clears it.
 * - **Assigned to you.** The Jira assignee is your account.
 * - **Chase.** Past its due date *and* you have already sent the current
 *   list. There is nothing left on your side, so the ticket is the other
 *   team's to finish and yours to chase; this is the one that glows. Overdue
 *   without a fresh list is marked too, but quietly: sending the list is the
 *   next step, not chasing.
 *
 * Nothing here calls Jira. The comments were summarised when they were last
 * read (VulnHub_Jira_Connector::conversation()), and which account is "you"
 * is matched once and remembered (jira_identity(): portal admins only, by
 * email and name together).
 *
 * See docs/TICKETS.md, "Waiting on you".
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Tickets;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Dash_Ticket_Signals {

	/** The values `tfor` takes on the Tickets list, in the order they are shown. */
	public const FILTERS = array( 'mention', 'reply', 'assigned', 'chase', 'overdue' );

	/** @var array<int,array<string,mixed>>|null Open tickets' signals, id => flags. */
	private static ?array $open = null;

	/** @var array{id:string,name:string}|null */
	private static ?array $me = null;

	private static int $me_for = -1;

	/** @var array<string,bool>|null Boilerplate comments, "ticket|at|author" => true. */
	private static ?array $boiler = null;

	public static function init(): void {
		add_filter( 'vulnhub_notifications', array( __CLASS__, 'notify' ) );
	}

	/**
	 * The viewer's Jira account id, or '' when it cannot be told.
	 */
	public static function me(): string {
		return self::identity()['id'];
	}

	/**
	 * @return array{id:string,name:string}
	 */
	private static function identity(): array {
		if ( null === self::$me || get_current_user_id() !== self::$me_for ) {
			$jira         = function_exists( 'vulnhub_jira_connector' ) ? vulnhub_jira_connector() : null;
			self::$me     = $jira ? $jira->jira_identity( get_current_user_id() ) : array( 'id' => '', 'name' => '' );
			self::$me_for = get_current_user_id();
			self::$open   = null;
		}

		return self::$me;
	}

	/**
	 * Whether a piece of text names somebody: their full name, or their first
	 * name as a word of its own ("Hi Sam," -- not "Samuel"). A relayed comment
	 * carries no @mention, only the words, so the words are read too.
	 */
	private static function names( string $text, string $name ): bool {
		$name = trim( $name );

		if ( '' === $name || '' === trim( $text ) ) {
			return false;
		}

		$first = (string) strtok( $name, ' ' );
		$alts  = array( preg_quote( $name, '/' ) );

		if ( mb_strlen( $first ) >= 3 && $first !== $name ) {
			$alts[] = preg_quote( $first, '/' );
		}

		return (bool) preg_match( '/(?<![\\p{L}\\p{N}])(?:' . implode( '|', $alts ) . ')(?![\\p{L}\\p{N}])/iu', $text );
	}

	public static function label( string $for ): string {
		return array(
			'mention'  => __( 'Mentioned you', 'vulnhub' ),
			'reply'    => __( 'Waiting on your reply', 'vulnhub' ),
			'assigned' => __( 'Assigned to you', 'vulnhub' ),
			'chase'    => __( 'Overdue, current list sent', 'vulnhub' ),
			'overdue'  => __( 'Overdue', 'vulnhub' ),
		)[ $for ] ?? $for;
	}

	/**
	 * Signals for a set of ticket rows, id => flags.
	 *
	 * @param array<int,array<string,mixed>> $rows Ticket rows with payload_json.
	 * @return array<int,array<string,mixed>>
	 */
	public static function for_rows( array $rows ): array {
		$sent = self::sent_from_audit( $rows );
		$out  = array();

		foreach ( $rows as $t ) {
			$out[ (int) $t['id'] ] = self::flags( $t, self::me(), $sent[ (int) $t['id'] ] ?? '' );
		}

		return $out;
	}

	/**
	 * Every open ticket's signals, id => flags. One query, once a request.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function open(): array {
		self::identity(); // Drops the cache when the viewer has changed.

		if ( null === self::$open ) {
			global $wpdb;

			$rows = (array) $wpdb->get_results(
				'SELECT id, external_key, summary, status_category, assignee_id, created_by, payload_json FROM '
				. vh_table( 'tickets' ) . " WHERE status_category <> 'done'", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
				ARRAY_A
			);

			self::$open = self::for_rows( $rows );
		}

		return self::$open;
	}

	/**
	 * The ids a `tfor` filter keeps, or null for no such filter.
	 *
	 * @return int[]|null
	 */
	public static function ids_for( string $for ): ?array {
		if ( ! in_array( $for, self::FILTERS, true ) ) {
			return null;
		}

		return array_keys( array_filter( self::open(), static fn( array $f ): bool => ! empty( $f[ $for ] ) ) );
	}

	/**
	 * How many open tickets carry each signal.
	 *
	 * @return array<string,int>
	 */
	public static function counts(): array {
		$counts = array_fill_keys( self::FILTERS, 0 );

		foreach ( self::open() as $f ) {
			foreach ( self::FILTERS as $k ) {
				$counts[ $k ] += empty( $f[ $k ] ) ? 0 : 1;
			}
		}

		return $counts;
	}

	/**
	 * The signals on one ticket, for one viewer.
	 *
	 * @param array<string,mixed> $t         Ticket row.
	 * @param string              $me        Viewer's Jira account id, or ''.
	 * @param string              $sent_at   Fallback "list sent" time (UTC) from the audit.
	 * @return array<string,mixed>
	 */
	public static function flags( array $t, string $me, string $sent_at = '' ): array {
		$f = array(
			'mention'  => false,
			'reply'    => false,
			'assigned' => false,
			'overdue'  => false,
			'chase'    => false,
		);

		if ( 'done' === (string) ( $t['status_category'] ?? '' ) ) {
			return $f;
		}

		/* ---- the SLA: overdue from the end of the due day, site time ---- */
		$due = Tickets::due_date( $t );

		if ( '' !== $due ) {
			$end = DateTimeImmutable::createFromFormat( 'Y-m-d H:i:s', $due . ' 23:59:59', wp_timezone() );

			if ( $end && time() > $end->getTimestamp() ) {
				$f['overdue']      = true;
				$f['overdue_days'] = max( 1, (int) ceil( ( time() - $end->getTimestamp() ) / DAY_IN_SECONDS ) );
			}
		}

		$sent = Tickets::list_sent( $t );
		$sent = $sent ? (string) $sent['at'] : $sent_at;

		if ( '' !== $sent ) {
			$f['sent_at'] = $sent;
		}

		$f['chase'] = $f['overdue'] && '' !== $sent;

		if ( '' === $me ) {
			return $f;
		}

		/* ---- the conversation, read for this viewer ---- */
		$f['assigned'] = $me === (string) ( $t['assignee_id'] ?? '' );

		$conv = Tickets::conversation( $t ) ?? array();
		$mine = '';

		foreach ( (array) ( $conv['last_by'] ?? array() ) as $by ) {
			if ( $me === (string) ( $by['id'] ?? '' ) ) {
				$mine = (string) ( $by['at'] ?? '' );
				break;
			}
		}

		$my_name       = self::identity()['name'];
		$said          = isset( $conv['said'] ) ? (array) $conv['said'] : null;

		// A desk macro is not somebody talking to you, whoever it greets.
		if ( null !== $said ) {
			$boiler = self::boilerplate();
			$said   = array_values(
				array_filter(
					$said,
					static fn( array $c ): bool => ! isset( $boiler[ self::said_key( (int) ( $t['id'] ?? 0 ), $c ) ] )
				)
			);
		}
		$is_me         = static fn( array $c ): bool => $me === (string) ( $c['by_id'] ?? '' )
			|| ( '' !== $my_name && mb_strtolower( trim( (string) ( $c['by'] ?? '' ) ) ) === mb_strtolower( $my_name ) );

		// A reply you made in the other system, relayed, is still you replying.
		foreach ( (array) $said as $c ) {
			if ( $is_me( $c ) && (string) ( $c['at'] ?? '' ) > $mine ) {
				$mine = (string) $c['at'];
			}
		}

		foreach ( (array) ( $conv['mentions'] ?? array() ) as $m ) {
			if ( $me !== (string) ( $m['id'] ?? '' ) ) {
				continue;
			}

			// Newest first, so the first one found is the latest. Answered
			// once you have commented after it; mentioning yourself is not
			// somebody asking.
			if ( $me !== (string) ( $m['by_id'] ?? '' ) && (string) ( $m['at'] ?? '' ) > $mine ) {
				$f['mention']    = true;
				$f['mention_by'] = (string) ( $m['by'] ?? '' );
				$f['mention_at'] = (string) ( $m['at'] ?? '' );
			}
			break;
		}

		// Your name in the words of a comment, which is all a relayed comment
		// can carry. Newest first; only one written since you last spoke.
		foreach ( (array) $said as $c ) {
			if ( $is_me( $c ) || ! self::names( (string) ( $c['text'] ?? '' ), $my_name ) ) {
				continue;
			}

			if ( (string) ( $c['at'] ?? '' ) > $mine && ( empty( $f['mention'] ) || (string) $c['at'] > (string) $f['mention_at'] ) ) {
				$f['mention']    = true;
				$f['mention_by'] = (string) ( $c['by'] ?? '' );
				$f['mention_at'] = (string) ( $c['at'] ?? '' );
			}
			break;
		}

		/*
		 * Your reply is owed only when somebody has asked for you: an
		 * @mention or your name in a comment written since you last commented
		 * (both worked out above). The newest comment merely being somebody
		 * else's is not enough -- routing notes, status updates and relayed
		 * work logs on a ticket you raised are not waiting on you. Commenting
		 * after the mention clears it.
		 */
		if ( ! empty( $f['mention'] ) ) {
			$f['reply']    = true;
			$f['reply_by'] = (string) $f['mention_by'];
			$f['reply_at'] = (string) $f['mention_at'];
		}

		return $f;
	}

	/**
	 * Comments that are a template rather than a person: the same words, bar
	 * names and the greeting, posted on more than one ticket. A service desk
	 * answers every new request with the same acknowledgement ("Hi <name>,
	 * thanks for raising this, the team are on it") and routes with the same
	 * note ("Could you help <name> with their request"). Each names you and
	 * each is the newest comment for a while; neither is waiting on you.
	 *
	 * Judged by word overlap (at least 80% of the words shared, six words or
	 * more), because a macro's wording drifts ("their request" / "their
	 * issue"). The price: an identical human note posted on several tickets
	 * is taken for a broadcast, which is usually what it is.
	 *
	 * @return array<string,bool>
	 */
	private static function boilerplate(): array {
		if ( null !== self::$boiler ) {
			return self::$boiler;
		}

		global $wpdb;

		$rows  = (array) $wpdb->get_results(
			'SELECT id, payload_json FROM ' . vh_table( 'tickets' ) . " WHERE LOCATE('\"said\"', payload_json) > 0", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);
		$items = array();

		foreach ( $rows as $r ) {
			$conv = Tickets::conversation( $r );

			foreach ( (array) ( $conv['said'] ?? array() ) as $c ) {
				$words = self::words( (string) ( $c['text'] ?? '' ), (string) ( $c['by'] ?? '' ) );

				if ( count( $words ) >= 6 ) {
					$items[] = array( 'ticket' => (int) $r['id'], 'key' => self::said_key( (int) $r['id'], $c ), 'words' => $words );
				}
			}
		}

		self::$boiler = array();
		$n            = count( $items );

		for ( $i = 0; $i < $n; $i++ ) {
			for ( $j = $i + 1; $j < $n; $j++ ) {
				if ( $items[ $i ]['ticket'] === $items[ $j ]['ticket'] ) {
					continue;
				}

				$a     = $items[ $i ]['words'];
				$b     = $items[ $j ]['words'];
				$share = count( array_intersect_key( $a, $b ) ) / max( 1, count( $a + $b ) );

				if ( $share >= 0.8 ) {
					self::$boiler[ $items[ $i ]['key'] ] = true;
					self::$boiler[ $items[ $j ]['key'] ] = true;
				}
			}
		}

		return self::$boiler;
	}

	/**
	 * A comment's words as a set, without the relay's header line, the
	 * greeting, or any name -- the parts a template fills in.
	 *
	 * @return array<string,bool>
	 */
	private static function words( string $text, string $by ): array {
		$text = (string) preg_replace( '/^\\s*[^\\n]{2,60}? in [^\\n]{1,40}? commented:\\s*/u', '', $text );
		$text = (string) preg_replace( '/^\\s*(?:hi|hello|hey|dear|good (?:morning|afternoon|evening))\\b[^,\\n]*[,\\n]/iu', '', $text );
		$name = self::identity()['name'];

		foreach ( array_filter( array( $name, $by ) ) as $n ) {
			$text = str_ireplace( $n, ' ', $text );
		}

		$out = array();

		foreach ( preg_split( '/[^\\p{L}\\p{N}]+/u', mb_strtolower( $text ), -1, PREG_SPLIT_NO_EMPTY ) as $w ) {
			$out[ $w ] = true;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $c One `said` entry.
	 */
	private static function said_key( int $ticket_id, array $c ): string {
		return $ticket_id . '|' . (string) ( $c['at'] ?? '' ) . '|' . (string) ( $c['by_id'] ?? '' );
	}

	/**
	 * When each ticket last had an updated list sent, from the audit, for
	 * tickets whose payload does not say -- lists sent before the payload
	 * recorded it.
	 *
	 * @param array<int,array<string,mixed>> $rows Ticket rows.
	 * @return array<int,string> id => UTC time.
	 */
	private static function sent_from_audit( array $rows ): array {
		$ids = array();

		foreach ( $rows as $t ) {
			if ( ! Tickets::list_sent( $t ) ) {
				$ids[] = (int) $t['id'];
			}
		}

		if ( ! $ids ) {
			return array();
		}

		global $wpdb;

		$in   = implode( ',', array_map( 'intval', $ids ) );
		$rows = (array) $wpdb->get_results(
			'SELECT object_id, MAX(logged_at) AS at FROM ' . vh_table( 'audit' )
			. " WHERE action = 'ticket.attachment_refreshed' AND object_type = 'ticket' AND object_id IN ('" . str_replace( ',', "','", $in ) . "')
			GROUP BY object_id", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- ints only.
			ARRAY_A
		);
		$out  = array();

		foreach ( $rows as $r ) {
			$out[ (int) $r['object_id'] ] = (string) $r['at'];
		}

		return $out;
	}

	/* =================================================================
	 * Drawing
	 * ============================================================== */

	/**
	 * Row classes for a ticket's signals.
	 *
	 * @param array<string,mixed> $f Flags.
	 */
	public static function row_class( array $f ): string {
		$c = array();

		if ( ! empty( $f['chase'] ) ) {
			$c[] = 'vh-trow--chase';
		} elseif ( ! empty( $f['overdue'] ) ) {
			$c[] = 'vh-trow--overdue';
		}

		foreach ( array( 'mention', 'reply', 'assigned' ) as $k ) {
			if ( ! empty( $f[ $k ] ) ) {
				$c[] = 'vh-trow--you vh-trow--' . $k;
				break; // The strongest signal colours the edge.
			}
		}

		return implode( ' ', $c );
	}

	/**
	 * The bell beside a ticket's key, when something on it is yours.
	 *
	 * @param array<string,mixed> $f Flags.
	 */
	public static function bell( array $f ): string {
		$why = array();

		if ( ! empty( $f['mention'] ) ) {
			/* translators: 1: person, 2: time ago. */
			$why[] = sprintf( __( '%1$s mentioned you %2$s', 'vulnhub' ), $f['mention_by'], vh_ago( $f['mention_at'] ) );
		}
		if ( ! empty( $f['reply'] ) && empty( $f['mention'] ) ) {
			/* translators: 1: person, 2: time ago. */
			$why[] = sprintf( __( '%1$s mentioned you %2$s; the next reply is yours', 'vulnhub' ), $f['reply_by'], vh_ago( $f['reply_at'] ) );
		}
		if ( ! empty( $f['assigned'] ) ) {
			$why[] = __( 'assigned to you in Jira', 'vulnhub' );
		}

		if ( ! $why ) {
			return '';
		}

		$tone = ! empty( $f['mention'] ) ? 'mention' : ( ! empty( $f['reply'] ) ? 'reply' : 'assigned' );
		$text = ucfirst( implode( '; ', $why ) ) . '.';

		return '<span class="vh-tbell vh-tbell--' . esc_attr( $tone ) . '" role="img" aria-label="' . esc_attr( $text ) . '" title="' . esc_attr( $text ) . '">'
			. '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 01-3.4 0" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
			. ( count( $why ) > 1 ? '<i>' . count( $why ) . '</i>' : '' )
			. '</span>';
	}

	/**
	 * The tags above a ticket's summary.
	 *
	 * @param array<string,mixed> $f Flags.
	 */
	public static function tags( array $f ): string {
		$out = '';

		if ( ! empty( $f['mention'] ) ) {
			$out .= self::tag(
				'mention',
				'<b aria-hidden="true">@</b>' . esc_html__( 'Mentioned you', 'vulnhub' ),
				/* translators: 1: person, 2: time ago. */
				sprintf( __( '%1$s mentioned you %2$s, and you have not commented since.', 'vulnhub' ), $f['mention_by'], vh_ago( $f['mention_at'] ) )
			);
		} elseif ( ! empty( $f['reply'] ) ) {
			$out .= self::tag(
				'reply',
				self::icon( 'M9 14L4 9l5-5M4 9h10a6 6 0 016 6v5' ) . esc_html__( 'Your reply', 'vulnhub' ),
				/* translators: 1: person, 2: time ago. */
				sprintf( __( '%1$s mentioned you %2$s, and you have not commented since.', 'vulnhub' ), $f['reply_by'], vh_ago( $f['reply_at'] ) )
			);
		}

		if ( ! empty( $f['assigned'] ) ) {
			$out .= self::tag(
				'assigned',
				self::icon( 'M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8z' ) . esc_html__( 'Yours', 'vulnhub' ),
				__( 'Assigned to you in Jira.', 'vulnhub' )
			);
		}

		if ( ! empty( $f['overdue'] ) ) {
			$days = (int) ( $f['overdue_days'] ?? 1 );
			/* translators: %s: number of days. */
			$late = sprintf( _n( '%s day over', '%s days over', $days, 'vulnhub' ), number_format_i18n( $days ) );

			if ( ! empty( $f['chase'] ) ) {
				$out .= self::tag(
					'chase',
					self::icon( 'M12 8v4l3 2M12 22a10 10 0 100-20 10 10 0 000 20z' ) . esc_html( $late ),
					/* translators: %s: time ago. */
					sprintf( __( 'Past its due date. You sent the current list %s, so nothing is waiting on you: chase the team working it.', 'vulnhub' ), vh_ago( (string) $f['sent_at'] ) )
				);
				/* translators: %s: time ago. */
				$out .= self::tag( 'sent', self::icon( 'M21.4 11.6l-9.2 9.2a6 6 0 01-8.5-8.5l9.2-9.2a4 4 0 015.7 5.7l-9.2 9.2a2 2 0 01-2.8-2.8l8.5-8.5' ) . esc_html( sprintf( __( 'list sent %s', 'vulnhub' ), vh_ago( (string) $f['sent_at'] ) ) ), __( 'When the updated list last went to Jira from here.', 'vulnhub' ) );
			} else {
				$out .= self::tag(
					'overdue',
					self::icon( 'M12 8v4l3 2M12 22a10 10 0 100-20 10 10 0 000 20z' ) . esc_html( $late ),
					__( 'Past its due date, and no updated list has been sent from here. Sending one (on the ticket page) is the next step before chasing.', 'vulnhub' )
				);
			}
		}

		return '' === $out ? '' : '<span class="vh-ttags">' . $out . '</span>';
	}

	private static function tag( string $tone, string $inner, string $title ): string {
		return '<span class="vh-ttag vh-ttag--' . esc_attr( $tone ) . '" title="' . esc_attr( $title ) . '">' . $inner . '</span>';
	}

	private static function icon( string $d ): string {
		return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="' . esc_attr( $d ) . '" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
	}

	/**
	 * The "For you" strip above the list: one chip per signal, each a filter.
	 *
	 * @param string $active The `tfor` in force, or ''.
	 * @param callable(array<string,string>):string $url Builds a list URL.
	 */
	public static function strip( string $active, callable $url ): void {
		$counts = self::counts();
		$me     = self::me();
		$total  = $counts['mention'] + $counts['reply'] + $counts['assigned'];
		?>
		<section class="vh-foryou<?php echo $total > 0 ? ' has-yours' : ''; ?>" aria-label="<?php esc_attr_e( 'Tickets waiting on you', 'vulnhub' ); ?>">
			<span class="vh-foryou__bell" aria-hidden="true">
				<svg viewBox="0 0 24 24"><path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 01-3.4 0" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
				<?php if ( $total > 0 ) : ?><i><?php echo esc_html( $total > 99 ? '99+' : (string) $total ); ?></i><?php endif; ?>
			</span>
			<span class="vh-foryou__h"><?php esc_html_e( 'For you', 'vulnhub' ); ?></span>
			<?php
			foreach ( self::FILTERS as $k ) {
				if ( '' === $me && in_array( $k, array( 'mention', 'reply', 'assigned' ), true ) ) {
					continue;
				}

				$on = $active === $k;
				printf(
					'<a class="vh-foryou__chip vh-foryou__chip--%1$s%2$s%3$s" href="%4$s"%5$s><span>%6$s</span><b>%7$s</b></a>',
					esc_attr( $k ),
					$on ? ' is-active' : '',
					0 === $counts[ $k ] ? ' is-zero' : '',
					esc_url( $on ? $url( array() ) : $url( array( 'tfor' => $k ) ) ),
					$on ? ' aria-current="true"' : '',
					esc_html( self::label( $k ) ),
					esc_html( number_format_i18n( $counts[ $k ] ) )
				);
			}
			?>
			<?php if ( '' === $me ) : ?>
				<span class="vh-meta vh-foryou__note">
					<?php
					/* translators: %s: email address. */
					echo esc_html( sprintf( __( 'No Jira account matches %s, so mentions, replies and assignments cannot be picked out for you.', 'vulnhub' ), wp_get_current_user()->user_email ) );
					?>
				</span>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Add the viewer's ticket signals to the topbar bell.
	 *
	 * @param array<int,array<string,mixed>> $items Notices so far.
	 * @return array<int,array<string,mixed>>
	 */
	public static function notify( array $items ): array {
		if ( ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return $items;
		}

		$open   = self::open();
		$counts = self::counts();
		$url    = static fn( string $for ): string => VulnHub_Dash_Portal::portal_url( 'tickets', array( 'tfor' => $for ) ) . '#vh-ticket-list';
		$keys   = static function ( string $for ) use ( $open ): string {
			global $wpdb;

			$ids = array_keys( array_filter( $open, static fn( array $f ): bool => ! empty( $f[ $for ] ) ) );
			$ids = array_slice( array_map( 'intval', $ids ), 0, 4 );

			if ( ! $ids ) {
				return '';
			}

			return implode( ', ', (array) $wpdb->get_col( 'SELECT external_key FROM ' . vh_table( 'tickets' ) . ' WHERE id IN (' . implode( ',', $ids ) . ')' ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- ints only.
		};

		if ( $counts['mention'] > 0 ) {
			$latest = null;

			foreach ( $open as $f ) {
				if ( ! empty( $f['mention'] ) && ( ! $latest || $f['mention_at'] > $latest['mention_at'] ) ) {
					$latest = $f;
				}
			}

			$items[] = array(
				'id'       => 'tickets-mention',
				'severity' => 'crit',
				'count'    => $counts['mention'],
				'title'    => __( 'You were mentioned on a ticket', 'vulnhub' ),
				'body'     => sprintf(
					/* translators: 1: person, 2: time ago, 3: ticket keys. */
					__( '%1$s mentioned you %2$s. Not answered yet: %3$s.', 'vulnhub' ),
					(string) $latest['mention_by'],
					vh_ago( (string) $latest['mention_at'] ),
					$keys( 'mention' )
				),
				'url'      => $url( 'mention' ),
			);
		}

		if ( $counts['reply'] > 0 ) {
			$items[] = array(
				'id'       => 'tickets-reply',
				'severity' => 'warn',
				'count'    => $counts['reply'],
				'title'    => __( 'Tickets waiting on your reply', 'vulnhub' ),
				/* translators: %s: ticket keys. */
				'body'     => sprintf( __( 'Somebody mentioned you and you have not replied: %s.', 'vulnhub' ), $keys( 'reply' ) ),
				'url'      => $url( 'reply' ),
			);
		}

		if ( $counts['chase'] > 0 ) {
			$items[] = array(
				'id'       => 'tickets-chase',
				'severity' => 'crit',
				'count'    => $counts['chase'],
				'title'    => __( 'Overdue, and they have the current list', 'vulnhub' ),
				/* translators: %s: ticket keys. */
				'body'     => sprintf( __( 'Past their due date after you sent the updated list. Worth chasing: %s.', 'vulnhub' ), $keys( 'chase' ) ),
				'url'      => $url( 'chase' ),
			);
		}

		if ( $counts['assigned'] > 0 ) {
			$items[] = array(
				'id'       => 'tickets-assigned',
				'severity' => 'info',
				'count'    => $counts['assigned'],
				'title'    => __( 'Tickets assigned to you', 'vulnhub' ),
				/* translators: %s: ticket keys. */
				'body'     => sprintf( __( 'Open, with you as the Jira assignee: %s.', 'vulnhub' ), $keys( 'assigned' ) ),
				'url'      => $url( 'assigned' ),
			);
		}

		return $items;
	}
}
