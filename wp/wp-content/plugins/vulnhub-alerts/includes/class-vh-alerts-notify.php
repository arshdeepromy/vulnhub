<?php
/**
 * Telling somebody, without becoming the thing they filter to a folder.
 *
 * Two channels on purpose. The nav badge is always accurate and costs nobody
 * anything. Mail is rationed: one digest a day, plus an immediate message only
 * when an exact match is either on CISA's exploited list or rated critical.
 * Everything else waits for the morning.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Notify {

	public const OPT = 'vulnhub_alerts_notify';

	public static function init(): void {
		add_action( 'vulnhub_alerts_polled', array( __CLASS__, 'after_poll' ) );
	}

	/** @return array<string,mixed> */
	public static function settings(): array {
		return wp_parse_args(
			(array) get_option( self::OPT, array() ),
			array(
				'digest'     => 1,
				'urgent'     => 1,
				'recipients' => '',
			)
		);
	}

	/** @return string[] */
	private static function recipients(): array {
		$settings = self::settings();
		$raw      = trim( (string) $settings['recipients'] );

		if ( '' === $raw ) {
			// Fall back to the site admin rather than silently sending
			// nothing -- a notification nobody configured is still better
			// than an alert nobody hears about.
			$raw = (string) get_option( 'admin_email', '' );
		}

		$out = array();

		foreach ( preg_split( '/[,\s]+/', $raw ) ?: array() as $address ) {
			if ( is_email( $address ) ) {
				$out[] = $address;
			}
		}

		return array_values( array_unique( $out ) );
	}

	public static function after_poll(): void {
		$settings = self::settings();

		if ( empty( $settings['urgent'] ) ) {
			return;
		}

		self::send_urgent();
	}

	/**
	 * The interrupt-worthy ones: exact match, untriaged, and either being
	 * exploited in the wild or rated critical. Each is mailed once.
	 */
	public static function send_urgent(): void {
		global $wpdb;

		$a = $wpdb->prefix . 'vulnhub_alerts';

		$rows = $wpdb->get_results(
			"SELECT * FROM {$a}
			  WHERE matched = 1
			    AND best_confidence = 'exact'
			    AND state = 'new'
			    AND notified_at IS NULL
			    AND (kev = 1 OR severity = 'critical')
			  ORDER BY kev DESC, cvss DESC
			  LIMIT 10",
			ARRAY_A
		);

		if ( ! $rows ) {
			return;
		}

		$to = self::recipients();

		foreach ( (array) $rows as $alert ) {
			if ( $to ) {
				wp_mail(
					$to,
					sprintf(
						/* translators: 1: site name, 2: advisory title */
						__( '[%1$s] Exploited advisory affects %2$s', 'vulnhub' ),
						get_bloginfo( 'name' ),
						vh_trim( (string) $alert['title'], 60 )
					),
					self::urgent_body( $alert ),
					array( 'Content-Type: text/plain; charset=UTF-8' )
				);
			}

			// Stamped whether or not mail was configured, so a missing mail
			// setup does not queue up a hundred messages for the day someone
			// finally configures it.
			$wpdb->update(
				$a,
				array( 'notified_at' => current_time( 'mysql', true ) ),
				array( 'id' => (int) $alert['id'] )
			);
		}
	}

	private static function urgent_body( array $alert ): string {
		$matches = VulnHub_Alerts_Repo::matches( (int) $alert['id'], 15 );
		$lines   = array();

		$lines[] = (string) $alert['title'];
		$lines[] = '';

		if ( (int) $alert['kev'] ) {
			$lines[] = __( 'This is reported as exploited in the wild.', 'vulnhub' );
		}

		$lines[] = sprintf(
			/* translators: 1: severity, 2: CVSS, 3: source */
			__( 'Severity: %1$s (CVSS %2$s) — from %3$s', 'vulnhub' ),
			(string) $alert['severity'],
			(string) $alert['cvss'],
			(string) $alert['source']
		);

		$cves = VulnHub_Alerts_Repo::cves( $alert );

		if ( $cves ) {
			$lines[] = sprintf(
				/* translators: %s: comma-separated CVE list */
				__( 'CVE: %s', 'vulnhub' ),
				implode( ', ', $cves )
			);
		}

		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %d: asset count */
			_n(
				'%d asset matches exactly:',
				'%d assets match exactly:',
				(int) $alert['asset_count'],
				'vulnhub'
			),
			(int) $alert['asset_count']
		);

		foreach ( $matches as $m ) {
			$lines[] = sprintf(
				'  - %s (%s %s)',
				(string) ( $m['hostname'] ?: __( 'unnamed asset', 'vulnhub' ) ),
				(string) $m['product'],
				(string) $m['installed_version']
			);
		}

		if ( count( $matches ) < (int) $alert['asset_count'] ) {
			$lines[] = sprintf(
				/* translators: %d: remaining asset count */
				__( '  ...and %d more.', 'vulnhub' ),
				(int) $alert['asset_count'] - count( $matches )
			);
		}

		$lines[] = '';
		$lines[] = __( 'Triage it here:', 'vulnhub' );
		$lines[] = VulnHub_Alerts_Page::url( array( 'alert' => (int) $alert['id'] ) );

		if ( ! empty( $alert['url'] ) ) {
			$lines[] = '';
			$lines[] = __( 'Advisory:', 'vulnhub' ) . ' ' . (string) $alert['url'];
		}

		return implode( "\n", $lines );
	}

	/**
	 * The morning digest: what arrived, what still needs a decision.
	 */
	public static function send_digest(): void {
		$settings = self::settings();

		if ( empty( $settings['digest'] ) ) {
			return;
		}

		global $wpdb;

		$a     = $wpdb->prefix . 'vulnhub_alerts';
		$since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );

		$new = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$a}
				  WHERE matched = 1 AND first_seen >= %s
				  ORDER BY FIELD(best_confidence,'exact','probable','possible'), kev DESC, cvss DESC
				  LIMIT 25",
				$since
			),
			ARRAY_A
		);

		$summary = VulnHub_Alerts_Repo::summary();

		// Nothing new and nothing outstanding is worth not sending. A daily
		// "no news" mail is how people learn to ignore the sender.
		if ( ! $new && 0 === (int) $summary['untriaged'] ) {
			return;
		}

		$to = self::recipients();

		if ( ! $to ) {
			return;
		}

		$lines = array();

		$lines[] = sprintf(
			/* translators: 1: new count, 2: untriaged count */
			__( '%1$d new advisories matched the estate in the last 24 hours. %2$d matched advisories are still waiting for a decision.', 'vulnhub' ),
			count( $new ),
			(int) $summary['untriaged']
		);
		$lines[] = '';

		foreach ( $new as $alert ) {
			$lines[] = sprintf(
				'[%s] %s',
				strtoupper( VulnHub_Alerts_Matcher::label( (string) $alert['best_confidence'] ) ),
				vh_trim( (string) $alert['title'], 90 )
			);
			$lines[] = sprintf(
				/* translators: 1: severity, 2: asset count, 3: source */
				__( '        %1$s · %2$d assets · %3$s', 'vulnhub' ),
				(string) $alert['severity'],
				(int) $alert['asset_count'],
				(string) $alert['source']
			);
		}

		$lines[] = '';
		$lines[] = VulnHub_Alerts_Page::url();

		wp_mail(
			$to,
			sprintf(
				/* translators: 1: site name, 2: count */
				__( '[%1$s] Advisory digest — %2$d new matches', 'vulnhub' ),
				get_bloginfo( 'name' ),
				count( $new )
			),
			implode( "\n", $lines ),
			array( 'Content-Type: text/plain; charset=UTF-8' )
		);
	}
}
