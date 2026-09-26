<?php
/**
 * Cost suggestions, worked out from one cost snapshot.
 *
 * Two lists, and the line between them is the whole point:
 *
 *  - CONFIRMED: every number in the suggestion is either measured (CloudWatch,
 *    EC2 inventory, Cost Explorer) or read from the AWS Price List, and the
 *    change it proposes does not depend on anything we did not measure. The
 *    saving is arithmetic you can check from the evidence shown with it.
 *  - NEEDS CONFIRMATION: the suggestion depends on something this reader
 *    cannot see -- memory use, a retention policy, an IOPS requirement, an
 *    architecture decision. Where the saving is still arithmetic on measured
 *    data it is shown as "if confirmed"; where it is not (how much of a
 *    snapshot estate is obsolete), no saving is shown at all, only what the
 *    item costs today.
 *
 * A suggestion whose price is missing or ambiguous in the Price List is not
 * made. A suggestion whose saving works out at zero or less is not made --
 * which is how "move RDS gp2 to gp3" disappears in a region where the two
 * cost the same.
 *
 * Savings are monthly at on-demand list price, 730 hours to the month (the
 * AWS billing convention). Where a Savings Plan covers the usage, the bill
 * moves by less; the context block says how much of EC2 was covered.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Cost_Recs {

	private const HOURS_MONTH = 730;

	/** Tags that mean something else starts and stops this machine. */
	private const MANAGED_TAGS = array( 'aws:autoscaling:groupName', 'elasticbeanstalk:environment-name', 'aws:eks:cluster-name', 'eks:cluster-name', 'aws:ecs:clusterName', 'karpenter.sh/nodepool' );

	/** @var array<string,mixed> */
	private array $s;
	/** @var array<string,true> Instances already covered by a stronger suggestion. */
	private array $claimed = array();
	/** @var array<string,true> Volumes already counted in another suggestion. */
	private array $claimed_vols = array();

	/** @param array<string,mixed> $snapshot */
	public function __construct( array $snapshot ) {
		$this->s = $snapshot;
	}

	/**
	 * @return array{confirmed:array<int,array<string,mixed>>,verify:array<int,array<string,mixed>>,context:array<string,mixed>}
	 */
	public function build(): array {
		$confirmed = array_merge(
			$this->idle_instances(),
			$this->stopped_instances(),
			$this->unused_addresses(),
			$this->unattached_volumes(),
			$this->nonprod_always_on(),
			$this->gp2_to_gp3()
		);

		$verify = array_merge(
			$this->rightsizing(),
			$this->piops_to_gp3(),
			$this->spend_reviews()
		);

		usort( $confirmed, static fn( $a, $b ) => ( $b['saving'] ?? 0 ) <=> ( $a['saving'] ?? 0 ) );
		usort( $verify, static fn( $a, $b ) => [ null === $a['saving'] ? 1 : 0, -( $a['saving'] ?? 0 ), -( $a['current'] ?? 0 ) ] <=> [ null === $b['saving'] ? 1 : 0, -( $b['saving'] ?? 0 ), -( $b['current'] ?? 0 ) ] );

		return array(
			'confirmed' => $confirmed,
			'verify'    => $verify,
			'context'   => $this->context(),
		);
	}

	/* ============================================================ prices */

	/** @param array<string,mixed> $i */
	private function ec2_price( array $i, string $type = '' ): ?float {
		$op = VulnHub_AWS_Cost_Collector::operation( (string) $i['platform'] );
		if ( '' === $op ) {
			return null;
		}
		$p = $this->s['prices']['ec2'][ ( $type ?: (string) $i['type'] ) . '|' . $op . '|' . $i['region'] ] ?? null;
		return is_numeric( $p ) ? (float) $p : null;
	}

	private function ebs( string $region, string $key ): ?float {
		$p = $this->s['prices']['ebs'][ $region ][ $key ] ?? null;
		return is_numeric( $p ) ? (float) $p : null;
	}

	/**
	 * Monthly cost of one volume at list price, or null when a price is missing.
	 *
	 * @param array<string,mixed> $v
	 */
	private function volume_cost( array $v ): ?float {
		$rg = (string) $v['region'];
		$gb = (float) $v['gb'];
		switch ( (string) $v['type'] ) {
			case 'gp2':
			case 'st1':
			case 'sc1':
			case 'standard':
				$p = $this->ebs( $rg, $v['type'] . '_gb' );
				return null === $p ? null : $gb * $p;
			case 'gp3':
				$g = $this->ebs( $rg, 'gp3_gb' );
				$i = $this->ebs( $rg, 'gp3_iops' );
				$t = $this->ebs( $rg, 'gp3_mibps' );
				if ( null === $g || null === $i || null === $t ) {
					return null;
				}
				return $gb * $g + max( 0, (int) $v['iops'] - 3000 ) * $i + max( 0, (int) $v['throughput'] - 125 ) * $t;
			case 'io1':
				$g = $this->ebs( $rg, 'io1_gb' );
				$i = $this->ebs( $rg, 'io1_iops' );
				return null === $g || null === $i ? null : $gb * $g + (int) $v['iops'] * $i;
			case 'io2':
				$g  = $this->ebs( $rg, 'io2_gb' );
				$t1 = $this->ebs( $rg, 'io2_iops' );
				$t2 = $this->ebs( $rg, 'io2_iops_t2' );
				$t3 = $this->ebs( $rg, 'io2_iops_t3' );
				if ( null === $g || null === $t1 || null === $t2 || null === $t3 ) {
					return null;
				}
				$n = (int) $v['iops'];
				return $gb * $g + min( $n, 32000 ) * $t1 + min( max( $n - 32000, 0 ), 32000 ) * $t2 + max( $n - 64000, 0 ) * $t3;
		}
		return null;
	}

	private function ipv4_month( string $region ): ?float {
		$p = $this->s['prices']['ipv4_idle_hr'][ $region ] ?? null;
		return is_numeric( $p ) ? (float) $p * self::HOURS_MONTH : null;
	}

	/* =========================================================== helpers */

	private static function money( ?float $x ): string {
		if ( null === $x ) {
			return '—';
		}
		// Unit prices keep the precision the Price List gives, so the
		// arithmetic shown beside them can be redone by hand.
		return '$' . number_format( $x, $x < 1 ? 4 : ( $x < 100 ? 2 : 0 ) );
	}

	private function window_hours(): int {
		return (int) ( $this->s['window']['possible']['all'] ?? 336 );
	}

	/** @param array<string,mixed> $i */
	private function env_of( array $i ): string {
		$tags = (array) $i['tags'];
		$key  = $this->scheduler_tag();
		return VulnHub_AWS_Environment::classify(
			(string) ( $tags[ $key ] ?? '' ),
			(string) ( $tags['env'] ?? $tags['Environment'] ?? $tags['environment'] ?? '' ),
			(string) $i['name'],
			(string) $i['account_name']
		);
	}

	/** @param array<string,mixed> $i */
	private static function is_managed( array $i ): bool {
		foreach ( self::MANAGED_TAGS as $k ) {
			if ( isset( $i['tags'][ $k ] ) ) {
				return true;
			}
		}
		return 'spot' === (string) $i['lifecycle'];
	}

	/** The tag key the Instance Scheduler reads, from its own hub stack. */
	private function scheduler_tag(): string {
		foreach ( (array) ( $this->s['scheduler']['stacks'] ?? array() ) as $st ) {
			if ( 'hub' === $st['role'] && ! empty( $st['params']['TagName'] ) ) {
				return (string) $st['params']['TagName'];
			}
		}
		return 'Schedule';
	}

	/**
	 * What the existing scheduled fleet actually does, measured: instances
	 * the Instance Scheduler has acted on (it stamps InstanceScheduler-
	 * LastAction) that did not run around the clock.
	 *
	 * @return array{count:int,hours_week:float,label:string,values:string[]}|null
	 */
	private function fleet_schedule(): ?array {
		static $memo = false;
		if ( false !== $memo ) {
			return $memo;
		}
		$tag    = $this->scheduler_tag();
		$weeks  = $this->window_hours() / 168;
		$hours  = array();
		$values = array();
		$wkday  = array_fill( 0, 24, 0 );
		$wkend  = 0;
		foreach ( (array) $this->s['instances'] as $i ) {
			if ( ! isset( $i['tags']['InstanceScheduler-LastAction'] ) || empty( $i['metrics']['hours'] ) ) {
				continue;
			}
			$h  = (int) $i['metrics']['hours'];
			$we = (int) ( $i['metrics']['buckets']['weekend']['hours'] ?? 0 );
			// On a schedule means: ran, but not most of the week, and not at
			// weekends. An instance the scheduler once touched that now runs
			// around the clock is an exception to the schedule, not part of it.
			if ( $h < 24 || $h > 0.6 * $this->window_hours() || $we > 0.1 * (int) ( $this->s['window']['possible']['weekend'] ?? 96 ) ) {
				continue;
			}
			$hours[]  = $h / $weeks;
			$values[] = (string) ( $i['tags'][ $tag ] ?? '' );
			foreach ( (array) $i['metrics']['grid'] as $d => $row ) {
				foreach ( (array) $row as $hr => $n ) {
					if ( $d < 5 ) {
						$wkday[ $hr ] += (int) $n;
					} else {
						$wkend += (int) $n;
					}
				}
			}
		}
		if ( count( $hours ) < 3 ) {
			$memo = null;
			return null;
		}
		sort( $hours );
		$median = $hours[ (int) floor( count( $hours ) / 2 ) ];

		// Hours of the weekday that at least half the fleet was up for.
		$need = count( $hours ) * 5 * $weeks * 0.5;
		$on   = array_keys( array_filter( $wkday, static fn( $n ) => $n >= $need ) );
		$lab  = $on ? sprintf( 'Mon–Fri %02d:00–%02d:00', min( $on ), max( $on ) + 1 ) : '';
		$lab .= $wkend < count( $hours ) * 48 * $weeks * 0.1 ? ', off at weekends' : '';

		$memo = array(
			'count'      => count( $hours ),
			'hours_week' => round( $median, 1 ),
			'label'      => $lab,
			'values'     => array_values( array_unique( array_filter( $values ) ) ),
		);
		return $memo;
	}

	/**
	 * @param array<string,mixed> $i
	 * @return array<string,mixed>
	 */
	private function base( string $id, string $kind, string $cat, string $title, array $i = array() ): array {
		return array(
			'id'           => $id,
			'kind'         => $kind,
			'category'     => $cat,
			'title'        => $title,
			'account'      => (string) ( $i['account'] ?? '' ),
			'account_name' => (string) ( $i['account_name'] ?? '' ),
			'region'       => (string) ( $i['region'] ?? '' ),
			'resource'     => (string) ( $i['id'] ?? '' ),
			'name'         => (string) ( $i['name'] ?? '' ),
			'env'          => $i ? VulnHub_AWS_Environment::label( isset( $i['tags'] ) ? $this->env_of( $i ) : VulnHub_AWS_Environment::classify( (string) ( $i['account_name'] ?? '' ) ) ) : '',
			'current'      => null,
			'saving'       => null,
			'basis'        => '',
			'evidence'     => array(),
			'action'       => '',
			'checks'       => array(),
			'grid'         => null,
		);
	}

	/** @param array<string,mixed> $i @return array<int,array{0:string,1:string}> */
	private function usage_evidence( array $i ): array {
		$m = (array) $i['metrics'];
		$p = (array) $this->s['window']['possible'];
		$b = (array) $m['buckets'];
		return array(
			array( __( 'Instance', 'vulnhub' ), trim( $i['name'] . ' · ' . $i['id'] . ' · ' . $i['type'] . ' · ' . $i['platform'] ) ),
			array( __( 'Hours running (14 days)', 'vulnhub' ), sprintf( '%d of %d', (int) $m['hours'], (int) $p['all'] ) ),
			array( __( 'Weekend hours running', 'vulnhub' ), sprintf( '%d of %d', (int) $b['weekend']['hours'], (int) $p['weekend'] ) ),
			array( __( 'CPU average / 95th pct of hourly max / peak', 'vulnhub' ), sprintf( '%s%% / %s%% / %s%%', $m['cpu_avg'], $m['cpu_p95'], $m['cpu_peak'] ) ),
			array( __( 'Network in+out, average', 'vulnhub' ), sprintf( '%s MB/hour', $m['net_mb_hr'] ) ),
		);
	}

	/* ================================================= CONFIRMED rules */

	/** Running around the clock and doing nothing: no network, no CPU. @return array<int,array<string,mixed>> */
	private function idle_instances(): array {
		$out = array();
		foreach ( (array) $this->s['instances'] as $i ) {
			$m = $i['metrics'] ?? null;
			if ( 'running' !== $i['state'] || ! $m || (int) $m['hours'] < 0.9 * $this->window_hours() || self::is_managed( $i ) ) {
				continue;
			}
			if ( (float) $m['net_mb_hr'] >= 0.05 || (float) $m['cpu_p95'] >= 5 ) {
				continue;
			}
			$p = $this->ec2_price( $i );
			if ( null === $p ) {
				continue;
			}
			$disk  = 0.0;
			$known = true;
			foreach ( (array) $i['ebs'] as $vid ) {
				$c = isset( $this->s['volumes'][ $vid ] ) ? $this->volume_cost( $this->s['volumes'][ $vid ] ) : null;
				if ( null === $c ) {
					$known = false;
				} else {
					$disk += $c;
				}
			}
			$compute = $p * self::HOURS_MONTH;
			$r       = $this->base( 'idle:' . $i['id'], 'confirmed', 'idle', sprintf( __( 'Idle for 14 days: %s', 'vulnhub' ), $i['name'] ?: $i['id'] ), $i );
			$r['current']  = $compute + ( $known ? $disk : 0 );
			$r['saving']   = $compute + ( $known ? $disk : 0 );
			$r['basis']    = sprintf( '%s/h × 730 h = %s compute', self::money( $p ), self::money( $compute ) ) . ( $known && $disk > 0 ? sprintf( ' + %s disks', self::money( $disk ) ) : '' );
			$r['evidence'] = array_merge(
				$this->usage_evidence( $i ),
				array( array( __( 'On-demand price (AWS Price List)', 'vulnhub' ), self::money( $p ) . '/hour' ) ),
				$known ? array( array( __( 'Attached disks at list price', 'vulnhub' ), self::money( $disk ) . '/month' ) ) : array()
			);
			$r['action'] = __( 'Less than 50 KB an hour of network and under 5% CPU for two weeks. Confirm with the owner, take a final snapshot, then terminate. If it must stay, stop it — that alone saves the compute.', 'vulnhub' );
			$r['grid']   = $m['grid'];
			$out[]       = $r;
			$this->claimed[ $i['id'] ] = true;
			foreach ( (array) $i['ebs'] as $vid ) {
				$this->claimed_vols[ $vid ] = true;
			}
		}
		return $out;
	}

	/** Stopped for a long time but still paying for its disks and addresses. @return array<int,array<string,mixed>> */
	private function stopped_instances(): array {
		$out = array();
		$now = time();
		foreach ( (array) $this->s['instances'] as $i ) {
			if ( 'stopped' !== $i['state'] ) {
				continue;
			}
			$since = '' !== (string) $i['stopped_at'] ? strtotime( $i['stopped_at'] . ' UTC' ) : 0;
			$days  = $since ? (int) floor( ( $now - $since ) / DAY_IN_SECONDS ) : null;
			$quiet = empty( $i['metrics']['hours'] );
			if ( ! ( ( null !== $days && $days >= 30 ) || ( null === $days && $quiet ) ) ) {
				continue;
			}
			$disk  = 0.0;
			$lines = array();
			$known = true;
			foreach ( (array) $i['ebs'] as $vid ) {
				$v = $this->s['volumes'][ $vid ] ?? null;
				$c = $v ? $this->volume_cost( $v ) : null;
				if ( null === $c ) {
					$known = false;
					continue;
				}
				$disk   += $c;
				$lines[] = sprintf( '%s %d GB %s = %s', $vid, $v['gb'], $v['type'], self::money( $c ) );
			}
			$ip   = 0.0;
			$ips  = array();
			foreach ( (array) $this->s['eips'] as $e ) {
				if ( $e['instance'] === $i['id'] ) {
					$m = $this->ipv4_month( (string) $e['region'] );
					if ( null !== $m ) {
						$ip   += $m;
						$ips[] = $e['ip'];
					}
				}
			}
			if ( ! $known || $disk + $ip <= 0 ) {
				continue;
			}
			$r = $this->base( 'stopped:' . $i['id'], 'confirmed', 'stopped', sprintf( __( 'Stopped %s but still billed: %s', 'vulnhub' ), null !== $days ? sprintf( _n( '%d day', '%d days', $days, 'vulnhub' ), $days ) : __( '14+ days', 'vulnhub' ), $i['name'] ?: $i['id'] ), $i );
			$r['current']  = $disk + $ip;
			$r['saving']   = $disk + $ip;
			$r['basis']    = sprintf( '%s disks', self::money( $disk ) ) . ( $ip > 0 ? sprintf( ' + %s for %d Elastic IP(s)', self::money( $ip ), count( $ips ) ) : '' );
			$r['evidence'] = array_values(
				array_filter(
					array(
						array( __( 'Instance', 'vulnhub' ), trim( $i['name'] . ' · ' . $i['id'] . ' · ' . $i['type'] ) ),
						array( __( 'Stopped since', 'vulnhub' ), $since ? wp_date( 'j M Y', $since ) : __( 'unknown — no activity in the 14-day window', 'vulnhub' ) ),
						array( __( 'Last launched', 'vulnhub' ), (string) $i['launch'] ),
						array( __( 'Disks at list price', 'vulnhub' ), implode( '; ', $lines ) ),
						$ips ? array( __( 'Elastic IPs (billed while the instance is stopped)', 'vulnhub' ), implode( ', ', $ips ) ) : null,
						isset( $i['tags']['InstanceScheduler-LastAction'] ) ? array( __( 'Scheduler last action', 'vulnhub' ), (string) $i['tags']['InstanceScheduler-LastAction'] ) : null,
					)
				)
			);
			$r['action'] = __( 'Not used for this long, it can be dropped: confirm with the owner, snapshot the disks (snapshot storage is billed separately and is not in this saving), then terminate and release its Elastic IPs.', 'vulnhub' );
			$out[]       = $r;
			$this->claimed[ $i['id'] ] = true;
			foreach ( (array) $i['ebs'] as $vid ) {
				$this->claimed_vols[ $vid ] = true;
			}
		}
		return $out;
	}

	/** Elastic IPs attached to nothing. @return array<int,array<string,mixed>> */
	private function unused_addresses(): array {
		$out = array();
		foreach ( (array) $this->s['eips'] as $e ) {
			if ( '' !== (string) $e['association'] ) {
				continue;
			}
			$m = $this->ipv4_month( (string) $e['region'] );
			if ( null === $m ) {
				continue;
			}
			$r = $this->base( 'eip:' . $e['alloc'], 'confirmed', 'address', sprintf( __( 'Elastic IP attached to nothing: %s', 'vulnhub' ), $e['ip'] ), array( 'account' => $e['account'], 'account_name' => $e['account_name'], 'region' => $e['region'], 'id' => $e['alloc'], 'name' => $e['name'] ) );
			$r['current']  = $m;
			$r['saving']   = $m;
			$r['basis']    = sprintf( '%s/h idle public IPv4 × 730 h', self::money( $m / self::HOURS_MONTH ) );
			$r['evidence'] = array(
				array( __( 'Address', 'vulnhub' ), $e['ip'] . ' · ' . $e['alloc'] . ( $e['name'] ? ' · ' . $e['name'] : '' ) ),
				array( __( 'Associated with', 'vulnhub' ), __( 'nothing', 'vulnhub' ) ),
			);
			$r['action'] = __( 'Check nothing whitelists this address (a partner firewall, DNS), then release it.', 'vulnhub' );
			$out[]       = $r;
		}
		return $out;
	}

	/** Volumes attached to nothing. @return array<int,array<string,mixed>> */
	private function unattached_volumes(): array {
		$out = array();
		foreach ( (array) $this->s['volumes'] as $v ) {
			if ( 'available' !== (string) $v['state'] ) {
				continue;
			}
			$c = $this->volume_cost( $v );
			if ( null === $c || $c <= 0 ) {
				continue;
			}
			$r = $this->base( 'vol:' . $v['id'], 'confirmed', 'volume', sprintf( __( 'Disk attached to nothing: %s', 'vulnhub' ), $v['name'] ?: $v['id'] ), array( 'account' => $v['account'], 'account_name' => $v['account_name'], 'region' => $v['region'], 'id' => $v['id'], 'name' => $v['name'] ) );
			$r['current']  = $c;
			$r['saving']   = $c;
			$r['basis']    = sprintf( '%d GB %s at list price', $v['gb'], $v['type'] );
			$r['evidence'] = array(
				array( __( 'Volume', 'vulnhub' ), sprintf( '%s · %d GB · %s · created %s', $v['id'], $v['gb'], $v['type'], $v['created'] ) ),
				array( __( 'Attached to', 'vulnhub' ), __( 'nothing', 'vulnhub' ) ),
			);
			$r['action'] = __( 'Snapshot it if the data might be needed, then delete the volume.', 'vulnhub' );
			$out[]       = $r;
			$this->claimed_vols[ $v['id'] ] = true;
		}
		return $out;
	}

	/**
	 * Non-production machines that run around the clock, while the rest of
	 * non-production is measurably on a schedule.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function nonprod_always_on(): array {
		$fleet = $this->fleet_schedule();
		if ( ! $fleet ) {
			return array();
		}
		$tag  = $this->scheduler_tag();
		$out  = array();
		$poss = (array) $this->s['window']['possible'];

		foreach ( (array) $this->s['instances'] as $i ) {
			$m = $i['metrics'] ?? null;
			if ( 'running' !== $i['state'] || ! $m || isset( $this->claimed[ $i['id'] ] ) || self::is_managed( $i ) ) {
				continue;
			}
			if ( VulnHub_AWS_Environment::NONPROD !== $this->env_of( $i ) ) {
				continue;
			}
			// Measured, not assumed: this instance's own hours a week against
			// the fleet's, and it must have run through a good part of the weekends.
			$weeks = max( 1, $poss['all'] / 168 );
			$wk    = (int) $m['hours'] / $weeks;
			if ( $wk < $fleet['hours_week'] + 20 || (int) $m['buckets']['weekend']['hours'] < 0.25 * $poss['weekend'] ) {
				continue;
			}
			$p = $this->ec2_price( $i );
			if ( null === $p ) {
				continue;
			}
			$off  = ( $wk - $fleet['hours_week'] ) / 168;
			$save = $p * self::HOURS_MONTH * $off;
			$cur  = (string) ( $i['tags'][ $tag ] ?? '' );
			$r    = $this->base( 'sched:' . $i['id'], 'confirmed', 'schedule', sprintf( __( 'Non-production, off the schedule (%1$s h/week): %2$s', 'vulnhub' ), round( $wk ), $i['name'] ?: $i['id'] ), $i );
			$r['current']  = $p * self::HOURS_MONTH;
			$r['saving']   = $save;
			$r['basis']    = sprintf( '%s/h × 730 h × (%s − %s h/week)/168 — its measured hours a week less the scheduled fleet’s', self::money( $p ), round( $wk, 1 ), $fleet['hours_week'] );
			$r['evidence'] = array_merge(
				$this->usage_evidence( $i ),
				array(
					array( __( 'Environment', 'vulnhub' ), sprintf( '%s tag "%s"', $tag, $cur ?: '—' ) ),
					array( __( 'How the scheduled fleet runs (measured)', 'vulnhub' ), sprintf( '%s — %d instances, median %s h/week', $fleet['label'], $fleet['count'], $fleet['hours_week'] ) ),
					array( __( 'Scheduled tag values in use', 'vulnhub' ), implode( ', ', $fleet['values'] ) ?: '—' ),
					array( __( 'On-demand price (AWS Price List)', 'vulnhub' ), self::money( $p ) . '/hour' ),
				)
			);
			$r['action'] = $fleet['values']
				/* translators: 1: tag key, 2: tag values. */
				? sprintf( __( 'Put it on the same schedule as the rest of non-production: set the %1$s tag to a scheduled value (%2$s). If something depends on it out of hours, schedule it to start earlier rather than run all week.', 'vulnhub' ), $tag, implode( ', ', $fleet['values'] ) )
				: __( 'Put it on the same schedule as the rest of non-production.', 'vulnhub' );
			$r['grid']   = $m['grid'];
			$out[]       = $r;
			$this->claimed[ $i['id'] ] = true;
		}
		return $out;
	}

	/**
	 * gp2 volumes to gp3, with gp3 provisioned to at least gp2's own baseline
	 * (3 IOPS per GB up to 16,000; 250 MiB/s above 170 GB) so nothing gets
	 * slower. Grouped per account.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function gp2_to_gp3(): array {
		$by = array();
		foreach ( (array) $this->s['volumes'] as $v ) {
			if ( 'gp2' !== (string) $v['type'] || isset( $this->claimed_vols[ $v['id'] ] ) ) {
				continue;
			}
			$rg  = (string) $v['region'];
			$g2  = $this->ebs( $rg, 'gp2_gb' );
			$g3  = $this->ebs( $rg, 'gp3_gb' );
			$io  = $this->ebs( $rg, 'gp3_iops' );
			$tp  = $this->ebs( $rg, 'gp3_mibps' );
			if ( null === $g2 || null === $g3 || null === $io || null === $tp ) {
				continue;
			}
			$gb    = (int) $v['gb'];
			$iops  = max( 0, min( 3 * $gb, 16000 ) - 3000 );
			$tput  = $gb > 170 ? 125 : 0;
			$after = $gb * $g3 + $iops * $io + $tput * $tp;
			$save  = $gb * $g2 - $after;
			if ( $save <= 0 ) {
				continue;
			}
			$by[ $v['account'] ]['vols'][]  = array( $v, $gb * $g2, $after, $iops + 3000, $tput + 125 );
			$by[ $v['account'] ]['save']    = ( $by[ $v['account'] ]['save'] ?? 0 ) + $save;
			$by[ $v['account'] ]['cur']     = ( $by[ $v['account'] ]['cur'] ?? 0 ) + $gb * $g2;
			$by[ $v['account'] ]['gb']      = ( $by[ $v['account'] ]['gb'] ?? 0 ) + $gb;
			$by[ $v['account'] ]['name']    = $v['account_name'];
			$by[ $v['account'] ]['region']  = $rg;
		}
		$out = array();
		foreach ( $by as $acct => $x ) {
			if ( $x['save'] < 1 ) {
				continue;
			}
			usort( $x['vols'], static fn( $a, $b ) => $b[0]['gb'] <=> $a[0]['gb'] );
			$r = $this->base( 'gp3:' . $acct, 'confirmed', 'storage', sprintf( _n( 'Move %d gp2 disk to gp3', 'Move %d gp2 disks to gp3', count( $x['vols'] ), 'vulnhub' ), count( $x['vols'] ) ), array( 'account' => $acct, 'account_name' => $x['name'], 'region' => $x['region'] ) );
			$r['current']  = $x['cur'];
			$r['saving']   = $x['save'];
			$r['basis']    = sprintf( '%d GB: gp2 %s → gp3 %s incl. IOPS/throughput to match gp2', $x['gb'], self::money( $x['cur'] ), self::money( $x['cur'] - $x['save'] ) );
			$lines         = array();
			foreach ( array_slice( $x['vols'], 0, 12 ) as $l ) {
				$lines[] = sprintf( '%s%s %d GB: %s → %s (gp3 at %d IOPS, %d MiB/s)', $l[0]['id'], $l[0]['instance'] ? ' (' . $l[0]['instance'] . ')' : '', $l[0]['gb'], self::money( $l[1] ), self::money( $l[2] ), $l[3], $l[4] );
			}
			if ( count( $x['vols'] ) > 12 ) {
				$lines[] = sprintf( __( '…and %d more', 'vulnhub' ), count( $x['vols'] ) - 12 );
			}
			$r['evidence'] = array(
				array( __( 'Prices (AWS Price List)', 'vulnhub' ), sprintf( 'gp2 %s/GB-month · gp3 %s/GB-month · gp3 IOPS %s · gp3 MiB/s %s', self::money( $this->ebs( $x['region'], 'gp2_gb' ) ), self::money( $this->ebs( $x['region'], 'gp3_gb' ) ), self::money( $this->ebs( $x['region'], 'gp3_iops' ) ), self::money( $this->ebs( $x['region'], 'gp3_mibps' ) ) ) ),
				array( __( 'Volumes', 'vulnhub' ), implode( "\n", $lines ) ),
			);
			$r['action'] = __( 'Modify each volume to gp3 with the IOPS and throughput listed (an online change, no downtime or detach). These match what gp2 gives the volume today, so nothing gets slower.', 'vulnhub' );
			$out[]       = $r;
		}
		return $out;
	}

	/* ========================================== NEEDS CONFIRMATION rules */

	/** One size down (and/or to the current generation) where CPU says it fits. @return array<int,array<string,mixed>> */
	private function rightsizing(): array {
		$out = array();
		foreach ( (array) $this->s['instances'] as $i ) {
			$m = $i['metrics'] ?? null;
			if ( 'running' !== $i['state'] || ! $m || isset( $this->claimed[ $i['id'] ] ) || self::is_managed( $i ) ) {
				continue;
			}
			if ( (int) $m['hours'] < 0.9 * $this->window_hours() ) {
				continue;
			}
			$type  = (string) $i['type'];
			$cur   = VulnHub_AWS_Cost_Collector::current_gen( $type );
			$low   = (float) $m['cpu_peak'] < 40 && (float) $m['cpu_p95'] < 25;
			$base  = $cur ?: $type;
			$target = $low ? VulnHub_AWS_Cost_Collector::one_size_down( $base ) : $cur;
			if ( '' === $target ) {
				continue;
			}
			$now = $this->ec2_price( $i );
			$new = $this->ec2_price( $i, $target );
			if ( null === $now || null === $new || $new >= $now ) {
				continue;
			}
			$save = ( $now - $new ) * self::HOURS_MONTH;
			$why  = $low && $cur ? __( 'low CPU, previous generation', 'vulnhub' ) : ( $low ? __( 'low CPU', 'vulnhub' ) : __( 'previous generation', 'vulnhub' ) );
			$r    = $this->base( 'size:' . $i['id'], 'verify', $low ? 'rightsize' : 'modernise', sprintf( '%s → %s: %s (%s)', $type, $target, $i['name'] ?: $i['id'], $why ), $i );
			$r['current']  = $now * self::HOURS_MONTH;
			$r['saving']   = $save;
			$r['basis']    = sprintf( '(%s − %s)/h × 730 h', self::money( $now ), self::money( $new ) );
			$r['evidence'] = array_merge(
				$this->usage_evidence( $i ),
				array( array( __( 'On-demand price (AWS Price List)', 'vulnhub' ), sprintf( '%s %s/h → %s %s/h', $type, self::money( $now ), $target, self::money( $new ) ) ) )
			);
			$checks = array();
			if ( $low ) {
				$checks[] = __( 'Memory: not measured (no CloudWatch agent memory metric). One size down halves the RAM — check the OS or application shows headroom.', 'vulnhub' );
				$checks[] = sprintf( __( 'CPU peaked at %s%% over 14 days; a month-end or batch peak outside this window would not show.', 'vulnhub' ), $m['cpu_peak'] );
			}
			if ( $cur ) {
				$checks[] = __( 'Moving to a current-generation (Nitro) type needs ENA and NVMe drivers in the AMI; older images need them installed first.', 'vulnhub' );
			}
			$checks[]    = __( 'Software licensed per vCPU or per instance size (databases, some Windows workloads) — check the licence terms before changing size.', 'vulnhub' );
			$r['checks'] = $checks;
			$r['action'] = sprintf( __( 'Stop, change the instance type to %s, start, and watch it for a week.', 'vulnhub' ), $target );
			$r['grid']   = $m['grid'];
			$out[]       = $r;
		}
		return $out;
	}

	/** Provisioned-IOPS disks whose measured IOPS fit gp3. @return array<int,array<string,mixed>> */
	private function piops_to_gp3(): array {
		$by = array();
		foreach ( (array) $this->s['volumes'] as $v ) {
			if ( ! in_array( (string) $v['type'], array( 'io1', 'io2' ), true ) || isset( $this->claimed_vols[ $v['id'] ] ) ) {
				continue;
			}
			$ms = $v['measured'] ?? null;
			if ( ! $ms || (int) $ms['points'] < 100 || (int) $v['gb'] > 16384 ) {
				continue;
			}
			$need_iops = max( 3000, (int) $ms['iops_peak'] );
			$need_tput = max( 125, (int) ceil( (float) $ms['mibs_peak'] * 1.2 ) );
			if ( $need_iops > 16000 || $need_tput > 1000 ) {
				continue;
			}
			$rg  = (string) $v['region'];
			$g3  = $this->ebs( $rg, 'gp3_gb' );
			$io  = $this->ebs( $rg, 'gp3_iops' );
			$tp  = $this->ebs( $rg, 'gp3_mibps' );
			$now = $this->volume_cost( $v );
			if ( null === $g3 || null === $io || null === $tp || null === $now ) {
				continue;
			}
			$after = (int) $v['gb'] * $g3 + ( $need_iops - 3000 ) * $io + ( $need_tput - 125 ) * $tp;
			if ( $after >= $now ) {
				continue;
			}
			$key = $v['instance'] ?: $v['id'];
			$by[ $key ][] = array( $v, $now, $after, $need_iops, $need_tput );
		}
		$out = array();
		foreach ( $by as $key => $vols ) {
			$now   = array_sum( array_column( $vols, 1 ) );
			$after = array_sum( array_column( $vols, 2 ) );
			$inst  = $this->s['instances'][ $key ] ?? null;
			$ctx   = $inst ?: array( 'account' => $vols[0][0]['account'], 'account_name' => $vols[0][0]['account_name'], 'region' => $vols[0][0]['region'], 'id' => $key, 'name' => $vols[0][0]['name'] );
			$label = $ctx['name'] ?: $key;
			$title = count( $vols ) > 1
				/* translators: 1: number of disks, 2: instance or volume name. */
				? sprintf( __( '%1$d provisioned-IOPS disks to gp3: %2$s', 'vulnhub' ), count( $vols ), $label )
				/* translators: %s: instance or volume name. */
				: sprintf( __( 'Provisioned-IOPS disk to gp3: %s', 'vulnhub' ), $label );
			$r     = $this->base( 'io:' . $key, 'verify', 'storage', $title, $ctx );
			$r['current'] = $now;
			$r['saving']  = $now - $after;
			$r['basis']   = sprintf( '%s now → %s on gp3 sized to measured peak', self::money( $now ), self::money( $after ) );
			$lines        = array();
			foreach ( $vols as $l ) {
				$lines[] = sprintf(
					'%s %d GB %s, %d IOPS provisioned — measured peak %d IOPS (p99 %d), peak %s MiB/s: %s → gp3 at %d IOPS / %d MiB/s %s',
					$l[0]['id'],
					$l[0]['gb'],
					$l[0]['type'],
					$l[0]['iops'],
					$l[0]['measured']['iops_peak'],
					$l[0]['measured']['iops_p99'],
					$l[0]['measured']['mibs_peak'],
					self::money( $l[1] ),
					$l[3],
					$l[4],
					self::money( $l[2] )
				);
			}
			$r['evidence'] = array(
				array( __( 'Volumes (14 days, 5-minute averages)', 'vulnhub' ), implode( "\n", $lines ) ),
				array( __( 'Prices (AWS Price List)', 'vulnhub' ), sprintf( 'gp3 %s/GB-month · %s per IOPS above 3,000 · %s per MiB/s above 125', self::money( $this->ebs( (string) $vols[0][0]['region'], 'gp3_gb' ) ), self::money( $this->ebs( (string) $vols[0][0]['region'], 'gp3_iops' ) ), self::money( $this->ebs( (string) $vols[0][0]['region'], 'gp3_mibps' ) ) ) ),
			);
			$r['checks'] = array(
				__( 'The peak is the highest 5-minute average: bursts shorter than that are averaged away. Check the application’s own latency and IOPS needs.', 'vulnhub' ),
				__( 'Fourteen days may miss a month-end, quarter-end or batch peak.', 'vulnhub' ),
				__( 'io2 is built for 99.999% durability and sub-millisecond latency; gp3 for 99.8–99.9%. Check the vendor or DBA does not require io2.', 'vulnhub' ),
			);
			$r['action'] = __( 'If the checks pass, modify each volume to gp3 at the IOPS and throughput listed (online change). Watch latency for a week.', 'vulnhub' );
			$out[]       = $r;
		}
		return $out;
	}

	/**
	 * Spend that deserves a decision but whose saving cannot be measured from
	 * here. Only today's cost is shown -- no invented percentage.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function spend_reviews(): array {
		$rules = array(
			array( 'snap', '/EBS:SnapshotUsage$/', 100, false, __( 'EBS snapshots', 'vulnhub' ), __( 'Check the retention policy, snapshots left behind by deleted volumes or AMIs, and whether older snapshots can move to the archive tier.', 'vulnhub' ), array( __( 'How long snapshots must be kept, and whether any belong to deleted volumes or retired AMIs.', 'vulnhub' ), __( 'Archive tier is cheaper per GB but stores a full copy, not an increment, and has a 90-day minimum — only worth it for snapshots kept long-term.', 'vulnhub' ) ) ),
			array( 'nat', '/NatGateway-(Hours|Bytes)$/', 150, true, __( 'NAT gateways in a non-production account', 'vulnhub' ), __( 'Consider routing non-production egress through a shared (centralised) NAT or inspection VPC instead of a NAT gateway per account.', 'vulnhub' ), array( __( 'Whether the account can use the shared egress path through the transit gateway.', 'vulnhub' ) ) ),
			array( 'vpce', '/VpcEndpoint-Hours$/', 150, true, __( 'Interface VPC endpoints in a non-production account', 'vulnhub' ), __( 'Consider sharing interface endpoints from a central VPC rather than each account running its own set.', 'vulnhub' ), array( __( 'Which endpoints are actually used (VPC Flow Logs or endpoint metrics), and whether a central endpoint VPC is reachable.', 'vulnhub' ) ) ),
			array( 'rdsbk', '/RDS:ChargedBackupUsage$/', 100, true, __( 'RDS backup storage in a non-production account', 'vulnhub' ), __( 'Shorten automated-backup retention and remove old manual snapshots on non-production databases.', 'vulnhub' ), array( __( 'The retention non-production actually needs.', 'vulnhub' ) ) ),
			array( 'config', '/ConfigurationItemRecorded$/', 150, true, __( 'AWS Config recording in a non-production account', 'vulnhub' ), __( 'Switch non-production to daily (periodic) recording, or exclude high-churn resource types.', 'vulnhub' ), array( __( 'Whether any compliance control requires continuous recording in this account.', 'vulnhub' ) ) ),
			array( 'trail', '/DataEventsRecorded$/', 150, false, __( 'CloudTrail data events', 'vulnhub' ), __( 'Narrow data-event selectors to the buckets and functions that need auditing.', 'vulnhub' ), array( __( 'Which data events an audit or investigation actually relies on.', 'vulnhub' ) ) ),
			array( 's3ia', '/TimedStorage-SIA-ByteHrs$/', 500, false, __( 'S3 Standard-IA storage', 'vulnhub' ), __( 'Review a lifecycle move to Glacier Instant Retrieval or colder classes for data that is rarely read.', 'vulnhub' ), array( __( 'How often the data is read and how fast a restore must be — retrieval fees apply to colder classes.', 'vulnhub' ) ) ),
		);

		$usage = (array) ( $this->s['usage']['last_month'] ?? array() );
		$out   = array();
		foreach ( $rules as $ru ) {
			foreach ( $usage as $acct => $rows ) {
				$name = (string) ( $this->s['accounts'][ $acct ]['name'] ?? '' );
				if ( $ru[3] && VulnHub_AWS_Environment::NONPROD !== VulnHub_AWS_Environment::classify( $name ) ) {
					continue;
				}
				$cost = 0.0;
				$qty  = array();
				foreach ( (array) $rows as $row ) {
					if ( preg_match( $ru[1], (string) $row[1] ) ) {
						$cost += (float) $row[2];
						$qty[] = sprintf( '%s: %s %s = %s', $row[1], number_format( (float) $row[3] ), $row[4], self::money( (float) $row[2] ) );
					}
				}
				if ( $cost < $ru[2] ) {
					continue;
				}
				$r = $this->base( $ru[0] . ':' . $acct, 'verify', 'review', sprintf( '%s — %s', $ru[4], $name ?: $acct ), array( 'account' => $acct, 'account_name' => $name ) );
				$r['current']  = $cost;
				$r['saving']   = null;
				$r['basis']    = __( 'Saving depends on the answer to the checks — not estimated.', 'vulnhub' );
				$r['evidence'] = array( array( __( 'Last full month (Cost Explorer)', 'vulnhub' ), implode( "\n", $qty ) ) );
				$r['checks']   = $ru[6];
				$r['action']   = $ru[5];
				$out[]         = $r;
			}
		}
		return $out;
	}

	/* ============================================================ context */

	/** @return array<string,mixed> */
	private function context(): array {
		$covered = 0.0;
		$ondem   = 0.0;
		foreach ( (array) ( $this->s['records'] ?? array() ) as $rows ) {
			foreach ( (array) $rows as $r ) {
				if ( 'Amazon Elastic Compute Cloud - Compute' !== $r[1] ) {
					continue;
				}
				if ( 'SavingsPlanCoveredUsage' === $r[0] || 'DiscountedUsage' === $r[0] ) {
					$covered += (float) $r[2];
				} elseif ( 'Usage' === $r[0] ) {
					$ondem += (float) $r[2];
				}
			}
		}
		return array(
			'ec2_covered'   => round( $covered, 2 ),
			'ec2_on_demand' => round( $ondem, 2 ),
			'fleet'         => $this->fleet_schedule(),
			'scheduler_tag' => $this->scheduler_tag(),
		);
	}
}
