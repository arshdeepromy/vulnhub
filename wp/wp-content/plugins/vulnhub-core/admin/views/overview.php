<?php
/**
 * Admin overview.
 *
 * This screen used to open with the severity breakdown, exposure by team, the
 * most widespread vulnerabilities and a table of unowned workstations -- every
 * one of which is already on the Security dashboard, which is where somebody
 * looking at exposure actually goes. The page said "Connector health, data
 * freshness and what needs attention" in its own subtitle and then spent
 * two-thirds of itself on something else.
 *
 * So it now answers only the questions an administrator opens it to ask: is
 * anything broken, is the data still arriving, and who has access. Numbers
 * about the estate live one click away under Dashboard.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;
use VulnHub\Core\Scheduler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_summary   = Repo::summary();
$vh_runs      = vulnhub()->logger->recent_runs( 6 );
$vh_connected = vulnhub()->connectors->all();
$vh_has_data  = (int) $vh_summary['assets_total'] > 0;

/* -------------------------------------------------------------------------
 * What needs attention
 *
 * Every item is something an administrator can act on, with the place to act
 * on it attached. Anything that is merely a large number belongs on the
 * dashboard, not here.
 * ---------------------------------------------------------------------- */
/**
 * A portal admin section's URL, falling back to the wp-admin screen.
 *
 * Imports and People exist only as portal sections -- they have no wp-admin
 * page at all -- so `vh_admin_url()` would send an administrator somewhere
 * that does not exist.
 */
$vh_section_url = static function ( string $section ): string {
	if ( class_exists( 'VulnHub_Dash_Portal' ) ) {
		return VulnHub_Dash_Portal::portal_url(
			VulnHub_Dash_Portal::ADMIN_VIEW,
			array( 'section' => $section )
		);
	}

	return home_url( '/portal-admin/?section=' . rawurlencode( $section ) );
};

$vh_attention = array();

foreach ( $vh_connected as $vh_id => $vh_c ) {
	$vh_h = $vh_c->health();

	if ( 'error' === $vh_h['state'] ) {
		$vh_attention[] = array(
			'level'  => 'bad',
			'text'   => sprintf(
				/* translators: 1: connector label, 2: error detail. */
				__( '%1$s: %2$s', 'vulnhub' ),
				$vh_c->label(),
				$vh_h['detail']
			),
			'action' => __( 'Open', 'vulnhub' ),
			'url'    => vh_admin_url( 'vulnhub-integrations', array( 'connector' => (string) $vh_id ) ),
		);
		continue;
	}

	if ( 'warn' === $vh_h['state'] ) {
		$vh_attention[] = array(
			'level'  => 'warn',
			'text'   => sprintf(
				/* translators: %s: connector label. */
				__( '%s is enabled but not configured.', 'vulnhub' ),
				$vh_c->label()
			),
			'action' => __( 'Configure', 'vulnhub' ),
			'url'    => vh_admin_url( 'vulnhub-integrations', array( 'connector' => (string) $vh_id ) ),
		);
		continue;
	}

	if ( 'mock' === $vh_h['state'] ) {
		$vh_attention[] = array(
			'level'  => 'warn',
			'text'   => sprintf(
				/* translators: %s: connector label. */
				__( '%s is running on generated sample data, not your estate.', 'vulnhub' ),
				$vh_c->label()
			),
			'action' => __( 'Go live', 'vulnhub' ),
			'url'    => vh_admin_url( 'vulnhub-integrations', array( 'connector' => (string) $vh_id ) ),
		);
		continue;
	}

	// Enabled, configured, live -- but is it still arriving?
	if ( $vh_c->supports_sync() && $vh_c->is_enabled() ) {
		$vh_last = vulnhub()->logger->last_run( (string) $vh_id );
		$vh_when = $vh_last ? strtotime( (string) $vh_last['finished_at'] ) : 0;

		if ( $vh_when && ( time() - $vh_when ) > DAY_IN_SECONDS ) {
			$vh_attention[] = array(
				'level'  => 'warn',
				'text'   => sprintf(
					/* translators: 1: connector label, 2: relative time. */
					__( '%1$s has not returned data since %2$s.', 'vulnhub' ),
					$vh_c->label(),
					vh_ago( (string) $vh_last['finished_at'] )
				),
				'action' => __( 'Sync log', 'vulnhub' ),
				'url'    => vh_admin_url( 'vulnhub-sync' ),
			);
		}
	}
}

// Email delivery, when the auth plugin is present. A portal that cannot send
// mail cannot onboard anybody, which is worth saying out loud on this page.
if ( class_exists( 'VulnHub_Auth_Mail' ) ) {
	$vh_mail_fail = VulnHub_Auth_Mail::last_failure();

	if ( ! VulnHub_Auth_Mail::is_configured() ) {
		$vh_attention[] = array(
			'level'  => 'warn',
			'text'   => __( 'Email delivery is not set up, so invitations and password links will not reach anybody.', 'vulnhub' ),
			'action' => __( 'Set up', 'vulnhub' ),
			'url'    => vh_admin_url( 'vulnhub-integrations', array( 'connector' => 'mail' ) ),
		);
	} elseif ( $vh_mail_fail ) {
		$vh_attention[] = array(
			'level'  => 'bad',
			'text'   => sprintf(
				/* translators: %s: error reported by the mail transport. */
				__( 'The last email the portal sent failed: %s', 'vulnhub' ),
				vh_trim( $vh_mail_fail['message'], 90 )
			),
			'action' => __( 'Check', 'vulnhub' ),
			'url'    => vh_admin_url( 'vulnhub-integrations', array( 'connector' => 'mail' ) ),
		);
	}
}

// Import jobs that fell over.
if ( class_exists( 'VulnHub_Import_Jobs' ) ) {
	foreach ( VulnHub_Import_Jobs::recent( 5 ) as $vh_job ) {
		if ( 'failed' !== (string) $vh_job['status'] ) {
			continue;
		}
		$vh_attention[] = array(
			'level'  => 'bad',
			'text'   => sprintf(
				/* translators: 1: file name, 2: relative time. */
				__( 'The import of %1$s failed %2$s.', 'vulnhub' ),
				(string) $vh_job['filename'],
				vh_ago( (string) $vh_job['created_at'] )
			),
			'action' => __( 'Imports', 'vulnhub' ),
			'url'    => $vh_section_url( 'imports' ),
		);
	}
}

/* -------------------------------------------------------------------------
 * People
 * ---------------------------------------------------------------------- */
$vh_people = null;

if ( class_exists( 'VulnHub_Auth_People' ) ) {
	$vh_accounts = VulnHub_Auth_People::manageable();
	$vh_people   = array(
		'total'     => count( $vh_accounts ),
		'by_role'   => array(),
		'invited'   => 0,
		'suspended' => 0,
		'mfa'       => 0,
	);

	foreach ( VulnHub_Auth_People::roles() as $vh_slug => $vh_label ) {
		$vh_people['by_role'][ $vh_label ] = 0;
	}

	foreach ( $vh_accounts as $vh_acct ) {
		$vh_r     = VulnHub_Auth_People::role_of( $vh_acct );
		$vh_label = VulnHub_Auth_People::roles()[ $vh_r ] ?? __( 'No role', 'vulnhub' );

		$vh_people['by_role'][ $vh_label ] = ( $vh_people['by_role'][ $vh_label ] ?? 0 ) + 1;

		if ( VulnHub_Auth_People::is_suspended( $vh_acct ) ) {
			++$vh_people['suspended'];
		}
		if ( VulnHub_Auth_People::is_invited( $vh_acct ) ) {
			++$vh_people['invited'];
		}

		$vh_status = VulnHub_Auth_People::mfa( $vh_acct );
		if ( ! empty( $vh_status['enabled'] ) ) {
			++$vh_people['mfa'];
		}
	}

	// Nobody stays "invited" forever; an unaccepted invitation a week old
	// usually means the mail never arrived.
	if ( $vh_people['invited'] > 0 ) {
		$vh_attention[] = array(
			'level'  => 'warn',
			'text'   => sprintf(
				/* translators: %d: number of accounts. */
				_n(
					'%d invitation has not been accepted yet.',
					'%d invitations have not been accepted yet.',
					$vh_people['invited'],
					'vulnhub'
				),
				$vh_people['invited']
			),
			'action' => __( 'People', 'vulnhub' ),
			'url'    => $vh_section_url( 'people' ),
		);
	}
}
?>

<?php if ( ! $vh_has_data ) : ?>
	<div class="vh-card vh-empty">
		<span class="dashicons dashicons-shield-alt"></span>
		<h2><?php esc_html_e( 'No asset or vulnerability data yet', 'vulnhub' ); ?></h2>
		<p>
			<?php esc_html_e( 'VulnHub is installed and ready. Enable a connector and run its first sync — with mock mode on you get a realistic sample fleet immediately, so you can build out ownership rules and automation before you point it at production.', 'vulnhub' ); ?>
		</p>
		<a class="button button-primary button-hero" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations' ) ); ?>">
			<?php esc_html_e( 'Set up integrations', 'vulnhub' ); ?>
		</a>
	</div>
<?php endif; ?>

<!-- ------------------------------------------------------ needs attention -->
<div class="vh-card" style="margin-bottom:16px">
	<h2><?php esc_html_e( 'Needs attention', 'vulnhub' ); ?></h2>

	<?php if ( ! $vh_attention ) : ?>
		<p class="vh-ok-note" style="margin-top:10px">
			<?php esc_html_e( 'Nothing is broken, every enabled connector has returned data in the last day, and email delivery is working.', 'vulnhub' ); ?>
		</p>
	<?php else : ?>
		<table class="widefat striped">
			<tbody>
			<?php foreach ( $vh_attention as $vh_item ) : ?>
				<tr>
					<td style="width:1%">
						<span class="vh-chip vh-chip--<?php echo 'bad' === $vh_item['level'] ? 'bad' : 'warn'; ?>">
							<?php echo 'bad' === $vh_item['level'] ? esc_html__( 'Error', 'vulnhub' ) : esc_html__( 'Check', 'vulnhub' ); ?>
						</span>
					</td>
					<td><?php echo esc_html( (string) $vh_item['text'] ); ?></td>
					<td class="vh-nowrap" style="width:1%">
						<a class="button button-small" href="<?php echo esc_url( (string) $vh_item['url'] ); ?>">
							<?php echo esc_html( (string) $vh_item['action'] ); ?>
						</a>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>

<div class="vh-grid vh-grid--2">

	<!-- ----------------------------------------------------- data freshness -->
	<div class="vh-card">
		<h2><?php esc_html_e( 'Data freshness', 'vulnhub' ); ?></h2>
		<p class="vh-card__meta" style="margin-bottom:10px">
			<?php esc_html_e( 'When each source last returned something, and how much.', 'vulnhub' ); ?>
		</p>

		<?php
		$vh_feeds = array_filter(
			$vh_connected,
			static fn( $vh_c ): bool => $vh_c->supports_sync()
		);
		?>

		<?php if ( ! $vh_feeds ) : ?>
			<p class="vh-muted"><?php esc_html_e( 'No data connectors are active.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<tbody>
				<?php foreach ( $vh_feeds as $vh_id => $vh_c ) : ?>
					<?php
					$vh_last = vulnhub()->logger->last_run( (string) $vh_id );
					$vh_next = Scheduler::next_run( (string) $vh_id );
					?>
					<tr>
						<td><strong><?php echo esc_html( $vh_c->label() ); ?></strong></td>
						<td class="vh-nowrap">
							<?php
							if ( ! $vh_c->is_enabled() ) {
								echo '<span class="vh-muted">' . esc_html__( 'disabled', 'vulnhub' ) . '</span>';
							} elseif ( ! $vh_last ) {
								echo '<span class="vh-muted">' . esc_html__( 'never run', 'vulnhub' ) . '</span>';
							} else {
								echo esc_html( vh_ago( (string) $vh_last['finished_at'] ) );
							}
							?>
						</td>
						<td class="vh-muted">
							<?php
							if ( $vh_last ) {
								printf(
									/* translators: 1: created count, 2: updated count. */
									esc_html__( '+%1$s new, %2$s updated', 'vulnhub' ),
									esc_html( number_format_i18n( (int) $vh_last['created'] ) ),
									esc_html( number_format_i18n( (int) $vh_last['updated'] ) )
								);
							}
							?>
						</td>
						<td class="vh-muted vh-nowrap" style="width:1%">
							<?php
							echo $vh_next
								? esc_html( sprintf( /* translators: %s: relative time. */ __( 'next in %s', 'vulnhub' ), human_time_diff( time(), $vh_next ) ) )
								: esc_html__( 'manual only', 'vulnhub' );
							?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>

		<p style="margin:12px 0 0">
			<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-sync' ) ); ?>">
				<?php esc_html_e( 'View sync log', 'vulnhub' ); ?>
			</a>
		</p>
	</div>

	<!-- ------------------------------------------------------------- people -->
	<div class="vh-card">
		<h2><?php esc_html_e( 'People', 'vulnhub' ); ?></h2>

		<?php if ( null === $vh_people ) : ?>
			<p class="vh-muted"><?php esc_html_e( 'Account management is unavailable — VulnHub Authentication is not active.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<p class="vh-card__meta" style="margin-bottom:10px">
				<?php
				printf(
					/* translators: 1: number of accounts, 2: number with MFA. */
					esc_html__( '%1$s portal accounts, %2$s with a second factor.', 'vulnhub' ),
					esc_html( number_format_i18n( (int) $vh_people['total'] ) ),
					esc_html( number_format_i18n( (int) $vh_people['mfa'] ) )
				);
				?>
			</p>

			<table class="widefat striped">
				<tbody>
				<?php foreach ( $vh_people['by_role'] as $vh_label => $vh_count ) : ?>
					<tr>
						<td><?php echo esc_html( (string) $vh_label ); ?></td>
						<td class="vh-nowrap" style="width:1%"><strong><?php echo esc_html( number_format_i18n( (int) $vh_count ) ); ?></strong></td>
					</tr>
				<?php endforeach; ?>
				<?php if ( $vh_people['invited'] > 0 ) : ?>
					<tr>
						<td><span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Invited', 'vulnhub' ); ?></span> <?php esc_html_e( 'not yet accepted', 'vulnhub' ); ?></td>
						<td class="vh-nowrap"><strong><?php echo esc_html( number_format_i18n( (int) $vh_people['invited'] ) ); ?></strong></td>
					</tr>
				<?php endif; ?>
				<?php if ( $vh_people['suspended'] > 0 ) : ?>
					<tr>
						<td><span class="vh-chip vh-chip--bad"><?php esc_html_e( 'Suspended', 'vulnhub' ); ?></span> <?php esc_html_e( 'access revoked', 'vulnhub' ); ?></td>
						<td class="vh-nowrap"><strong><?php echo esc_html( number_format_i18n( (int) $vh_people['suspended'] ) ); ?></strong></td>
					</tr>
				<?php endif; ?>
				</tbody>
			</table>

			<p style="margin:12px 0 0">
				<a class="button" href="<?php echo esc_url( $vh_section_url( 'people' ) ); ?>">
					<?php esc_html_e( 'Manage people', 'vulnhub' ); ?>
				</a>
			</p>
		<?php endif; ?>
	</div>
</div>

<div class="vh-grid vh-grid--2">
	<div class="vh-card">
		<h2><?php esc_html_e( 'Connectors', 'vulnhub' ); ?></h2>
		<?php if ( ! $vh_connected ) : ?>
			<p class="vh-muted"><?php esc_html_e( 'No integration plugins are active. Activate VulnHub Tenable, Intune, Jira or CMDB to start pulling data.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<tbody>
				<?php foreach ( $vh_connected as $vh_id => $vh_c ) : ?>
					<?php $vh_health = $vh_c->health(); ?>
					<tr>
						<td><strong><?php echo esc_html( $vh_c->label() ); ?></strong></td>
						<td>
							<span class="vh-health vh-health--<?php echo esc_attr( (string) $vh_health['state'] ); ?>">
								<?php echo esc_html( (string) $vh_health['label'] ); ?>
							</span>
						</td>
						<td class="vh-nowrap" style="width:1%">
							<a class="button button-small" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations', array( 'connector' => (string) $vh_id ) ) ); ?>">
								<?php esc_html_e( 'Open', 'vulnhub' ); ?>
							</a>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		<p style="margin:12px 0 0">
			<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations' ) ); ?>">
				<?php esc_html_e( 'Manage integrations', 'vulnhub' ); ?>
			</a>
		</p>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Recent sync activity', 'vulnhub' ); ?></h2>
		<?php if ( ! $vh_runs ) : ?>
			<p class="vh-muted"><?php esc_html_e( 'No syncs have run yet.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<tbody>
				<?php foreach ( $vh_runs as $vh_run ) : ?>
					<tr>
						<td><strong><?php echo esc_html( ucfirst( (string) $vh_run['connector'] ) ); ?></strong></td>
						<td>
							<span class="vh-state vh-state--<?php echo 'success' === $vh_run['status'] ? 'fixed' : 'open'; ?>">
								<?php echo esc_html( (string) $vh_run['status'] ); ?>
							</span>
						</td>
						<td class="vh-muted">
							<?php
							printf(
								/* translators: 1: created count, 2: updated count. */
								esc_html__( '+%1$d new, %2$d updated', 'vulnhub' ),
								(int) $vh_run['created'],
								(int) $vh_run['updated']
							);
							?>
						</td>
						<td class="vh-muted vh-nowrap"><?php echo esc_html( vh_ago( (string) $vh_run['started_at'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		<p style="margin:12px 0 0">
			<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-sync' ) ); ?>">
				<?php esc_html_e( 'View sync log', 'vulnhub' ); ?>
			</a>
		</p>
	</div>
</div>

