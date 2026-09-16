<?php
/**
 * VulnHub → Threat context.
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_status  = VulnHub_Threat_Feeds::status();
$vh_sources = VulnHub_Threat_Classify::poc_sources();
$vh_rule    = VulnHub_Threat_Classify::exposure_rule();
$vh_notice  = VulnHub_Threat_Admin::notice();
$vh_lanes   = VulnHub_Threat_Repo::has_data() ? VulnHub_Threat_Repo::lanes() : null;
?>
<div class="vh-section vh-section--threat">

	<?php if ( '' !== $vh_notice ) : ?>
		<div class="vh-notice"><p><?php echo esc_html( $vh_notice ); ?></p></div>
	<?php endif; ?>

	<h2><?php esc_html_e( 'Where the numbers come from', 'vulnhub' ); ?></h2>

	<p class="vh-sub">
		<?php
		esc_html_e(
			'Tenable does not say how a vulnerability would be reached, but the CVE ids in its titles and descriptions do. Those ids are looked up in three public feeds — nothing about this estate is sent anywhere — and the CVSS vector on each one says whether an exploit needs a network, an account, or a person to click something. That is the whole basis of the attack-path widget.',
			'vulnhub'
		);
		?>
	</p>

	<table class="vh-table vh-table--kv">
		<tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'Last refresh', 'vulnhub' ); ?></th>
				<td>
					<?php echo esc_html( '' !== $vh_status['last_run'] ? $vh_status['last_run'] . ' UTC' : __( 'never', 'vulnhub' ) ); ?>
					<?php if ( $vh_status['duration'] ) : ?>
						<span class="vh-sub">(<?php echo esc_html( sprintf( /* translators: %s: seconds. */ __( 'took %ss', 'vulnhub' ), $vh_status['duration'] ) ); ?>)</span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Next scheduled', 'vulnhub' ); ?></th>
				<td><?php echo esc_html( $vh_status['next_run'] ? vh_date( gmdate( 'Y-m-d H:i:s', (int) $vh_status['next_run'] ) ) : __( 'not scheduled', 'vulnhub' ) ); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'CVEs known', 'vulnhub' ); ?></th>
				<td>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: CVEs stored, 2: how many carry a CVSS v3 vector, 3: how many are on CISA KEV, 4: how many count as exploitable. */
							__( '%1$s stored · %2$s with a CVSS v3 vector · %3$s on CISA KEV · %4$s counted as exploitable today', 'vulnhub' ),
							number_format_i18n( (int) $vh_status['cves_known'] ),
							number_format_i18n( (int) $vh_status['cves_vectored'] ),
							number_format_i18n( (int) $vh_status['cves_kev'] ),
							number_format_i18n( (int) $vh_status['cves_poc'] )
						)
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Definitions placed', 'vulnhub' ); ?></th>
				<td><?php echo esc_html( number_format_i18n( (int) $vh_status['vulns_placed'] ) ); ?></td>
			</tr>
			<?php if ( '' !== (string) $vh_status['last_error'] ) : ?>
				<tr>
					<th scope="row"><?php esc_html_e( 'Last error', 'vulnhub' ); ?></th>
					<td class="vh-bad"><?php echo esc_html( (string) $vh_status['last_error'] ); ?></td>
				</tr>
			<?php endif; ?>
		</tbody>
	</table>

	<?php if ( $vh_lanes ) : ?>
		<h3><?php esc_html_e( 'What that produces right now', 'vulnhub' ); ?></h3>
		<table class="vh-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Route', 'vulnhub' ); ?></th>
					<th scope="col" class="vh-num"><?php esc_html_e( 'Open findings', 'vulnhub' ); ?></th>
					<th scope="col" class="vh-num"><?php esc_html_e( 'Machines', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php
				foreach (
					array(
						'edge'   => __( 'Straight from the internet', 'vulnhub' ),
						'user'   => __( 'Delivered to a person', 'vulnhub' ),
						'inside' => __( 'Usable once inside', 'vulnhub' ),
					) as $vh_lane => $vh_label
				) :
					?>
					<tr>
						<td><a href="<?php echo esc_url( VulnHub_Threat_Repo::lane_url( $vh_lane ) ); ?>"><?php echo esc_html( $vh_label ); ?></a></td>
						<td class="vh-num"><?php echo esc_html( number_format_i18n( (int) $vh_lanes[ $vh_lane ]['findings'] ) ); ?></td>
						<td class="vh-num"><?php echo esc_html( number_format_i18n( (int) $vh_lanes[ $vh_lane ]['assets'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>

	<form method="post" class="vh-form">
		<?php wp_nonce_field( VulnHub_Threat_Admin::NONCE ); ?>

		<h3><?php esc_html_e( 'What counts as exploitable today', 'vulnhub' ); ?></h3>
		<p class="vh-sub"><?php esc_html_e( 'A vulnerability enters the widget only if at least one of its CVEs meets one of these. Turning all three off empties the widget.', 'vulnhub' ); ?></p>

		<fieldset class="vh-fieldset">
			<label>
				<input type="checkbox" name="poc_kev" value="1" <?php checked( in_array( 'kev', $vh_sources, true ) ); ?>>
				<?php esc_html_e( 'On CISA\'s Known Exploited Vulnerabilities catalogue — observed in real attacks', 'vulnhub' ); ?>
			</label>
			<label>
				<input type="checkbox" name="poc_refs" value="1" <?php checked( in_array( 'refs', $vh_sources, true ) ); ?>>
				<?php esc_html_e( 'NVD links to a reference it has tagged "Exploit" — public working code', 'vulnhub' ); ?>
			</label>
			<label>
				<input type="checkbox" name="poc_epss" value="1" <?php checked( in_array( 'epss', $vh_sources, true ) ); ?>>
				<?php esc_html_e( 'FIRST\'s EPSS score for today is at or above the threshold below', 'vulnhub' ); ?>
			</label>
		</fieldset>

		<p>
			<label for="vh-epss">
				<?php esc_html_e( 'EPSS threshold (% chance of exploitation in the next 30 days)', 'vulnhub' ); ?>
			</label>
			<input type="number" id="vh-epss" name="epss_min" min="0" max="100" step="0.5"
				value="<?php echo esc_attr( (string) round( VulnHub_Threat_Classify::epss_threshold() * 100, 1 ) ); ?>">
		</p>

		<h3><?php esc_html_e( 'Which assets the internet can reach', 'vulnhub' ); ?></h3>
		<p class="vh-sub">
			<?php
			esc_html_e(
				'This is what separates a theoretical number from an actionable one. Plenty of vulnerabilities are network-exploitable with no credentials, and most of them sit on laptops that nothing outside can open a connection to. Only assets matched here can appear in the "straight from the internet" lane; the rest of those findings move to the "once inside" lane, where they can genuinely be used.',
				'vulnhub'
			);
			?>
		</p>

		<fieldset class="vh-fieldset">
			<?php
			foreach (
				array(
					'servers_and_cloud' => __( 'Servers, cloud instances, and anything tagged internet-facing, dmz, public-facing, edge or perimeter (default)', 'vulnhub' ),
					'cloud_only'        => __( 'Cloud instances only', 'vulnhub' ),
					'tagged'            => __( 'Only assets carrying one of those tags — strictest, and the one to move to once tagging is trustworthy', 'vulnhub' ),
					'all'               => __( 'Every asset — assume no perimeter at all', 'vulnhub' ),
				) as $vh_key => $vh_label
			) :
				?>
				<label>
					<input type="radio" name="exposure_rule" value="<?php echo esc_attr( $vh_key ); ?>" <?php checked( $vh_rule, $vh_key ); ?>>
					<?php echo esc_html( $vh_label ); ?>
				</label>
			<?php endforeach; ?>
		</fieldset>

		<h3><?php esc_html_e( 'Other', 'vulnhub' ); ?></h3>

		<fieldset class="vh-fieldset">
			<label>
				<input type="checkbox" name="backfill" value="1" <?php checked( (bool) get_option( 'vulnhub_threat_backfill_exploit', '1' ) ); ?>>
				<?php esc_html_e( 'Write the verdict back to the scanner\'s own exploit_available column, so the impact funnel and anything else reading it stop reporting zero. A future Tenable sync carrying the real field will overwrite it, which is correct.', 'vulnhub' ); ?>
			</label>
		</fieldset>

		<p>
			<label for="vh-nvd-key"><?php esc_html_e( 'NVD API key (optional)', 'vulnhub' ); ?></label>
			<input type="password" id="vh-nvd-key" name="nvd_key" autocomplete="off"
				placeholder="<?php echo esc_attr( get_option( 'vulnhub_threat_nvd_key', '' ) ? __( '•••••• stored — leave blank to keep it', 'vulnhub' ) : __( 'not set', 'vulnhub' ) ); ?>">
			<span class="vh-sub"><?php esc_html_e( 'Only used for the fallback path, when a CVE is missing from the bulk year files. A key lifts the rate limit from 5 requests per 30 seconds to 50.', 'vulnhub' ); ?></span>
		</p>

		<p class="vh-actions">
			<button type="submit" name="vulnhub_threat_action" value="save" class="vh-btn vh-btn--primary"><?php esc_html_e( 'Save and re-place', 'vulnhub' ); ?></button>
			<button type="submit" name="vulnhub_threat_action" value="reclassify" class="vh-btn"><?php esc_html_e( 'Re-place without downloading', 'vulnhub' ); ?></button>
			<button type="submit" name="vulnhub_threat_action" value="refresh" class="vh-btn"><?php esc_html_e( 'Download the feeds again now', 'vulnhub' ); ?></button>
		</p>
	</form>

	<?php if ( ! empty( $vh_status['log'] ) && is_array( $vh_status['log'] ) ) : ?>
		<details class="vh-details">
			<summary><?php esc_html_e( 'Last run log', 'vulnhub' ); ?></summary>
			<pre class="vh-log"><?php echo esc_html( implode( "\n", array_map( 'strval', $vh_status['log'] ) ) ); ?></pre>
		</details>
	<?php endif; ?>

	<details class="vh-details">
		<summary><?php esc_html_e( 'How a vulnerability is placed on a route', 'vulnhub' ); ?></summary>
		<table class="vh-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'CVSS v3 vector says', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Route', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Because', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td><code>UI:R</code></td>
					<td><?php esc_html_e( 'Delivered to a person', 'vulnhub' ); ?></td>
					<td><?php esc_html_e( 'Somebody has to open, click or visit something. That is phishing, a malicious site, or a download — whatever the network metric says.', 'vulnhub' ); ?></td>
				</tr>
				<tr>
					<td><code>AV:N / PR:N / UI:N</code></td>
					<td><?php esc_html_e( 'Straight from the internet', 'vulnhub' ); ?></td>
					<td><?php esc_html_e( 'A listening service, no account needed and no user involved — but only counted when the asset is one the internet can reach.', 'vulnhub' ); ?></td>
				</tr>
				<tr>
					<td><code>AV:L</code>, <code>AV:A</code>, <code>AV:P</code>, <?php esc_html_e( 'or', 'vulnhub' ); ?> <code>PR:L/H</code></td>
					<td><?php esc_html_e( 'Usable once inside', 'vulnhub' ); ?></td>
					<td><?php esc_html_e( 'Needs local access, an adjacent network, or credentials the attacker must already hold. Privilege escalation and lateral movement.', 'vulnhub' ); ?></td>
				</tr>
				<tr>
					<td><?php esc_html_e( 'no v3 vector published', 'vulnhub' ); ?></td>
					<td><?php esc_html_e( 'Not placed', 'vulnhub' ); ?></td>
					<td><?php esc_html_e( 'CVSS v2 has no user-interaction or privileges metric, so there is nothing to read. Counted and reported rather than guessed at.', 'vulnhub' ); ?></td>
				</tr>
			</tbody>
		</table>
		<p class="vh-sub">
			<?php esc_html_e( 'An advisory that bundles many CVEs takes the most reachable route any one of them opens, because the patch is per-package and not per-CVE.', 'vulnhub' ); ?>
		</p>
	</details>
</div>
