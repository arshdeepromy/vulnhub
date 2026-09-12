<?php
/**
 * The dashboard widget registry.
 *
 * A security dashboard is read by people with different jobs. The person who
 * owns patching wants SLA burn-down; the person who owns the estate wants to
 * know what the scanner has never seen; the person who owns the budget wants
 * one number. Rather than guess, the dashboard is a set of widgets and each
 * operator keeps their own arrangement of them.
 *
 * A widget is data plus a way to draw it plus a way to export it. Keeping the
 * data callback separate from the render callback is what makes "download as
 * CSV" honest -- the file is built from the same rows the picture was.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Coverage;
use VulnHub\Core\Defender_Coverage;
use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Dash_Widgets {

	/** Where a person's chosen arrangement is kept. */
	public const META_KEY = 'vulnhub_dashboard_layout';

	/**
	 * Every widget id this person has ever had on their board.
	 *
	 * Kept separately from the layout so that removing a widget and never
	 * having seen one are different states. Without that distinction a new
	 * release has only two options, both wrong: never show a new widget to
	 * anybody who has arranged their board, or put back the widgets people
	 * deliberately took off.
	 */
	public const SEEN_KEY = 'vulnhub_dashboard_seen';

	/** Widths a widget can occupy on the 12-column grid. */
	public const WIDTHS = array( 3, 4, 6, 8, 12 );

	/**
	 * Every widget the dashboard knows how to draw.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function all(): array {
		static $cache = null;

		if ( null !== $cache ) {
			return $cache;
		}

		$w = array();

		/* ------------------------------------------------------- exposure. */

		$w['headline'] = array(
			'label'   => __( 'Headline figures', 'vulnhub' ),
			'summary' => __( 'Critical, past SLA, unowned workstations and failed verifications.', 'vulnhub' ),
			'group'   => 'exposure',
			'width'   => 12,
			'render'  => array( __CLASS__, 'render_headline' ),
		);

		$w['trend'] = array(
			'label'   => __( 'Open findings over time', 'vulnhub' ),
			'summary' => __( 'Daily snapshot by severity for the last 30 days.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings' ),
			'width'   => 8,
			'render'  => array( __CLASS__, 'render_trend' ),
			'data'    => array( __CLASS__, 'data_trend' ),
		);

		$w['severity_mix'] = array(
			'label'   => __( 'Findings by severity', 'vulnhub' ),
			'summary' => __( 'The shape of what is open right now.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_severity_mix' ),
			'data'    => array( __CLASS__, 'data_severity_mix' ),
		);

		$w['age_buckets'] = array(
			'label'   => __( 'Findings by age', 'vulnhub' ),
			'summary' => __( 'How long open findings have been sitting there.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_age_buckets' ),
			'data'    => array( __CLASS__, 'data_age_buckets' ),
		);

		$w['severity_age'] = array(
			'label'   => __( 'Vulnerabilities by severity and age', 'vulnhub' ),
			'summary' => __( 'Each vulnerability counted once and aged by its oldest open instance, with the asset findings behind it.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 12,
			'render'  => array( __CLASS__, 'render_severity_age' ),
			'data'    => array( __CLASS__, 'data_severity_age' ),
		);

		$w['exploit_funnel'] = array(
			'label'   => __( 'Impact funnel', 'vulnhub' ),
			'summary' => __( 'From every open finding down to the ones with a public exploit and no ticket.', 'vulnhub' ),
			'group'   => 'exposure',
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_exploit_funnel' ),
			'data'    => array( __CLASS__, 'data_exploit_funnel' ),
		);

		$w['top_vulns'] = array(
			'label'   => __( 'Most widespread vulnerabilities', 'vulnhub' ),
			'summary' => __( 'Fix these once and the number moves.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_top_vulns' ),
			'data'    => array( __CLASS__, 'data_top_vulns' ),
		);

		$w['top_assets'] = array(
			'label'   => __( 'Most exposed assets', 'vulnhub' ),
			'summary' => __( 'Highest risk score, with who to chase.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_top_assets' ),
			'data'    => array( __CLASS__, 'data_top_assets' ),
		);

		$w['os_mix'] = array(
			'label'   => __( 'Impact by operating system', 'vulnhub' ),
			'summary' => __( 'Which platforms carry the open findings.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'assets' ),
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_os_mix' ),
			'data'    => array( __CLASS__, 'data_os_mix' ),
		);

		$w['family_mix'] = array(
			'label'   => __( 'Impact by product family', 'vulnhub' ),
			'summary' => __( 'Tenable plugin families, largest first.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_family_mix' ),
			'data'    => array( __CLASS__, 'data_family_mix' ),
		);

		$w['patch_availability'] = array(
			'label'   => __( 'Patch availability by severity', 'vulnhub' ),
			'summary' => __( 'Every open finding split into the part a vendor has fixed and the part nobody has. Select either half for the list.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 6,
			'render'  => array( 'VulnHub_Dash_Patching', 'render' ),
			'data'    => array( 'VulnHub_Dash_Patching', 'data' ),
		);

		/* ----------------------------------------------------- lifecycle. */

		$w['eol_platforms'] = array(
			'label'   => __( 'Platforms past end of life', 'vulnhub' ),
			'summary' => __( 'Assets in the reporting scope, by the operating system release they run, matched on build number rather than on what the inventory calls it.', 'vulnhub' ),
			'group'   => 'lifecycle',
			'depends' => array( 'assets' ),
			'width'   => 12,
			'render'  => array( 'VulnHub_Dash_Eol', 'render' ),
			'data'    => array( 'VulnHub_Dash_Eol', 'data' ),
		);

		$w['eol_software'] = array(
			'label'   => __( 'Software past end of life', 'vulnhub' ),
			'summary' => __( 'Installed software whose vendor has stopped shipping fixes, counted once per machine.', 'vulnhub' ),
			'group'   => 'lifecycle',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 6,
			'render'  => array( 'VulnHub_Dash_Eol', 'render_software' ),
			'data'    => array( 'VulnHub_Dash_Eol', 'data_software' ),
		);

		$w['eol_hardware'] = array(
			'label'   => __( 'Hardware support', 'vulnhub' ),
			'summary' => __( 'How much of the estate is still under a warranty somebody could call on.', 'vulnhub' ),
			'group'   => 'lifecycle',
			'depends' => array( 'assets' ),
			'width'   => 6,
			'render'  => array( 'VulnHub_Dash_Eol', 'render_hardware' ),
		);

		/* ------------------------------------------------------- coverage. */

		$w['coverage_summary'] = array(
			'label'   => __( 'Tenable coverage', 'vulnhub' ),
			'summary' => __( 'How much of the estate Tenable has actually scanned.', 'vulnhub' ),
			'group'   => 'coverage',
			'depends' => array( 'coverage', 'assets' ),
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_coverage_summary' ),
			'data'    => array( __CLASS__, 'data_coverage_summary' ),
		);

		$w['coverage_by_type'] = array(
			'label'   => __( 'Tenable coverage by device type', 'vulnhub' ),
			'summary' => __( 'Where Tenable is not looking.', 'vulnhub' ),
			'group'   => 'coverage',
			'depends' => array( 'coverage', 'assets' ),
			'width'   => 8,
			'render'  => array( __CLASS__, 'render_coverage_by_type' ),
			'data'    => array( __CLASS__, 'data_coverage_by_type' ),
		);

		$w['coverage_by_site'] = array(
			'label'   => __( 'Tenable coverage by site', 'vulnhub' ),
			'summary' => __( 'Tenable coverage per location, worst first.', 'vulnhub' ),
			'group'   => 'coverage',
			'depends' => array( 'coverage', 'assets' ),
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_coverage_by_site' ),
			'data'    => array( __CLASS__, 'data_coverage_by_site' ),
		);

		$w['coverage_by_source'] = array(
			'label'   => __( 'Tenable coverage by source system', 'vulnhub' ),
			/*
			 * The arithmetic in this line has to match the table under it.
			 * It read "covered + gaps + out of scope = total" from when the
			 * total was the whole population; the total became the in-scope
			 * count and the sentence did not follow, so the widget spent a
			 * while telling readers to add a column that is no longer there.
			 */
			'summary' => __( 'Which systems say an asset exists, and whether Tenable has a record of it. Covered + gaps = total. An asset three systems know is counted three times.', 'vulnhub' ),
			'group'   => 'coverage',
			'depends' => array( 'coverage', 'assets' ),
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_coverage_by_source' ),
			'data'    => array( __CLASS__, 'data_coverage_by_source' ),
		);

		$w['coverage_gaps'] = array(
			'label'   => __( 'Tenable gap list', 'vulnhub' ),
			'summary' => __( 'Assets the CMDB or Intune knows about that Tenable does not.', 'vulnhub' ),
			'group'   => 'coverage',
			'depends' => array( 'coverage', 'assets' ),
			'width'   => 12,
			'render'  => array( __CLASS__, 'render_coverage_gaps' ),
			'data'    => array( __CLASS__, 'data_coverage_gaps' ),
		);

		$w['downloads_zone'] = array(
			'label'   => __( 'Vulnerable software in Downloads folders', 'vulnhub' ),
			'summary' => __( 'Open findings whose vulnerable files sit in a user download folder, split by platform.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_downloads_zone' ),
			'data'    => array( __CLASS__, 'data_downloads_zone' ),
		);

		/* ---------------------------------------------- endpoint coverage. */

		$w['defender_summary'] = array(
			'label'   => __( 'Defender coverage', 'vulnhub' ),
			'summary' => __( 'How much of the estate has a Defender sensor on it.', 'vulnhub' ),
			'group'   => 'endpoint',
			'depends' => array( 'defender', 'assets' ),
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_defender_summary' ),
			'data'    => array( __CLASS__, 'data_defender_summary' ),
		);

		$w['defender_by_type'] = array(
			'label'   => __( 'Defender coverage by device type', 'vulnhub' ),
			'summary' => __( 'Where the Defender sensor is not installed.', 'vulnhub' ),
			'group'   => 'endpoint',
			'depends' => array( 'defender', 'assets' ),
			'width'   => 8,
			'render'  => array( __CLASS__, 'render_defender_by_type' ),
			'data'    => array( __CLASS__, 'data_defender_by_type' ),
		);

		$w['defender_by_source'] = array(
			'label'   => __( 'Defender coverage by source system', 'vulnhub' ),
			'summary' => __( 'Which systems say an asset exists, and whether Defender has onboarded it. Covered + gaps = total. An asset three systems know is counted three times.', 'vulnhub' ),
			'group'   => 'endpoint',
			'depends' => array( 'defender', 'assets' ),
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_defender_by_source' ),
			'data'    => array( __CLASS__, 'data_defender_by_source' ),
		);

		$w['defender_cmdb'] = array(
			'label'   => __( 'Defender coverage of the CMDB', 'vulnhub' ),
			'summary' => __( 'Of the assets the CMDB says exist, how many have a Defender sensor.', 'vulnhub' ),
			'group'   => 'endpoint',
			'depends' => array( 'defender', 'assets' ),
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_defender_cmdb' ),
			'data'    => array( __CLASS__, 'data_defender_cmdb' ),
		);

		$w['defender_gaps_cmdb'] = array(
			'label'   => __( 'Defender gaps in the CMDB register', 'vulnhub' ),
			'summary' => __( 'Assets the CMDB says exist that have no Defender sensor reporting.', 'vulnhub' ),
			'group'   => 'endpoint',
			'depends' => array( 'defender', 'assets' ),
			'width'   => 12,
			'render'  => array( __CLASS__, 'render_defender_gaps_cmdb' ),
			'data'    => array( __CLASS__, 'data_defender_gaps_cmdb' ),
		);

		$w['defender_gaps'] = array(
			'label'   => __( 'Defender gap list', 'vulnhub' ),
			'summary' => __( 'In-scope assets with no Defender sensor reporting.', 'vulnhub' ),
			'group'   => 'endpoint',
			'depends' => array( 'defender', 'assets' ),
			'width'   => 12,
			'render'  => array( __CLASS__, 'render_defender_gaps' ),
			'data'    => array( __CLASS__, 'data_defender_gaps' ),
		);

		$w['coverage_cmdb'] = array(
			'label'   => __( 'Tenable coverage of the CMDB', 'vulnhub' ),
			'summary' => __( 'Of the assets the CMDB says exist, how many Tenable has a record of.', 'vulnhub' ),
			'group'   => 'coverage',
			'depends' => array( 'coverage', 'assets' ),
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_coverage_cmdb' ),
			'data'    => array( __CLASS__, 'data_coverage_cmdb' ),
		);

		$w['coverage_gaps_cmdb'] = array(
			'label'   => __( 'Tenable gaps in the CMDB register', 'vulnhub' ),
			'summary' => __( 'Assets the CMDB says exist that Tenable has no record of.', 'vulnhub' ),
			'group'   => 'coverage',
			'depends' => array( 'coverage', 'assets' ),
			'width'   => 12,
			'render'  => array( __CLASS__, 'render_coverage_gaps_cmdb' ),
			'data'    => array( __CLASS__, 'data_coverage_gaps_cmdb' ),
		);

		/* ------------------------------------------------------ ownership. */

		$w['team_exposure'] = array(
			'label'   => __( 'Exposure by team', 'vulnhub' ),
			'summary' => __( 'Who currently carries the open findings.', 'vulnhub' ),
			'group'   => 'ownership',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_team_exposure' ),
			'data'    => array( __CLASS__, 'data_team_exposure' ),
		);

		$w['ownership_gaps'] = array(
			'label'   => __( 'Ownership gaps', 'vulnhub' ),
			'summary' => __( 'Workstations and mobiles with nobody to chase.', 'vulnhub' ),
			'group'   => 'ownership',
			'depends' => array( 'assets' ),
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_ownership_gaps' ),
			'data'    => array( __CLASS__, 'data_ownership_gaps' ),
		);

		$w['assets_by_type'] = array(
			'label'   => __( 'Estate by device type', 'vulnhub' ),
			'summary' => __( 'What the fleet in the reporting scope is made of.', 'vulnhub' ),
			'group'   => 'ownership',
			'depends' => array( 'assets' ),
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_assets_by_type' ),
			'data'    => array( __CLASS__, 'data_assets_by_type' ),
		);

		$w['product_exposure'] = array(
			'label'   => __( 'Exposure by product', 'vulnhub' ),
			'summary' => __( 'Which apps, libraries and OS updates put the most assets at risk. Fix the top rows and the number moves fastest.', 'vulnhub' ),
			'group'   => 'exposure',
			'depends' => array( 'findings', 'assets' ),
			'width'   => 12,
			'render'  => array( __CLASS__, 'render_product_exposure' ),
			'data'    => array( __CLASS__, 'data_product_exposure' ),
		);

		/* ---------------------------------------------------- remediation. */

		$w['remediation_health'] = array(
			'label'   => __( 'Remediation health', 'vulnhub' ),
			'summary' => __( 'SLA attainment, ownership and verification in one place.', 'vulnhub' ),
			'group'   => 'remediation',
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_remediation_health' ),
			'data'    => array( __CLASS__, 'data_remediation_health' ),
		);

		$w['verification'] = array(
			'label'   => __( 'Closure verification', 'vulnhub' ),
			'summary' => __( 'What happened when we re-checked tickets Jira called done.', 'vulnhub' ),
			'group'   => 'remediation',
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_verification' ),
			'data'    => array( __CLASS__, 'data_verification' ),
		);

		$w['ticket_flow'] = array(
			'label'   => __( 'Ticket flow', 'vulnhub' ),
			'summary' => __( 'Open versus done, by status category.', 'vulnhub' ),
			'group'   => 'remediation',
			'depends' => array( 'tickets' ),
			'width'   => 4,
			'render'  => array( __CLASS__, 'render_ticket_flow' ),
			'data'    => array( __CLASS__, 'data_ticket_flow' ),
		);

		$w['exceptions_expiring'] = array(
			'label'   => __( 'Exceptions expiring', 'vulnhub' ),
			'summary' => __( 'Risk acceptances about to run out.', 'vulnhub' ),
			'group'   => 'remediation',
			'width'   => 6,
			'render'  => array( __CLASS__, 'render_exceptions_expiring' ),
			'data'    => array( __CLASS__, 'data_exceptions_expiring' ),
		);

		/**
		 * Filters the dashboard widget registry.
		 *
		 * @param array<string,array<string,mixed>> $w Widget definitions.
		 */
		$cache = (array) apply_filters( 'vulnhub_dashboard_widgets', $w );

		return $cache;
	}

	/**
	 * Widget groups, in the order the picker lists them.
	 *
	 * @return array<string,string>
	 */
	public static function groups(): array {
		return array(
			'exposure'    => __( 'Exposure', 'vulnhub' ),
			'lifecycle'   => __( 'End of life', 'vulnhub' ),
			/*
			 * Both groups name their feed. "Scanning coverage" and "Endpoint
			 * coverage" read as two views of one number until you notice the
			 * denominators differ, and a reader comparing 60% against 80%
			 * has no way to tell they are measuring different tools.
			 */
			'coverage'    => __( 'Tenable coverage', 'vulnhub' ),
			'endpoint'    => __( 'Defender coverage', 'vulnhub' ),
			'ownership'   => __( 'Ownership', 'vulnhub' ),
			'remediation' => __( 'Remediation', 'vulnhub' ),
		);
	}

	/* =================================================================
	 * Layout
	 * ============================================================== */

	/**
	 * What a new operator sees before they arrange anything.
	 *
	 * @return array<int,array{id:string,width:int}>
	 */
	public static function default_layout(): array {
		$default = array(
			array( 'id' => 'headline', 'width' => 12 ),
			array( 'id' => 'severity_age', 'width' => 12 ),
			array( 'id' => 'product_exposure', 'width' => 12 ),
			array( 'id' => 'trend', 'width' => 8 ),
			array( 'id' => 'severity_mix', 'width' => 4 ),
			/*
			 * Directly under the severity split, because it is the follow-up
			 * question to it: of those criticals, how many can anybody
			 * actually do something about?
			 */
			array( 'id' => 'patch_availability', 'width' => 6 ),
			/*
			 * Next to patch availability, because it is the same question from
			 * the other end: software in a download folder has no patch route
			 * at all -- no packaging system knows it is there, so nothing will
			 * ever update it.
			 */
			array( 'id' => 'downloads_zone', 'width' => 6 ),
			array( 'id' => 'eol_platforms', 'width' => 12 ),
			array( 'id' => 'coverage_summary', 'width' => 4 ),
			array( 'id' => 'coverage_cmdb', 'width' => 4 ),
			array( 'id' => 'defender_cmdb', 'width' => 4 ),
			array( 'id' => 'coverage_by_type', 'width' => 8 ),
			// Beside the coverage charts because it answers their first
			// follow-up question: this gap -- who says the machine exists?
			array( 'id' => 'coverage_by_source', 'width' => 6 ),
			/*
			 * Endpoint coverage sits directly under scanning coverage, not in
			 * a section of its own. They are two answers to the same question
			 * -- is anything watching this machine -- and a reader who sees
			 * only one of them draws the wrong conclusion from it.
			 */
			array( 'id' => 'defender_summary', 'width' => 4 ),
			array( 'id' => 'defender_by_type', 'width' => 8 ),
			array( 'id' => 'age_buckets', 'width' => 6 ),
			array( 'id' => 'exploit_funnel', 'width' => 6 ),
			array( 'id' => 'team_exposure', 'width' => 6 ),
			array( 'id' => 'ownership_gaps', 'width' => 6 ),
			array( 'id' => 'top_vulns', 'width' => 6 ),
			array( 'id' => 'top_assets', 'width' => 6 ),
			array( 'id' => 'remediation_health', 'width' => 4 ),
			array( 'id' => 'verification', 'width' => 4 ),
			array( 'id' => 'ticket_flow', 'width' => 4 ),
			/*
			 * The register-anchored lists lead, and the unrestricted ones sit
			 * below them. Somebody opening the dashboard wants the gaps they
			 * can hand to a team this morning, not the discovery backlog.
			 */
			array( 'id' => 'coverage_gaps_cmdb', 'width' => 12 ),
			array( 'id' => 'defender_gaps_cmdb', 'width' => 12 ),
			array( 'id' => 'coverage_gaps', 'width' => 12 ),
		);

		/**
		 * Filters the dashboard shown to someone who has not customised it.
		 *
		 * @param array<int,array{id:string,width:int}> $default Layout.
		 */
		return (array) apply_filters( 'vulnhub_dashboard_default_layout', $default );
	}

	/**
	 * The current person's arrangement, falling back to the default.
	 *
	 * @return array<int,array{id:string,width:int}>
	 */
	public static function layout( int $user_id = 0 ): array {
		$user_id = $user_id ?: get_current_user_id();
		$stored  = $user_id ? get_user_meta( $user_id, self::META_KEY, true ) : '';

		if ( ! is_array( $stored ) || ! $stored ) {
			return self::default_layout();
		}

		return self::with_new_widgets( self::sanitise_layout( $stored ), $user_id );
	}

	/**
	 * Append widgets this person has never had the chance to see.
	 *
	 * A widget shipped after somebody arranged their board is invisible to
	 * them for ever otherwise, which makes half of every release pointless
	 * for exactly the people who use the product most. So: anything in the
	 * default layout that is neither on their board nor in their seen list
	 * is added once, at the end, at its own default width. Take it off and
	 * it stays off -- saving the layout records it as seen.
	 *
	 * @param array<int,array{id:string,width:int}> $layout Saved layout.
	 * @return array<int,array{id:string,width:int}>
	 */
	private static function with_new_widgets( array $layout, int $user_id ): array {
		if ( ! $user_id ) {
			return $layout;
		}

		$seen = get_user_meta( $user_id, self::SEEN_KEY, true );
		$seen = is_array( $seen ) ? $seen : array();

		$have = array_column( $layout, 'id' );
		$know = array_unique( array_merge( $have, $seen ) );
		$all  = self::all();
		$new  = array();

		foreach ( self::default_layout() as $item ) {
			$id = (string) $item['id'];

			if ( in_array( $id, $know, true ) || ! isset( $all[ $id ] ) ) {
				continue;
			}

			$new[] = $item;
		}

		if ( ! $new ) {
			return $layout;
		}

		$merged = array_merge( $layout, $new );

		/*
		 * Written back, not just returned. Recording the widget as seen
		 * without adding it to the stored board made it appear on exactly
		 * one page load and then vanish for ever -- which is worse than
		 * never showing it, because the person saw it and cannot find it
		 * again. It is on their board now, and taking it off will stick.
		 */
		update_user_meta( $user_id, self::META_KEY, $merged );
		update_user_meta( $user_id, self::SEEN_KEY, array_values( array_unique( array_merge( $know, array_column( $new, 'id' ) ) ) ) );

		return $merged;
	}

	/**
	 * Keep only widgets that exist and widths the grid understands.
	 *
	 * @param array<int,mixed> $raw Untrusted layout.
	 * @return array<int,array{id:string,width:int}>
	 */
	public static function sanitise_layout( array $raw ): array {
		$known = self::all();
		$out   = array();
		$seen  = array();

		foreach ( $raw as $item ) {
			$id = is_array( $item ) ? (string) ( $item['id'] ?? '' ) : (string) $item;
			$id = sanitize_key( $id );

			if ( '' === $id || ! isset( $known[ $id ] ) || isset( $seen[ $id ] ) ) {
				continue;
			}

			$width = is_array( $item ) ? (int) ( $item['width'] ?? 0 ) : 0;
			$width = in_array( $width, self::WIDTHS, true ) ? $width : (int) $known[ $id ]['width'];

			$out[]        = array( 'id' => $id, 'width' => $width );
			$seen[ $id ] = true;
		}

		return $out;
	}

	public static function save_layout( array $layout, int $user_id = 0 ): bool {
		$user_id = $user_id ?: get_current_user_id();

		if ( ! $user_id ) {
			return false;
		}

		$clean = self::sanitise_layout( $layout );

		// Anything on the board when it was saved has been seen, whether it
		// was kept or is about to be removed on the next save.
		$seen = get_user_meta( $user_id, self::SEEN_KEY, true );
		$seen = is_array( $seen ) ? $seen : array();

		update_user_meta(
			$user_id,
			self::SEEN_KEY,
			array_values( array_unique( array_merge( $seen, array_column( $clean, 'id' ), array_column( self::default_layout(), 'id' ) ) ) )
		);

		return (bool) update_user_meta( $user_id, self::META_KEY, $clean );
	}

	public static function reset_layout( int $user_id = 0 ): void {
		$user_id = $user_id ?: get_current_user_id();

		if ( $user_id ) {
			delete_user_meta( $user_id, self::META_KEY );
			delete_user_meta( $user_id, self::SEEN_KEY );
		}
	}

	/* =================================================================
	 * Render
	 * ============================================================== */

	/**
	 * A stamp that changes whenever the numbers could have changed.
	 *
	 * Cached widget markup keys off this, so a sync, an import or a coverage
	 * recalculation invalidates every widget at once and nobody has to
	 * remember which widget reads which table.
	 */
	public static function epoch(): string {
		$epoch = get_option( 'vulnhub_widget_epoch', '' );

		if ( ! $epoch ) {
			$epoch = '1';
			update_option( 'vulnhub_widget_epoch', $epoch, false );
		}

		return (string) $epoch;
	}

	/**
	 * The data a widget's numbers come from.
	 *
	 * One global epoch meant a Defender sync threw away the Tenable widgets
	 * and the whole board had to be rebuilt -- 2.3s of cron time for a change
	 * that moved four numbers. A widget keyed on its own sources is only
	 * rebuilt when one of them actually moves.
	 *
	 * A widget that declares nothing depends on everything. That is the old
	 * behaviour, and it is the safe default: under-declaring a dependency
	 * produces a widget that silently stops updating, which is a worse bug
	 * than rebuilding something that did not need it.
	 *
	 * @return array<int,string>
	 */
	public static function sources(): array {
		return array( 'findings', 'assets', 'coverage', 'defender', 'tickets', 'threat' );
	}

	/**
	 * Which sources each connector moves.
	 *
	 * @return array<string,array<int,string>>
	 */
	public static function connector_sources(): array {
		return (array) apply_filters(
			'vulnhub_widget_connector_sources',
			array(
				'tenable'  => array( 'findings', 'assets', 'coverage' ),
				'intune'   => array( 'assets', 'coverage' ),
				'defender' => array( 'defender', 'assets', 'coverage' ),
				'cmdb'     => array( 'assets' ),
				'jira'     => array( 'tickets' ),
				'threat'   => array( 'threat', 'findings' ),
				'alerts'   => array( 'threat' ),
			)
		);
	}

	/**
	 * One source's stamp.
	 *
	 * A counter, not a timestamp, and it does not fall back to the global
	 * stamp. Both of those were bugs: with second-resolution timestamps, two
	 * busts inside the same second produced the same stamp and the second one
	 * invalidated nothing -- and a sync finishing in the same second as
	 * anything else is not a rare case, it is a Tuesday. Falling back to the
	 * global stamp made it worse, because the global had just been set to the
	 * same time() value.
	 */
	public static function source_epoch( string $source ): string {
		$all = (array) get_option( 'vulnhub_widget_epochs', array() );

		return (string) ( $all[ $source ] ?? '0' );
	}

	/**
	 * The composite stamp for one widget: its own sources, in a fixed order.
	 */
	public static function widget_epoch( string $id ): string {
		$all  = self::all();
		$deps = (array) ( $all[ $id ]['depends'] ?? array() );

		// Nothing declared: depends on everything, which is the global stamp.
		if ( ! $deps ) {
			return self::epoch();
		}

		sort( $deps );
		$parts = array( self::epoch_floor() );

		foreach ( $deps as $dep ) {
			$parts[] = $dep . ':' . self::source_epoch( (string) $dep );
		}

		return md5( implode( '|', $parts ) );
	}

	/**
	 * A stamp bumped only by things no per-source list covers.
	 *
	 * A deploy, a settings change, a manual bust from the admin screen: these
	 * can change any widget's output and belong to no data source, so they
	 * have to invalidate widgets that declare their dependencies too.
	 */
	public static function epoch_floor(): string {
		return (string) get_option( 'vulnhub_widget_floor', '0' );
	}

	/** Bump a counter option and return the new value. */
	private static function tick( string $option ): string {
		$next = (string) ( (int) get_option( $option, '0' ) + 1 );
		update_option( $option, $next, false );

		return $next;
	}

	/**
	 * Invalidate everything, or just the widgets fed by one source.
	 *
	 * Called with no argument from the admin screens and from anything whose
	 * blast radius is not known, which is the safe reading.
	 */
	public static function bust( string $source = '' ): void {
		self::tick( 'vulnhub_widget_epoch' );

		if ( '' === $source ) {
			// Nothing is trusted: move the floor, which is in every key.
			self::tick( 'vulnhub_widget_floor' );
			return;
		}

		$all            = (array) get_option( 'vulnhub_widget_epochs', array() );
		$all[ $source ] = (string) ( (int) ( $all[ $source ] ?? '0' ) + 1 );
		update_option( 'vulnhub_widget_epochs', $all, false );
	}

	/**
	 * Invalidate the sources a finished connector sync actually moved.
	 *
	 * @param string $connector Connector id.
	 */
	public static function bust_for_connector( string $connector = '' ): void {
		$map = self::connector_sources();

		// An unknown connector could have moved anything.
		if ( '' === $connector || ! isset( $map[ $connector ] ) ) {
			self::bust();
			return;
		}

		foreach ( (array) $map[ $connector ] as $source ) {
			self::bust( (string) $source );
		}
	}

	/**
	 * How long rendered widget markup may be reused.
	 *
	 * A security dashboard is not a live trading screen: the underlying data
	 * changes when a connector runs, not between two page loads. Fifteen
	 * widgets each running their own aggregate over 425,289 findings costs
	 * about 1.7 s cold, and nothing about that is worth paying twice.
	 */
	public static function ttl(): int {
		return (int) apply_filters( 'vulnhub_widget_cache_ttl', 15 * MINUTE_IN_SECONDS );
	}

	/**
	 * How long a *stale* copy may still be served while a refresh is queued.
	 *
	 * Deliberately much longer than ttl(). These two numbers do different
	 * jobs: ttl() decides when markup stops being trusted, this decides how
	 * long it stays better than nothing. Serving numbers a few minutes old
	 * beats making somebody wait 3.5 seconds for numbers a few seconds old,
	 * and a dashboard nobody has opened for six hours can afford to render
	 * once.
	 */
	public static function stale_ttl(): int {
		return (int) apply_filters( 'vulnhub_widget_stale_ttl', 6 * HOUR_IN_SECONDS );
	}

	/** Hook that renders one widget in the background. */
	public const HOOK_REFRESH = 'vulnhub_widget_refresh';

	/** Hook that re-renders the whole board in the background. */
	public const HOOK_WARM = 'vulnhub_widget_warm';

	/** Hosts a board has been rendered for, so a cron warm can target them. */
	public const HOSTS_KEY = 'vulnhub_widget_hosts';

	/** What the last warm did, so a stalled cron shows up as stale numbers. */
	public const WARM_KEY = 'vulnhub_widget_warm_state';

	/**
	 * Remember a host we have served a board for.
	 *
	 * A cron process has no request host, so a warm has to be told which ones
	 * to render for -- this stack answers on localhost and on whatever public
	 * hostname it is published under, and widget markup carries absolute
	 * links built from whichever one asked. Bounded to four so a spoofed Host
	 * header cannot turn this into an unbounded list of render targets.
	 */
	private static function remember_host(): void {
		$host  = home_url();
		$hosts = (array) get_option( self::HOSTS_KEY, array() );

		if ( in_array( $host, $hosts, true ) ) {
			return;
		}

		$hosts[] = $host;
		update_option( self::HOSTS_KEY, array_slice( $hosts, -4 ), false );
	}

	/**
	 * Queue a whole-board warm, at most one in flight.
	 *
	 * Called after anything that busts the cache. The point is that the
	 * re-render happens on cron rather than in front of whoever opens the
	 * dashboard next -- serve-stale already means they do not wait, and this
	 * means they do not get stale numbers for long either.
	 */
	public static function queue_warm(): void {
		if ( false !== get_transient( 'vh_warm_lock' ) ) {
			return;
		}

		set_transient( 'vh_warm_lock', 1, 2 * MINUTE_IN_SECONDS );
		wp_schedule_single_event( time(), self::HOOK_WARM );
	}

	/**
	 * Re-render every widget on the default board, for every host we serve.
	 *
	 * Renders the union of the default layout and whatever is actually on
	 * people's boards, so a widget somebody added by hand is warmed too.
	 * Measured at ~2.3s for 28 widgets, which is one cron tick.
	 */
	public static function warm(): void {
		$started = microtime( true );
		$hosts   = (array) get_option( self::HOSTS_KEY, array() );

		if ( ! $hosts ) {
			$hosts = array( home_url() );
		}

		$ids = array_column( self::default_layout(), 'id' );

		/*
		 * Anything anybody has on a board, not just the default set. A widget
		 * that only one person added is exactly the one that would otherwise
		 * always be rendered on the request path.
		 */
		foreach ( self::boards_in_use() as $extra ) {
			if ( ! in_array( $extra, $ids, true ) ) {
				$ids[] = $extra;
			}
		}

		$done = 0;
		foreach ( $hosts as $host ) {
			foreach ( $ids as $id ) {
				self::refresh( (string) $id, (string) $host );
				++$done;
			}
		}

		update_option(
			self::WARM_KEY,
			array(
				'at'      => time(),
				'widgets' => $done,
				'hosts'   => count( $hosts ),
				'seconds' => round( microtime( true ) - $started, 2 ),
				'epoch'   => self::epoch(),
			),
			false
		);

		delete_transient( 'vh_warm_lock' );
	}

	/**
	 * Every widget id anybody currently has on a board.
	 *
	 * @return array<int,string>
	 */
	private static function boards_in_use(): array {
		global $wpdb;

		$rows = (array) $wpdb->get_col(
			$wpdb->prepare(
				"SELECT meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s LIMIT 200",
				self::META_KEY
			)
		);

		$ids = array();
		foreach ( $rows as $raw ) {
			$layout = maybe_unserialize( $raw );
			if ( ! is_array( $layout ) ) {
				continue;
			}
			foreach ( $layout as $item ) {
				if ( isset( $item['id'] ) ) {
					$ids[ (string) $item['id'] ] = true;
				}
			}
		}

		return array_keys( $ids );
	}

	/**
	 * How stale the warmed cache is, for the admin portal.
	 *
	 * The whole plan makes cron responsible for dashboard latency rather than
	 * only for scheduled syncs, so a cron loop that has quietly stopped has
	 * to be visible as something other than nothing at all.
	 *
	 * @return array{at:int,age:int,widgets:int,seconds:float,current:bool}
	 */
	public static function warm_state(): array {
		$state = (array) get_option( self::WARM_KEY, array() );
		$at    = (int) ( $state['at'] ?? 0 );

		return array(
			'at'      => $at,
			'age'     => $at ? time() - $at : 0,
			'widgets' => (int) ( $state['widgets'] ?? 0 ),
			'seconds' => (float) ( $state['seconds'] ?? 0 ),
			'current' => (string) ( $state['epoch'] ?? '' ) === self::epoch(),
		);
	}

	/**
	 * Queue a background re-render, at most one in flight per widget.
	 *
	 * The host travels with the job. Widget markup contains absolute links
	 * built from home_url(), and wp-config derives that from the request --
	 * so a cron process, which has no request host and falls back to the
	 * siteurl row, would otherwise re-render the localhost copy full of
	 * public-hostname links. That is the same trap the cache key documents
	 * above; this is the write side of it.
	 */
	private static function queue_refresh( string $id ): void {
		$lock = 'vh_wref_' . md5( $id . '|' . home_url() );

		// A dashboard draws 28 widgets at once. Without the lock, one stale
		// board would queue 28 jobs, and a reload before cron runs would
		// queue 28 more.
		if ( false !== get_transient( $lock ) ) {
			return;
		}

		set_transient( $lock, 1, 5 * MINUTE_IN_SECONDS );
		wp_schedule_single_event( time(), self::HOOK_REFRESH, array( $id, home_url() ) );
	}

	/**
	 * Re-render one widget into the cache, for the given host.
	 *
	 * Runs on cron, so it has to put the host back before rendering: see
	 * queue_refresh().
	 */
	public static function refresh( string $id, string $host = '' ): void {
		$all = self::all();

		if ( ! isset( $all[ $id ] ) || ! is_callable( $all[ $id ]['render'] ) ) {
			return;
		}

		$filter = static fn(): string => $host;

		if ( '' !== $host ) {
			add_filter( 'pre_option_home', $filter );
			add_filter( 'pre_option_siteurl', $filter );
		}

		ob_start();
		call_user_func( $all[ $id ]['render'] );
		$html = (string) ob_get_clean();

		/*
		 * Stored while the filters are still on: store() builds the key from
		 * home_url(), so dropping them first writes the entry under the
		 * rendering process's own host instead of the one it was rendered
		 * for -- which looks exactly like the warm doing nothing.
		 */
		self::store( $id, self::rehost( $html, $host ) );

		if ( '' !== $host ) {
			remove_filter( 'pre_option_home', $filter );
			remove_filter( 'pre_option_siteurl', $filter );
		}

		delete_transient( 'vh_wref_' . md5( $id . '|' . ( '' !== $host ? $host : home_url() ) ) );
	}

	/**
	 * Point every absolute URL in rendered markup at the host it is for.
	 *
	 * The option filters in refresh() fix anything built from home_url() --
	 * which is the links -- and cannot fix asset URLs at all, because
	 * VULNHUB_DASH_URL is a constant assigned from plugin_dir_url() when the
	 * plugin file loads, long before any filter exists. In a cron process that
	 * resolves to the siteurl row, so a localhost board came back with its
	 * product icons pointed at the public hostname and every one of them
	 * failed to load.
	 *
	 * So the origin is rewritten in the finished string. It catches the
	 * constant, anything else baked at load, and the links as well. Both
	 * schemes are matched because plugin_dir_url() runs set_url_scheme() and
	 * a CLI process is never is_ssl(), so the constant can hold http:// for a
	 * site whose stored URL is https://.
	 */
	private static function rehost( string $html, string $host ): string {
		if ( '' === $host || '' === $html ) {
			return $html;
		}

		$target = untrailingslashit( $host );
		$from   = wp_parse_url( VULNHUB_DASH_URL, PHP_URL_HOST );

		if ( ! $from || $from === wp_parse_url( $target, PHP_URL_HOST ) ) {
			return $html;
		}

		$port = wp_parse_url( VULNHUB_DASH_URL, PHP_URL_PORT );
		$from = $from . ( $port ? ':' . $port : '' );

		return str_replace(
			array( 'https://' . $from, 'http://' . $from ),
			array( $target, $target ),
			$html
		);
	}

	/** The cache key for one widget. See the host note above. */
	private static function cache_key( string $id ): string {
		return 'vh_w_' . md5( $id . '|' . get_locale() . '|' . home_url() );
	}

	/** Write rendered markup, stamped with the epoch it was true for. */
	private static function store( string $id, string $html ): void {
		set_transient(
			self::cache_key( $id ),
			array(
				'html'        => $html,
				'epoch'       => self::widget_epoch( $id ),
				'fresh_until' => time() + self::ttl(),
			),
			self::stale_ttl()
		);
	}

	/**
	 * The cached markup of a widget belongs to the host that rendered it.
	 *
	 * This stack derives WP_HOME from the request host so the same install
	 * answers on `localhost:8093` and on the public domain behind the
	 * Cloudflare tunnel. Widget HTML contains absolute links built from
	 * that, and the cache key did not mention the host -- so whichever host
	 * rendered a widget first served its links to the other, and a reader
	 * on the public site clicked through to `localhost`. WP-CLI and cron
	 * are worse again: they have no request host at all and fall back to
	 * the stored option.
	 *
	 * Naming the host in the key is the whole fix. It is cheap -- the
	 * caches simply do not collide any more -- and it cannot drift, because
	 * it asks the same function the links themselves are built from.
	 */

	/**
	 * Draw one widget inside its frame.
	 */
	public static function render( string $id, int $width ): void {
		$all = self::all();
		$def = $all[ $id ] ?? null;

		if ( ! $def || ! is_callable( $def['render'] ) ) {
			return;
		}

		$width = in_array( $width, self::WIDTHS, true ) ? $width : (int) $def['width'];

		/*
		 * The body is rendered before the header so the export menu can
		 * tell the truth. "Download PNG" and "Download SVG" work by
		 * serialising an <svg> out of the widget, and half of these widgets
		 * draw bars and tables with no SVG in them at all -- on those, both
		 * buttons were offered and both did nothing when pressed. A widget
		 * can only offer what it actually contains.
		 */
		/*
		 * Serve what we have, then refresh behind the reader.
		 *
		 * The epoch used to be part of the key, which meant every bust() was
		 * a hard miss: a connector sync finishes, the keys all change, and
		 * the next person to open the dashboard rebuilds 28 widgets and
		 * waits 3.5 seconds for the privilege. Since syncs run on a
		 * schedule, that was happening several times a day to whoever
		 * happened to be first.
		 *
		 * The epoch now travels inside the entry instead. A bust no longer
		 * hides the markup -- it marks it stale, so the reader still gets an
		 * answer immediately and cron re-renders it within the minute. The
		 * only person who ever renders a widget on the request path is the
		 * first one after a deploy.
		 */
		self::remember_host();

		$ttl   = self::ttl();
		$key   = self::cache_key( $id );
		$entry = $ttl > 0 ? get_transient( $key ) : false;
		$html  = null;

		if ( is_array( $entry ) && isset( $entry['html'] ) ) {
			$html = (string) $entry['html'];

			$stale = (string) ( $entry['epoch'] ?? '' ) !== self::widget_epoch( $id )
				|| (int) ( $entry['fresh_until'] ?? 0 ) < time();

			if ( $stale ) {
				self::queue_refresh( $id );
			}
		} elseif ( is_string( $entry ) && '' !== $entry ) {
			// An entry written before the payload gained its epoch. Usable
			// once, then replaced by the refresh.
			$html = $entry;
			self::queue_refresh( $id );
		}

		if ( null === $html ) {
			ob_start();
			call_user_func( $def['render'] );
			$html = (string) ob_get_clean();

			if ( $ttl > 0 ) {
				self::store( $id, $html );
			}
		}

		$has_csv   = ! empty( $def['data'] );
		$has_image = false !== stripos( (string) $html, '<svg' );
		$exports   = $has_csv || $has_image;

		printf(
			'<section class="vh-w vh-w--%1$d" data-vh-widget="%2$s" data-vh-width="%1$d" aria-label="%3$s">',
			(int) $width,
			esc_attr( $id ),
			esc_attr( (string) $def['label'] )
		);

		echo '<header class="vh-w__head">';

		/*
		 * The drag handle.
		 *
		 * Hidden until app.js unhides it: with no JavaScript the board still
		 * renders from the saved layout, and offering a grip that cannot move
		 * anything would be a lie. It is a button rather than a decorative
		 * span because reordering has to work from the keyboard too -- arrow
		 * keys move the widget, which is the only route somebody who cannot
		 * drag has.
		 */
		printf(
			'<button type="button" class="vh-w__grip" data-vh-grip hidden'
			. ' aria-label="%s" title="%s">'
			. '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" focusable="false">'
			. '<circle cx="9" cy="6" r="1.6"/><circle cx="15" cy="6" r="1.6"/>'
			. '<circle cx="9" cy="12" r="1.6"/><circle cx="15" cy="12" r="1.6"/>'
			. '<circle cx="9" cy="18" r="1.6"/><circle cx="15" cy="18" r="1.6"/>'
			. '</svg></button>',
			esc_attr(
				sprintf(
					/* translators: %s: widget name. */
					__( 'Move %s. Drag, or use the arrow keys.', 'vulnhub' ),
					(string) $def['label']
				)
			),
			esc_attr__( 'Drag to rearrange', 'vulnhub' )
		);

		echo '<div><h2>' . esc_html( (string) $def['label'] ) . '</h2>';

		if ( ! empty( $def['summary'] ) ) {
			echo '<p class="vh-sub">' . esc_html( (string) $def['summary'] ) . '</p>';
		}

		echo '</div>';

		if ( $exports ) {
			/*
			 * Every icon here carries width and height attributes, and must.
			 *
			 * An inline <svg> with only a viewBox has no intrinsic size: with
			 * no CSS to size it, it fills its container. These icons were
			 * sized solely by app-redesign.css, which the portal loads and
			 * Elementor pages do not -- so on /vulnhub-estate/ this 15px
			 * download glyph rendered at 1102x1102 and swallowed the widget.
			 *
			 * The attributes make the icon right with or without a
			 * stylesheet; CSS still overrides them where it is present.
			 */
			echo '<details class="vh-w__menu"><summary aria-label="' . esc_attr__( 'Export this widget', 'vulnhub' ) . '">'
				. '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 17v3h16v-3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>'
				. '</summary><div class="vh-w__menu-body">';

			if ( $has_image ) {
				echo '<button type="button" class="vh-w__export" data-vh-export="png">' . esc_html__( 'Download PNG', 'vulnhub' ) . '</button>'
					. '<button type="button" class="vh-w__export" data-vh-export="svg">' . esc_html__( 'Download SVG', 'vulnhub' ) . '</button>';
			}

			if ( $has_csv ) {
				echo '<a class="vh-w__export" href="' . esc_url( self::export_url( $id ) ) . '">' . esc_html__( 'Download CSV', 'vulnhub' ) . '</a>'
					. '<button type="button" class="vh-w__export" data-vh-copy="tsv">' . esc_html__( 'Copy as TSV', 'vulnhub' ) . '</button>';
			}

			echo '</div></details>';
		}

		echo '</header><div class="vh-w__body">';

		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built by the widget above.

		echo '</div></section>';
	}

	public static function export_url( string $id ): string {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => 'vulnhub_widget_csv',
					'widget' => $id,
				),
				admin_url( 'admin-post.php' )
			),
			'vulnhub_widget_csv_' . $id
		);
	}

	/**
	 * Rows for a widget's CSV, or null when it has none.
	 *
	 * @return array{headers:string[],rows:array<int,array<int,scalar>>}|null
	 */
	public static function export_data( string $id ): ?array {
		$all = self::all();
		$def = $all[ $id ] ?? null;

		if ( ! $def || empty( $def['data'] ) || ! is_callable( $def['data'] ) ) {
			return null;
		}

		$data = call_user_func( $def['data'] );

		return is_array( $data ) && isset( $data['headers'], $data['rows'] ) ? $data : null;
	}

	/* =================================================================
	 * Widgets: exposure
	 * ============================================================== */

	/**
	 * Open findings whose vulnerable files live in a user's Downloads folder.
	 *
	 * Software run out of a download folder is its own risk: nobody patches
	 * it, no packaging system knows it is there, and it usually got there
	 * because somebody needed it once. The split is by platform because the
	 * remediation differs -- a Windows workstation is a conversation with the
	 * person whose profile it is, a Linux host with whoever owns the box.
	 *
	 * A platform with nothing in it is still drawn. "Linux: 0" is a finding;
	 * a missing tile just looks like the widget forgot.
	 */
	public static function render_downloads_zone(): void {
		$counts = Repo::path_zone_platforms( 'downloads' );
		$reach  = Repo::path_zone_reach( 'downloads' );
		$enum   = Repo::path_zone_enumeration( 'downloads' );
		$total  = array_sum( $counts );

		if ( 0 === $total && 0 === $enum['findings'] ) {
			echo '<p class="vh-sub">' . esc_html__( 'No open finding has a vulnerable file in a user download folder.', 'vulnhub' ) . '</p>';
			return;
		}

		if ( 0 === $total ) {
			echo '<p class="vh-sub">' . esc_html__( 'No vulnerable software is running from a user download folder.', 'vulnhub' ) . '</p>';
		} else {
			echo '<p class="vh-sub">';
			printf(
				/* translators: 1: number of findings, 2: number of assets, 3: number of owners. */
				esc_html__( '%1$s open findings across %2$s machines, traced to %3$s named owners.', 'vulnhub' ),
				'<strong>' . esc_html( number_format_i18n( $total ) ) . '</strong>',
				esc_html( number_format_i18n( $reach['assets'] ) ),
				esc_html( number_format_i18n( $reach['owners'] ) )
			);
			echo '</p>';
		}

		echo '<div class="vh-tiles">';

		$estate = \VulnHub\Core\Os::estate_platforms();

		foreach ( $counts as $platform => $count ) {
			// Only the platforms a person runs software on.
			if ( ! in_array( $platform, array( 'windows', 'linux', 'macos' ), true ) ) {
				continue;
			}

			/*
			 * A zero is worth drawing when the estate actually has machines of
			 * that kind -- "Linux: 0" across 251 Linux hosts is the answer to
			 * the question. A platform with no assets at all is not an answer,
			 * it is a tile about nothing, so it is left out.
			 */
			if ( 0 === $count && 0 === (int) ( $estate[ $platform ] ?? 0 ) ) {
				continue;
			}

			echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				array(
					'label' => \VulnHub\Core\Os::platform_label( $platform ),
					'value' => $count,
					'tone'  => $count > 0 ? 'warning' : 'good',
					'meta'  => $count > 0
						? __( 'running from a download folder', 'vulnhub' )
						: __( 'nothing running from a download folder', 'vulnhub' ),
					'href'  => VulnHub_Dash_Portal::portal_url(
						'vulnerabilities',
						array( 'zone' => 'downloads', 'platform' => $platform, 'sev_not' => 'info' )
					),
				)
			);
		}

		echo '</div>';

		/*
		 * Below the tiles and deliberately not in them. Tenable's forensic
		 * plugins catalogue what sits in a download folder -- "User Download
		 * Folder Files" exists to list it -- and those findings quote a
		 * download path without describing any vulnerability. They are worth
		 * showing, because a machine with hundreds of files parked in
		 * Downloads is worth knowing about; they are not worth adding to an
		 * exposure count, which is what made this widget read 1,819 instead
		 * of 158.
		 */
		if ( $enum['findings'] > 0 ) {
			echo '<p class="vh-sub vh-muted">';
			printf(
				/* translators: 1: number of catalogued files, 2: number of machines. */
				esc_html__( 'Separately, Tenable has catalogued %1$s files in user download folders on %2$s machines. Those are informational listings, not vulnerabilities.', 'vulnhub' ),
				'<strong>' . esc_html( number_format_i18n( $enum['findings'] ) ) . '</strong>',
				esc_html( number_format_i18n( $enum['assets'] ) )
			);
			echo ' <a href="' . esc_url(
				VulnHub_Dash_Portal::portal_url(
					'vulnerabilities',
					array( 'zone' => 'downloads', 'severity' => 'info' )
				)
			) . '">' . esc_html__( 'See the listings', 'vulnhub' ) . '</a>';
			echo '</p>';
		}
	}

	/**
	 * CSV behind the widget.
	 *
	 * @return array<int,array<string,string|int>>
	 */
	public static function data_downloads_zone(): array {
		$rows = array();
		foreach ( Repo::path_zone_platforms( 'downloads' ) as $platform => $count ) {
			if ( ! in_array( $platform, array( 'windows', 'linux', 'macos' ), true ) ) {
				continue;
			}
			$rows[] = array(
				'platform' => \VulnHub\Core\Os::platform_label( $platform ),
				'findings' => $count,
			);
		}
		return $rows;
	}

	public static function render_headline(): void {
		$s     = Repo::summary();
		$trend = Repo::trend( array( 'open_critical', 'open_high' ), 30 );
		$cov   = Coverage::summary();

		echo '<div class="vh-tiles">';

		echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array(
				'label' => __( 'Critical open', 'vulnhub' ),
				'value' => (int) $s['critical'],
				'tone'  => (int) $s['critical'] > 0 ? 'critical' : 'good',
				'meta'  => sprintf(
					/* translators: %s: count of high severity findings. */
					__( '%s high severity alongside', 'vulnhub' ),
					number_format_i18n( (int) $s['high'] )
				),
				'spark' => array_values( $trend['open_critical'] ?? array() ),
				'href'  => VulnHub_Dash_Portal::portal_url( 'vulnerabilities', array( 'severity' => 'critical' ) ),
			)
		);

		echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array(
				'label' => __( 'Past SLA', 'vulnhub' ),
				'value' => (int) $s['overdue'],
				'tone'  => (int) $s['overdue'] > 0 ? 'serious' : 'good',
				'meta'  => __( 'beyond the agreed remediation window', 'vulnhub' ),
				'spark' => array_values( $trend['open_high'] ?? array() ),
				'href'  => VulnHub_Dash_Portal::portal_url( 'vulnerabilities', array( 'overdue' => '1' ) ),
			)
		);

		echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array(
				'label' => __( 'Not scanned by Tenable', 'vulnhub' ),
				'value' => (int) $cov['gaps'],
				'tone'  => (int) $cov['gaps'] > 0 ? 'warning' : 'good',
				'meta'  => sprintf(
					/* translators: %s: coverage percentage. */
					__( '%s%% of the in-scope estate is covered', 'vulnhub' ),
					number_format_i18n( $cov['percent'] )
				),
				'href'  => VulnHub_Dash_Portal::portal_url( 'assets', array( 'coverage' => 'gap', 'life' => 'reportable' ) ),
			)
		);

		echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array(
				'label' => __( 'Closed but still detected', 'vulnhub' ),
				'value' => (int) ( $s['verify_failed'] ?? 0 ),
				'tone'  => (int) ( $s['verify_failed'] ?? 0 ) > 0 ? 'critical' : 'good',
				'meta'  => __( 'Jira said done; Tenable disagreed', 'vulnhub' ),
				'href'  => VulnHub_Dash_Portal::portal_url( 'tickets' ),
			)
		);

		echo '</div>';
	}

	public static function render_trend(): void {
		$trend = Repo::trend( array( 'open_critical', 'open_high', 'open_medium', 'open_low' ), 30 );

		// Keep the date keys. line_chart() builds its x axis from them, so
		// array_values() here turns every label into an array index and the
		// axis tries to format 0 as a date.
		$series = array(
			__( 'Critical', 'vulnhub' ) => (array) ( $trend['open_critical'] ?? array() ),
			__( 'High', 'vulnhub' )     => (array) ( $trend['open_high'] ?? array() ),
			__( 'Medium', 'vulnhub' )   => (array) ( $trend['open_medium'] ?? array() ),
			__( 'Low', 'vulnhub' )      => (array) ( $trend['open_low'] ?? array() ),
		);

		$colours = array(
			__( 'Critical', 'vulnhub' ) => 'var(--vh-sev-critical)',
			__( 'High', 'vulnhub' )     => 'var(--vh-sev-high)',
			__( 'Medium', 'vulnhub' )   => 'var(--vh-sev-medium)',
			__( 'Low', 'vulnhub' )      => 'var(--vh-sev-low)',
		);

		echo VulnHub_Dash_Charts::line_chart( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$series,
			$colours,
			array( 'title' => __( 'Open findings over time', 'vulnhub' ) )
		);
	}

	public static function data_trend(): array {
		$trend = Repo::trend( array( 'open_critical', 'open_high', 'open_medium', 'open_low' ), 30 );
		$dates = array_keys( $trend['open_critical'] ?? array() );
		$rows  = array();

		foreach ( $dates as $date ) {
			$rows[] = array(
				$date,
				(int) ( $trend['open_critical'][ $date ] ?? 0 ),
				(int) ( $trend['open_high'][ $date ] ?? 0 ),
				(int) ( $trend['open_medium'][ $date ] ?? 0 ),
				(int) ( $trend['open_low'][ $date ] ?? 0 ),
			);
		}

		return array(
			'headers' => array( __( 'Date', 'vulnhub' ), __( 'Critical', 'vulnhub' ), __( 'High', 'vulnhub' ), __( 'Medium', 'vulnhub' ), __( 'Low', 'vulnhub' ) ),
			'rows'    => $rows,
		);
	}

	public static function render_severity_mix(): void {
		$s    = Repo::summary();
		$rows = array();

		foreach ( vh_severities() as $key => $def ) {
			$rows[] = array(
				'label' => (string) $def['label'],
				'value' => (float) ( $s[ $key ] ?? 0 ),
				'color' => 'var(--vh-sev-' . $key . ')',
			);
		}

		echo VulnHub_Dash_Charts::donut( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'centre'       => number_format_i18n( (int) $s['open_total'] ),
				'centre_label' => __( 'open', 'vulnhub' ),
				'title'        => __( 'Findings by severity', 'vulnhub' ),
			)
		);
	}

	public static function data_severity_mix(): array {
		$s    = Repo::summary();
		$rows = array();

		foreach ( vh_severities() as $key => $def ) {
			$rows[] = array( (string) $def['label'], (int) ( $s[ $key ] ?? 0 ) );
		}

		return array(
			'headers' => array( __( 'Severity', 'vulnhub' ), __( 'Open findings', 'vulnhub' ) ),
			'rows'    => $rows,
		);
	}

	/**
	 * @return array<int,array{label:string,buckets:array<string,int>}>
	 */
	private static function age_rows(): array {
		global $wpdb;

		$f    = vh_table( 'findings' );
		$rows = (array) $wpdb->get_results(
			"SELECT
				CASE
					WHEN first_found IS NULL THEN 'unknown'
					WHEN first_found >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY)  THEN '0-30'
					WHEN first_found >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 60 DAY)  THEN '31-60'
					WHEN first_found >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 90 DAY)  THEN '61-90'
					WHEN first_found >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 180 DAY) THEN '91-180'
					ELSE '180+'
				END AS bucket,
				severity,
				COUNT(*) AS n
			 FROM {$f}
			 WHERE state IN ('open','reopened') AND exception_id = 0
			 GROUP BY bucket, severity", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		$order   = array( '0-30', '31-60', '61-90', '91-180', '180+', 'unknown' );
		$buckets = array();

		foreach ( $order as $b ) {
			$buckets[ $b ] = array_fill_keys( array_keys( vh_severities() ), 0 );
		}

		foreach ( $rows as $row ) {
			$b = (string) $row['bucket'];
			$s = (string) $row['severity'];
			if ( isset( $buckets[ $b ][ $s ] ) ) {
				$buckets[ $b ][ $s ] = (int) $row['n'];
			}
		}

		$out = array();

		foreach ( $buckets as $bucket => $sev ) {
			if ( ! array_sum( $sev ) ) {
				continue;
			}
			$label = 'unknown' === $bucket
				? __( 'Unknown', 'vulnhub' )
				: sprintf( /* translators: %s: day range. */ __( '%s days', 'vulnhub' ), $bucket );

			$out[] = array( 'label' => $label, 'buckets' => $sev );
		}

		return $out;
	}

	public static function render_age_buckets(): void {
		$rows  = self::age_rows();
		$stack = array();

		foreach ( $rows as $row ) {
			// severity_stack() wants the per-severity counts under `counts`,
			// not spread across the row.
			$stack[] = array(
				'label'  => $row['label'],
				'counts' => $row['buckets'],
			);
		}

		echo VulnHub_Dash_Charts::severity_stack( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$stack,
			array( 'caption' => __( 'Open findings by how long they have been open.', 'vulnhub' ) )
		);
	}

	public static function data_age_buckets(): array {
		$rows = self::age_rows();
		$out  = array();

		foreach ( $rows as $row ) {
			$out[] = array_merge( array( $row['label'] ), array_values( $row['buckets'] ) );
		}

		return array(
			'headers' => array_merge(
				array( __( 'Age', 'vulnhub' ) ),
				array_map( static fn( array $d ): string => (string) $d['label'], vh_severities() )
			),
			'rows'    => $out,
		);
	}

	/**
	 * @return array<int,array{label:string,value:int,note:string}>
	 */
	private static function funnel_stages(): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$v = vh_table( 'vulns' );

		$open = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$f} WHERE state IN ('open','reopened') AND exception_id = 0" ); // phpcs:ignore
		$sev  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$f} WHERE state IN ('open','reopened') AND exception_id = 0 AND severity IN ('critical','high')" ); // phpcs:ignore
		/*
		 * Resolve which vulns carry a public exploit first. There are 4,022
		 * vuln definitions and 425,289 findings: joining the two so the
		 * optimiser can filter on `exploit_available` made it walk the
		 * findings table doing a primary-key lookup per row, which measured
		 * 2.25 s. An id list turns both counts into index range scans.
		 */
		$exploitable = array_map(
			'intval',
			(array) $wpdb->get_col( "SELECT id FROM {$v} WHERE exploit_available = 1" ) // phpcs:ignore
		);

		$expl     = 0;
		$noticket = 0;

		if ( $exploitable ) {
			$in = implode( ',', $exploitable );

			$expl = (int) $wpdb->get_var(
				"SELECT COUNT(*) FROM {$f} f
				 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
				   AND f.severity IN ('critical','high') AND f.vuln_id IN ({$in})" // phpcs:ignore
			);
			$noticket = (int) $wpdb->get_var(
				"SELECT COUNT(*) FROM {$f} f
				 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
				   AND f.severity IN ('critical','high') AND f.vuln_id IN ({$in})
				   AND f.ticket_id = 0" // phpcs:ignore
			);
		}

		return array(
			array( 'label' => __( 'Open findings', 'vulnhub' ), 'value' => $open, 'note' => __( 'everything currently detected', 'vulnhub' ) ),
			array( 'label' => __( 'Critical or high', 'vulnhub' ), 'value' => $sev, 'note' => __( 'severity worth acting on', 'vulnhub' ) ),
			array( 'label' => __( 'With a public exploit', 'vulnhub' ), 'value' => $expl, 'note' => __( 'someone already wrote the attack', 'vulnhub' ) ),
			array( 'label' => __( 'And nobody has a ticket', 'vulnhub' ), 'value' => $noticket, 'note' => __( 'this is the number that matters', 'vulnhub' ) ),
		);
	}

	public static function render_exploit_funnel(): void {
		echo VulnHub_Dash_Charts::funnel( self::funnel_stages() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	public static function data_exploit_funnel(): array {
		return array(
			'headers' => array( __( 'Stage', 'vulnhub' ), __( 'Findings', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $s ): array => array( (string) $s['label'], (int) $s['value'] ),
				self::funnel_stages()
			),
		);
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	private static function top_vuln_rows( int $limit = 8 ): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$v = vh_table( 'vulns' );

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT v.id, v.title, v.plugin_id, v.severity,
					COUNT(DISTINCT f.asset_id) AS asset_count
				 FROM {$f} f
				 INNER JOIN {$v} v ON v.id = f.vuln_id
				 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
				   AND v.severity IN ('critical','high','medium')
				 GROUP BY v.id
				 ORDER BY asset_count DESC
				 LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$limit
			),
			ARRAY_A
		);
	}

	public static function render_top_vulns(): void {
		$rows = self::top_vuln_rows();

		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( __( 'Nothing open above medium severity.', 'vulnhub' ) ); // phpcs:ignore
			return;
		}

		echo VulnHub_Dash_Charts::bar_chart( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array_map(
				static fn( array $r ): array => array(
					'label' => vh_trim( (string) $r['title'], 44 ),
					'value' => (int) $r['asset_count'],
					'href'  => VulnHub_Dash_Portal::portal_url( 'vulnerabilities', array( 'vuln_id' => (int) $r['id'] ) ),
				),
				$rows
			),
			array( 'caption' => __( 'Number of assets affected, largest first.', 'vulnhub' ) )
		);
	}

	public static function data_top_vulns(): array {
		return array(
			'headers' => array( __( 'Vulnerability', 'vulnhub' ), __( 'Plugin', 'vulnhub' ), __( 'Severity', 'vulnhub' ), __( 'Assets affected', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['title'],
					(string) $r['plugin_id'],
					(string) $r['severity'],
					(int) $r['asset_count'],
				),
				self::top_vuln_rows( 50 )
			),
		);
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	private static function top_asset_rows( int $limit = 8 ): array {
		global $wpdb;

		$a = vh_table( 'assets' );
		$t = vh_table( 'teams' );
		$p = vh_table( 'people' );

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT a.id, a.hostname, a.asset_type, a.risk_score,
					a.open_critical, a.open_high,
					t.name AS team_name, p.display_name AS owner_name
				 FROM {$a} a
				 LEFT JOIN {$t} t ON t.id = a.team_id
				 LEFT JOIN {$p} p ON p.id = a.owner_person_id
				 WHERE a.risk_score > 0
				 ORDER BY a.risk_score DESC
				 LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$limit
			),
			ARRAY_A
		);
	}

	public static function render_top_assets(): void {
		$rows = self::top_asset_rows();

		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( __( 'No asset carries any risk yet.', 'vulnhub' ) ); // phpcs:ignore
			return;
		}

		echo '<ul class="vh-list">';

		foreach ( $rows as $row ) {
			$who = (string) ( $row['owner_name'] ?: $row['team_name'] );

			echo '<li class="vh-list__row">'
				. '<a class="vh-mono" href="' . esc_url( VulnHub_Dash_Portal::portal_url( 'assets', array( 'asset' => (int) $row['id'] ) ) ) . '">'
				. esc_html( (string) $row['hostname'] ) . '</a>'
				. '<span class="vh-meta">' . esc_html( $who ?: __( 'Unassigned', 'vulnhub' ) ) . '</span>'
				. '<span class="vh-list__num">' . esc_html( number_format_i18n( (float) $row['risk_score'], 0 ) ) . '</span>'
				. '</li>';
		}

		echo '</ul>';

		echo VulnHub_Dash_Charts::table_view( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array( __( 'Asset', 'vulnhub' ), __( 'Owner', 'vulnhub' ), __( 'Critical', 'vulnhub' ), __( 'High', 'vulnhub' ), __( 'Risk', 'vulnhub' ) ),
			array_map(
				static fn( array $r ): array => array(
					(string) $r['hostname'],
					(string) ( $r['owner_name'] ?: $r['team_name'] ),
					number_format_i18n( (int) $r['open_critical'] ),
					number_format_i18n( (int) $r['open_high'] ),
					number_format_i18n( (float) $r['risk_score'], 0 ),
				),
				$rows
			),
			__( 'Highest risk score first.', 'vulnhub' )
		);
	}

	public static function data_top_assets(): array {
		return array(
			'headers' => array( __( 'Asset', 'vulnhub' ), __( 'Type', 'vulnhub' ), __( 'Owner', 'vulnhub' ), __( 'Team', 'vulnhub' ), __( 'Critical', 'vulnhub' ), __( 'High', 'vulnhub' ), __( 'Risk score', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['hostname'],
					(string) $r['asset_type'],
					(string) $r['owner_name'],
					(string) $r['team_name'],
					(int) $r['open_critical'],
					(int) $r['open_high'],
					(float) $r['risk_score'],
				),
				self::top_asset_rows( 100 )
			),
		);
	}

	/**
	 * @return array<int,array{label:string,value:int}>
	 */
	private static function group_rows( string $column, int $limit = 6 ): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$a = vh_table( 'assets' );
		$v = vh_table( 'vulns' );

		$sql = 'operating_system' === $column
			? "SELECT COALESCE(NULLIF(a.operating_system, ''), 'Unknown') AS label, COUNT(*) AS n
			   FROM {$f} f INNER JOIN {$a} a ON a.id = f.asset_id
			   WHERE f.state IN ('open','reopened') AND f.exception_id = 0
			   GROUP BY label ORDER BY n DESC LIMIT %d"
			: "SELECT COALESCE(NULLIF(v.family, ''), 'Unknown') AS label, COUNT(*) AS n
			   FROM {$f} f INNER JOIN {$v} v ON v.id = f.vuln_id
			   WHERE f.state IN ('open','reopened') AND f.exception_id = 0
			   GROUP BY label ORDER BY n DESC LIMIT %d";

		$rows = (array) $wpdb->get_results( $wpdb->prepare( $sql, $limit ), ARRAY_A ); // phpcs:ignore

		return array_map(
			static fn( array $r ): array => array( 'label' => (string) $r['label'], 'value' => (int) $r['n'] ),
			$rows
		);
	}

	private static function palette(): array {
		return array(
			'var(--vh-series-1)',
			'var(--vh-series-2)',
			'var(--vh-sev-medium)',
			'var(--vh-good)',
			'var(--vh-sev-critical)',
			'var(--vh-muted)',
		);
	}

	public static function render_os_mix(): void {
		$rows    = self::group_rows( 'operating_system' );
		$palette = self::palette();

		echo VulnHub_Dash_Charts::donut( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array_map(
				static function ( array $r, int $i ) use ( $palette ): array {
					return array(
						'label' => vh_trim( $r['label'], 30 ),
						'value' => $r['value'],
						'color' => $palette[ $i % count( $palette ) ],
					);
				},
				$rows,
				array_keys( $rows )
			),
			array( 'title' => __( 'Impact by operating system', 'vulnhub' ) )
		);
	}

	public static function data_os_mix(): array {
		return array(
			'headers' => array( __( 'Operating system', 'vulnhub' ), __( 'Open findings', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array( $r['label'], $r['value'] ),
				self::group_rows( 'operating_system', 30 )
			),
		);
	}

	public static function render_family_mix(): void {
		$rows = self::group_rows( 'family' );

		echo VulnHub_Dash_Charts::bar_chart( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array_map(
				static fn( array $r ): array => array( 'label' => vh_trim( $r['label'], 30 ), 'value' => $r['value'] ),
				$rows
			),
			array( 'caption' => __( 'Open findings by Tenable plugin family.', 'vulnhub' ) )
		);
	}

	public static function data_family_mix(): array {
		return array(
			'headers' => array( __( 'Family', 'vulnhub' ), __( 'Open findings', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array( $r['label'], $r['value'] ),
				self::group_rows( 'family', 30 )
			),
		);
	}

	/* =================================================================
	 * Widgets: coverage
	 * ============================================================== */

	public static function render_coverage_summary(): void {
		$cov  = Coverage::summary();
		$tone = array(
			Coverage::COVERED        => 'var(--vh-good)',
			Coverage::STALE          => 'var(--vh-sev-medium)',
			Coverage::NEVER_SCANNED  => 'var(--vh-sev-high)',
			Coverage::NOT_IN_TENABLE => 'var(--vh-sev-critical)',
			Coverage::OUT_OF_SCOPE   => 'var(--vh-muted)',
		);

		$rows = array();

		/*
		 * Out of scope is not a coverage state, it is the absence of the
		 * question, so it is not a slice. It is named underneath instead.
		 */
		foreach ( $cov['states'] as $state => $count ) {
			/*
			 * Both exclusions leave the donut, not just retired kit. A muted
			 * "not a scanning target" slice was tried and read worse than
			 * leaving it out: the centre said 60% covered while the legend
			 * beside it said 53%, because one is a share of the machines in
			 * scope and the other a share of everything. Both are named
			 * underneath instead, where there is room to say why.
			 */
			if ( Coverage::OUT_OF_SCOPE === $state || Coverage::OTHER_DEVICE === $state ) {
				continue;
			}
			$rows[] = array(
				'label' => Coverage::label( (string) $state ),
				'value' => (float) $count,
				'color' => $tone[ $state ] ?? 'var(--vh-muted)',
			);
		}

		echo VulnHub_Dash_Charts::donut( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'centre'       => number_format_i18n( $cov['percent'] ) . '%',
				'centre_label' => __( 'covered', 'vulnhub' ),
				'title'        => __( 'Tenable coverage', 'vulnhub' ),
				'caption'      => sprintf(
					/* translators: %d: number of days. */
					__( 'A scan counts as current for %d days.', 'vulnhub' ),
					(int) $cov['window_days']
				),
			)
		);

		/*
		 * Say out loud what scope is holding back.
		 *
		 * Excluding quarantined and in-repair machines is the right call --
		 * nothing can scan a device that is off the network -- but it moves a
		 * number people report upwards, and a number that moves without an
		 * explanation is a number somebody has to go and re-derive by hand.
		 * So the widget names the statuses and the counts, and links to them.
		 */
		$excluded = Coverage::excluded_by_scope();

		if ( ! $excluded ) {
			return;
		}

		$parts = array();
		$total = 0;

		foreach ( $excluded as $row ) {
			$total  += (int) $row['count'];
			$parts[] = sprintf(
				'<a href="%s">%s %s</a>',
				esc_url( VulnHub_Dash_Portal::portal_url( 'assets', array( 'life' => (string) $row['status'] ) ) ),
				esc_html( number_format_i18n( (int) $row['count'] ) ),
				esc_html( strtolower( (string) $row['label'] ) )
			);
		}

		printf(
			'<p class="vh-sub">%s %s</p>',
			esc_html(
				sprintf(
					/* translators: %s: number of assets held out of the coverage figure. */
					_n(
						'%s asset is not expected to be scanned and is excluded from this figure:',
						'%s assets are not expected to be scanned and are excluded from this figure:',
						$total,
						'vulnhub'
					),
					number_format_i18n( $total )
				)
			),
			implode( ', ', $parts ) . '.' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- each part escaped above.
		);
	}

	public static function data_coverage_summary(): array {
		$cov  = Coverage::summary();
		$rows = array();

		foreach ( $cov['states'] as $state => $count ) {
			if ( Coverage::OUT_OF_SCOPE === $state || Coverage::OTHER_DEVICE === $state ) {
				continue;
			}
			$rows[] = array( Coverage::label( (string) $state ), (int) $count );
		}

		return array(
			'headers' => array( __( 'Coverage state', 'vulnhub' ), __( 'Assets', 'vulnhub' ) ),
			'rows'    => $rows,
		);
	}

	private static function render_coverage_dimension( string $dimension ): void {
		/*
		 * Every site, not the ten biggest. A small office with two
		 * machines and no scan is exactly the row worth seeing, and
		 * ordering by size put it below the fold; twelve sites are in use
		 * here and eleven fitted. The bars are 20px, so fifty is still a
		 * readable widget and the cap is only there to stop a pathological
		 * import rendering a thousand.
		 */
		$rows = Coverage::by_dimension( $dimension, 50 );

		usort( $rows, static fn( array $a, array $b ): int => $a['percent'] <=> $b['percent'] );

		foreach ( $rows as $i => $row ) {
			$rows[ $i ]['href'] = self::coverage_slice_url( $row );
		}

		echo VulnHub_Dash_Charts::coverage_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'caption'  => __( 'Worst coverage first. Select a row for the assets behind it.', 'vulnhub' ),
				'excluded' => (int) ( Coverage::summary()['excluded'] ?? 0 ),
				'excluded_note_1' => __( 'In-scope assets only; %s asset that is retired or is not a scanning target is excluded.', 'vulnhub' ),
				'excluded_note_n' => __( 'In-scope assets only; %s assets that are retired or are not scanning targets are excluded.', 'vulnhub' ),
			)
		);
	}

	/**
	 * Where one bar of a coverage chart leads.
	 *
	 * To the assets list, filtered to that slice and to assets with a gap --
	 * which is what the bar is measuring. A bar with no gaps still links,
	 * to the slice itself, because "show me the 3 cloud assets that are all
	 * covered" is a reasonable thing to want and a dead link is not.
	 *
	 * @param array<string,mixed> $row One row from Coverage::by_dimension().
	 * @return string Empty when the slice cannot be expressed as a filter.
	 */
	private static function coverage_slice_url( array $row ): string {
		$filter = (string) ( $row['filter'] ?? '' );
		$key    = (string) ( $row['key'] ?? '' );

		/*
		 * "Unclassified" is the absence of a value, and an empty filter would
		 * silently mean "everything" rather than "the ones with nothing
		 * recorded" -- better no link than a wrong one. The site dimension is
		 * the exception: it hands over `none`, which the asset query reads as
		 * `location_id = 0`. That row matters more than any other here, since
		 * unplaced assets hold more coverage gaps than any named office.
		 */
		if ( '' === $filter || '' === $key || '0' === $key ) {
			return '';
		}

		/*
		 * `coverage=gap` goes on unconditionally, including when the row has
		 * no gaps at all. Leaving it off for a zero meant the "0 gaps" chip
		 * on the cloud row opened a list of three assets, which is the one
		 * thing a number on a chart must never do. An empty list is the
		 * honest answer to "show me the nothing".
		 */
		return VulnHub_Dash_Portal::portal_url(
			'assets',
			array(
				$filter    => $key,
				'coverage' => 'gap',
				/*
				 * Named, never inherited. Every list a widget links to says
				 * which lifecycle scope it means, so that changing the assets
				 * page default cannot silently change what a chart claims.
				 */
				'life'     => 'reportable',
			)
		);
	}

	private static function data_coverage_dimension( string $dimension ): array {
		$rows = Coverage::by_dimension( $dimension, 50 );

		usort( $rows, static fn( array $a, array $b ): int => $a['percent'] <=> $b['percent'] );

		return array(
			'headers' => array( __( 'Group', 'vulnhub' ), __( 'Total', 'vulnhub' ), __( 'Covered', 'vulnhub' ), __( 'Gaps', 'vulnhub' ), __( 'Coverage %', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array( $r['label'], $r['total'], $r['covered'], $r['gaps'], $r['percent'] ),
				$rows
			),
		);
	}

	public static function render_coverage_by_type(): void {
		self::render_coverage_dimension( 'asset_type' );
	}

	public static function data_coverage_by_type(): array {
		return self::data_coverage_dimension( 'asset_type' );
	}

	public static function render_coverage_by_site(): void {
		self::render_coverage_dimension( 'location' );
	}

	public static function data_coverage_by_site(): array {
		return self::data_coverage_dimension( 'location' );
	}

	/**
	 * Coverage per source system.
	 *
	 * This used to group on `primary_source`, which records only whichever
	 * feed wrote to the row last -- on this estate that made almost every
	 * asset read "tenable", including the several hundred the CMDB and
	 * Intune also know. Counting each system that claims an asset is the
	 * question people were actually reading the chart to answer.
	 */
	public static function render_coverage_by_source(): void {
		$rows = Coverage::by_source();

		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( __( 'No import has recorded a source yet.', 'vulnhub' ) ); // phpcs:ignore
			return;
		}

		usort( $rows, static fn( array $a, array $b ): int => $a['percent'] <=> $b['percent'] );

		foreach ( $rows as $i => $row ) {
			$rows[ $i ]['href'] = self::coverage_slice_url( $row );
		}

		echo VulnHub_Dash_Charts::coverage_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'caption'  => __( 'Worst coverage first. Select a row for the assets behind it.', 'vulnhub' ),
				'excluded' => (int) ( Coverage::summary()['excluded'] ?? 0 ),
				'excluded_note_1' => __( 'In-scope assets only; %s asset that is retired or is not a scanning target is excluded.', 'vulnhub' ),
				'excluded_note_n' => __( 'In-scope assets only; %s assets that are retired or are not scanning targets are excluded.', 'vulnhub' ),
			)
		);

		/*
		 * The cleanup line. An asset one system claims and nothing else has
		 * ever confirmed is the one to doubt: either it left the network and
		 * nobody retired the record, or the other feeds cannot see it.
		 */
		$sole = array_values( array_filter( $rows, static fn( array $r ): bool => (int) $r['sole'] > 0 ) );

		if ( ! $sole ) {
			return;
		}

		echo '<p class="vh-sub vh-srcs-sole">' . esc_html__( 'Claimed by one system alone:', 'vulnhub' ) . ' ';

		$links = array();

		foreach ( $sole as $row ) {
			$links[] = '<a href="' . esc_url(
				VulnHub_Dash_Portal::portal_url( 'assets', array( 'known' => 'only:' . $row['slug'], 'life' => 'reportable' ) )
			) . '">' . sprintf(
				/* translators: 1: a count of assets, 2: name of a source system. */
				esc_html__( '%1$s by %2$s', 'vulnhub' ),
				esc_html( number_format_i18n( (int) $row['sole'] ) ),
				esc_html( (string) $row['label'] )
			) . '</a>';
		}

		echo implode( ', ', $links ) . '.</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	public static function data_coverage_by_source(): array {
		return array(
			'headers' => array(
				__( 'Source', 'vulnhub' ),
				__( 'Assets', 'vulnhub' ),
				__( 'Covered', 'vulnhub' ),
				__( 'Gaps', 'vulnhub' ),
				__( 'Coverage %', 'vulnhub' ),
				__( 'In Tenable, not scanned', 'vulnhub' ),
				__( 'Claimed by this source alone', 'vulnhub' ),
			),
			'rows'    => array_map(
				static fn( array $r ): array => array( $r['label'], $r['total'], $r['covered'], $r['gaps'], $r['percent'], $r['unscanned'] ?? 0, $r['sole'] ),
				Coverage::by_source()
			),
		);
	}

	public static function render_coverage_gaps( string $source = '' ): void {
		$gaps = Coverage::gaps( array( 'limit' => 12, 'source' => $source ) );

		if ( ! $gaps['rows'] ) {
			echo VulnHub_Dash_Charts::empty_state(
				'' === $source
					? __( 'Every in-scope asset has a current Tenable scan.', 'vulnhub' )
					: __( 'Every in-scope asset in this register has a current Tenable scan.', 'vulnhub' )
			); // phpcs:ignore
			return;
		}

		echo '<div class="vh-tablewrap"><table class="vh-table"><thead><tr>'
			. '<th>' . esc_html__( 'Asset', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Type', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Why it is a gap', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Known from', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Owner', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Last scan', 'vulnhub' ) . '</th>'
			. '</tr></thead><tbody>';

		foreach ( $gaps['rows'] as $row ) {
			/*
			 * Read from the source column rather than from whichever ids the
			 * row happens to carry. A CSV export gives a CMDB reference but
			 * no `cmdb_id`, so the old test called those assets Unknown --
			 * exactly the rows a reader is trying to trace.
			 */
			$labels = vh_asset_sources();
			$known  = array();

			foreach ( \VulnHub\Core\Repo::sources_of( (string) ( $row['sources_json'] ?? '' ) ) as $slug ) {
				$known[] = (string) ( $labels[ $slug ] ?? ucfirst( $slug ) );
			}

			echo '<tr><td><a class="vh-mono" href="' . esc_url( VulnHub_Dash_Portal::portal_url( 'assets', array( 'asset' => (int) $row['id'] ) ) ) . '">'
				. esc_html( (string) $row['hostname'] ) . '</a><span class="vh-meta">' . esc_html( (string) $row['ipv4'] ) . '</span></td>'
				. '<td>' . esc_html( vh_asset_type_label( (string) $row['asset_type'] ) ) . '</td>'
				. '<td><span class="vh-chip vh-chip--' . esc_attr( Coverage::tone( (string) $row['coverage_state'] ) ) . '">'
				. esc_html( Coverage::label( (string) $row['coverage_state'] ) ) . '</span></td>'
				. '<td>' . esc_html( $known ? implode( ', ', $known ) : __( 'Unknown', 'vulnhub' ) ) . '</td>'
				. '<td>' . esc_html( (string) ( $row['owner_name'] ?: $row['team_name'] ?: __( 'Unassigned', 'vulnhub' ) ) ) . '</td>'
				. '<td>' . esc_html( $row['tenable_last_scan'] ? vh_ago( (string) $row['tenable_last_scan'] ) : __( 'never', 'vulnhub' ) ) . '</td>'
				. '</tr>';
		}

		echo '</tbody></table></div>';

		printf(
			'<p class="vh-sub"><a href="%s">%s</a></p>',
			esc_url(
				VulnHub_Dash_Portal::portal_url(
					'assets',
					array_filter( array( 'coverage' => 'gap', 'life' => 'reportable', 'known' => $source ) )
				)
			),
			esc_html(
				sprintf(
					/* translators: %s: number of assets. */
					__( 'See all %s assets with a coverage gap', 'vulnhub' ),
					number_format_i18n( (int) $gaps['total'] )
				)
			)
		);
	}

	public static function data_coverage_gaps( string $source = '' ): array {
		$gaps = Coverage::gaps( array( 'limit' => 500, 'source' => $source ) );

		return array(
			'headers' => array( __( 'Asset', 'vulnhub' ), __( 'FQDN', 'vulnhub' ), __( 'IP', 'vulnhub' ), __( 'Type', 'vulnhub' ), __( 'Coverage state', 'vulnhub' ), __( 'Known by', 'vulnhub' ), __( 'CMDB id', 'vulnhub' ), __( 'Intune id', 'vulnhub' ), __( 'Tenable UUID', 'vulnhub' ), __( 'Owner', 'vulnhub' ), __( 'Team', 'vulnhub' ), __( 'Last Tenable scan', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['hostname'],
					(string) $r['fqdn'],
					(string) $r['ipv4'],
					(string) $r['asset_type'],
					(string) $r['coverage_state'],
					implode( ' + ', \VulnHub\Core\Repo::sources_of( (string) ( $r['sources_json'] ?? '' ) ) ),
					(string) $r['cmdb_id'],
					(string) $r['intune_id'],
					(string) $r['tenable_uuid'],
					(string) $r['owner_name'],
					(string) $r['team_name'],
					(string) ( $r['tenable_last_scan'] ?? '' ),
				),
				$gaps['rows']
			),
		);
	}

	/* =================================================================
	 * Widgets: endpoint coverage
	 * ============================================================== */

	/**
	 * The endpoint-coverage donut, in-scope assets only.
	 *
	 * Reads exactly like the scanning donut beside it, on purpose: the same
	 * slices in the same order with the same colours, so the two can be
	 * compared at a glance rather than re-read.
	 */
	public static function render_defender_summary(): void {
		$cov  = Defender_Coverage::summary();
		$tone = array(
			Defender_Coverage::ONBOARDED       => 'var(--vh-good)',
			Defender_Coverage::SILENT          => 'var(--vh-sev-medium)',
			Defender_Coverage::NEVER_REPORTED  => 'var(--vh-sev-medium)',
			Defender_Coverage::NO_CONTACT      => 'var(--vh-sev-high)',
			Defender_Coverage::NOT_ONBOARDED   => 'var(--vh-sev-high)',
			Defender_Coverage::NOT_IN_DEFENDER => 'var(--vh-sev-critical)',
			Defender_Coverage::OUT_OF_SCOPE    => 'var(--vh-muted)',
		);

		$rows = array();

		foreach ( $cov['states'] as $state => $count ) {
			if ( Defender_Coverage::OUT_OF_SCOPE === $state || Defender_Coverage::OTHER_DEVICE === $state ) {
				continue;
			}
			$rows[] = array(
				'label' => Defender_Coverage::label( (string) $state ),
				'value' => (float) $count,
				'color' => $tone[ $state ] ?? 'var(--vh-muted)',
			);
		}

		echo VulnHub_Dash_Charts::donut( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'centre'       => number_format_i18n( $cov['percent'] ) . '%',
				'centre_label' => __( 'onboarded', 'vulnhub' ),
				'title'        => __( 'Defender coverage', 'vulnhub' ),
				'caption'      => sprintf(
					/* translators: %d: number of days. */
					__( 'A sensor counts as reporting for %d days.', 'vulnhub' ),
					(int) $cov['window_days']
				),
			)
		);

		/*
		 * Two reasons an asset is held out of this figure, named separately.
		 *
		 * Retired kit is excluded for the reason it is excluded everywhere.
		 * A printer or a switch is excluded because Defender cannot onboard
		 * one -- a different fact, and the one a reader will otherwise spend
		 * ten minutes trying to reconcile against the scanning figure.
		 */
		$excluded = Defender_Coverage::excluded_by_scope();

		if ( ! $excluded ) {
			return;
		}

		$parts = array();
		$total = 0;

		foreach ( $excluded as $row ) {
			$total += (int) $row['count'];

			$args = 'unonboardable' === (string) $row['status']
				? array( 'defender' => Defender_Coverage::OUT_OF_SCOPE, 'life' => 'reportable' )
				: array( 'life' => (string) $row['status'] );

			$parts[] = sprintf(
				'<a href="%s">%s %s</a>',
				esc_url( VulnHub_Dash_Portal::portal_url( 'assets', $args ) ),
				esc_html( number_format_i18n( (int) $row['count'] ) ),
				esc_html( strtolower( (string) $row['label'] ) )
			);
		}

		printf(
			'<p class="vh-sub">%s %s</p>',
			esc_html(
				sprintf(
					/* translators: %s: number of assets held out of the coverage figure. */
					_n(
						'%s asset is excluded from this figure:',
						'%s assets are excluded from this figure:',
						$total,
						'vulnhub'
					),
					number_format_i18n( $total )
				)
			),
			implode( ', ', $parts ) . '.' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- each part escaped above.
		);
	}

	public static function data_defender_summary(): array {
		$cov  = Defender_Coverage::summary();
		$rows = array();

		foreach ( $cov['states'] as $state => $count ) {
			if ( Defender_Coverage::OUT_OF_SCOPE === $state || Defender_Coverage::OTHER_DEVICE === $state ) {
				continue;
			}
			$rows[] = array( Defender_Coverage::label( (string) $state ), (int) $count );
		}

		return array(
			'headers' => array( __( 'Endpoint state', 'vulnhub' ), __( 'Assets', 'vulnhub' ) ),
			'rows'    => $rows,
		);
	}

	/**
	 * Where one bar of an endpoint chart leads.
	 *
	 * The same contract as `coverage_slice_url()`, pointed at the endpoint
	 * filter instead of the scanning one.
	 *
	 * @param array<string,mixed> $row One row from Defender_Coverage.
	 * @return string Empty when the slice cannot be expressed as a filter.
	 */
	private static function defender_slice_url( array $row ): string {
		$filter = (string) ( $row['filter'] ?? '' );
		$key    = (string) ( $row['key'] ?? '' );

		if ( '' === $filter || '' === $key || '0' === $key ) {
			return '';
		}

		return VulnHub_Dash_Portal::portal_url(
			'assets',
			array(
				$filter    => $key,
				'defender' => 'gap',
				'life'     => 'reportable',
			)
		);
	}

	private static function render_defender_dimension( string $dimension ): void {
		$rows = Defender_Coverage::by_dimension( $dimension, 50 );

		usort( $rows, static fn( array $a, array $b ): int => $a['percent'] <=> $b['percent'] );

		foreach ( $rows as $i => $row ) {
			$rows[ $i ]['href'] = self::defender_slice_url( $row );
		}

		echo VulnHub_Dash_Charts::coverage_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'caption'  => __( 'Worst first. Select a row for the assets behind it.', 'vulnhub' ),
				'excluded' => (int) ( Defender_Coverage::summary()['excluded'] ?? 0 ),
				/*
				 * Two reasons in one number, so the wording names both. Most
				 * of what is held back here is not retired kit -- it is
				 * printers, switches and video units that Defender has
				 * discovered and can never onboard.
				 */
				'excluded_note_1' => __( 'In-scope assets only; %s asset that is retired or that Defender cannot onboard is excluded.', 'vulnhub' ),
				'excluded_note_n' => __( 'In-scope assets only; %s assets that are retired or that Defender cannot onboard are excluded.', 'vulnhub' ),
			)
		);
	}

	public static function render_defender_by_type(): void {
		self::render_defender_dimension( 'asset_type' );
	}

	public static function data_defender_by_type(): array {
		$rows = Defender_Coverage::by_dimension( 'asset_type', 50 );

		usort( $rows, static fn( array $a, array $b ): int => $a['percent'] <=> $b['percent'] );

		return array(
			'headers' => array( __( 'Group', 'vulnhub' ), __( 'Total', 'vulnhub' ), __( 'Onboarded', 'vulnhub' ), __( 'Gaps', 'vulnhub' ), __( 'Coverage %', 'vulnhub' ), __( 'Onboarded, not reporting', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array( $r['label'], $r['total'], $r['covered'], $r['gaps'], $r['percent'], $r['unscanned'] ),
				$rows
			),
		);
	}

	public static function render_defender_by_source(): void {
		$rows = Defender_Coverage::by_source();

		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( __( 'No import has recorded a source yet.', 'vulnhub' ) ); // phpcs:ignore
			return;
		}

		usort( $rows, static fn( array $a, array $b ): int => $a['percent'] <=> $b['percent'] );

		foreach ( $rows as $i => $row ) {
			$rows[ $i ]['href'] = self::defender_slice_url( $row );
		}

		echo VulnHub_Dash_Charts::coverage_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'caption'  => __( 'Worst first. Select a row for the assets behind it.', 'vulnhub' ),
				'excluded' => (int) ( Defender_Coverage::summary()['excluded'] ?? 0 ),
				/*
				 * Two reasons in one number, so the wording names both. Most
				 * of what is held back here is not retired kit -- it is
				 * printers, switches and video units that Defender has
				 * discovered and can never onboard.
				 */
				'excluded_note_1' => __( 'In-scope assets only; %s asset that is retired or that Defender cannot onboard is excluded.', 'vulnhub' ),
				'excluded_note_n' => __( 'In-scope assets only; %s assets that are retired or that Defender cannot onboard are excluded.', 'vulnhub' ),
			)
		);
	}

	public static function data_defender_by_source(): array {
		return array(
			'headers' => array(
				__( 'Source', 'vulnhub' ),
				__( 'Assets', 'vulnhub' ),
				__( 'Onboarded', 'vulnhub' ),
				__( 'Gaps', 'vulnhub' ),
				__( 'Coverage %', 'vulnhub' ),
				__( 'Onboarded, not reporting', 'vulnhub' ),
				__( 'Claimed by this source alone', 'vulnhub' ),
			),
			'rows'    => array_map(
				static fn( array $r ): array => array( $r['label'], $r['total'], $r['covered'], $r['gaps'], $r['percent'], $r['unscanned'], $r['sole'] ),
				Defender_Coverage::by_source()
			),
		);
	}

	public static function render_defender_gaps( string $source = '' ): void {
		$gaps = Defender_Coverage::gaps( array( 'limit' => 12, 'source' => $source ) );

		if ( ! $gaps['rows'] ) {
			echo VulnHub_Dash_Charts::empty_state(
				'' === $source
					? __( 'Every in-scope asset Defender can onboard has a sensor.', 'vulnhub' )
					: __( 'Every in-scope asset in this register has a Defender sensor.', 'vulnhub' )
			); // phpcs:ignore
			return;
		}

		echo '<div class="vh-tablewrap"><table class="vh-table"><thead><tr>'
			. '<th>' . esc_html__( 'Asset', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Type', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Why it is a gap', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Known from', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Owner', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Last sensor report', 'vulnhub' ) . '</th>'
			. '</tr></thead><tbody>';

		$labels = vh_asset_sources();

		foreach ( $gaps['rows'] as $row ) {
			$known = array();

			foreach ( Repo::sources_of( (string) ( $row['sources_json'] ?? '' ) ) as $slug ) {
				$known[] = (string) ( $labels[ $slug ] ?? ucfirst( $slug ) );
			}

			$state = (string) ( $row['defender_coverage_state'] ?? '' );

			echo '<tr><td><a class="vh-mono" href="' . esc_url( VulnHub_Dash_Portal::portal_url( 'assets', array( 'asset' => (int) $row['id'] ) ) ) . '">'
				. esc_html( (string) $row['hostname'] ) . '</a><span class="vh-meta">' . esc_html( (string) $row['ipv4'] ) . '</span></td>'
				. '<td>' . esc_html( vh_asset_type_label( (string) $row['asset_type'] ) ) . '</td>'
				. '<td><span class="vh-chip vh-chip--' . esc_attr( Defender_Coverage::tone( $state ) ) . '">'
				. esc_html( Defender_Coverage::label( $state ) ) . '</span></td>'
				. '<td>' . esc_html( $known ? implode( ', ', $known ) : __( 'Unknown', 'vulnhub' ) ) . '</td>'
				. '<td>' . esc_html( (string) ( $row['owner_name'] ?: $row['team_name'] ?: __( 'Unassigned', 'vulnhub' ) ) ) . '</td>'
				. '<td>' . esc_html( $row['defender_last_seen'] ? vh_ago( (string) $row['defender_last_seen'] ) : __( 'never', 'vulnhub' ) ) . '</td>'
				. '</tr>';
		}

		echo '</tbody></table></div>';

		printf(
			'<p class="vh-sub"><a href="%s">%s</a></p>',
			esc_url(
				VulnHub_Dash_Portal::portal_url(
					'assets',
					array_filter( array( 'defender' => 'gap', 'life' => 'reportable', 'known' => $source ) )
				)
			),
			esc_html(
				sprintf(
					/* translators: %s: number of assets. */
					__( 'See all %s assets with no Defender sensor', 'vulnhub' ),
					number_format_i18n( (int) $gaps['total'] )
				)
			)
		);
	}

	/* =================================================================
	 * Widgets: coverage of the CMDB register
	 * ============================================================== */

	/**
	 * One source's row out of a by_source() result.
	 *
	 * @param array<int,array<string,mixed>> $rows  From Coverage::by_source().
	 * @param string                         $slug  Source key.
	 * @return array<string,mixed>|null
	 */
	private static function source_row( array $rows, string $slug ): ?array {
		foreach ( $rows as $row ) {
			if ( $slug === (string) ( $row['slug'] ?? '' ) ) {
				return $row;
			}
		}

		return null;
	}

	/**
	 * How far below a full register a coverage figure is worth alarming about.
	 *
	 * @param float $percent Coverage percentage.
	 * @return string A tone the meter and tile stylesheets both understand.
	 */
	private static function register_tone( float $percent ): string {
		if ( $percent >= 95 ) {
			return 'ok';
		}

		return $percent >= 80 ? 'warn' : 'bad';
	}

	/**
	 * The small pair: coverage measured against the asset register alone.
	 *
	 * Deliberately two widgets rather than one with a toggle. Scanning and
	 * endpoint coverage of the register are reported to different people and
	 * move for different reasons -- a machine can be scanned weekly and have
	 * no sensor, or carry a sensor and have never been scanned -- and a single
	 * control that switched between them would let a reader carry one number
	 * away believing it was the other.
	 */
	public static function render_coverage_cmdb(): void {
		$row = self::source_row( Coverage::by_source(), 'cmdb' );

		if ( ! $row || (int) $row['total'] < 1 ) {
			echo VulnHub_Dash_Charts::empty_state( __( 'No CMDB import has run yet.', 'vulnhub' ) ); // phpcs:ignore
			return;
		}

		$pct = (float) $row['percent'];

		echo VulnHub_Dash_Charts::meter( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			(float) $row['covered'],
			(float) max( 1, (int) $row['total'] ),
			__( 'CMDB assets Tenable knows', 'vulnhub' ),
			self::register_tone( $pct )
		);

		echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array(
				'label' => __( 'Not in Tenable', 'vulnhub' ),
				'value' => (int) $row['gaps'],
				'tone'  => $row['gaps'] > 0 ? 'critical' : 'good',
				'meta'  => sprintf(
					/* translators: %s: number of in-scope assets in the register. */
					__( 'of %s in-scope CMDB assets', 'vulnhub' ),
					number_format_i18n( (int) $row['total'] )
				),
				'href'  => VulnHub_Dash_Portal::portal_url(
					'assets',
					array( 'known' => 'cmdb', 'coverage' => 'gap', 'life' => 'reportable' )
				),
			)
		);

		if ( (int) $row['unscanned'] > 0 ) {
			printf(
				'<p class="vh-sub">%s</p>',
				esc_html(
					sprintf(
						/* translators: %s: number of assets. */
						_n(
							'%s more is in Tenable but has no current scan.',
							'%s more are in Tenable but have no current scan.',
							(int) $row['unscanned'],
							'vulnhub'
						),
						number_format_i18n( (int) $row['unscanned'] )
					)
				)
			);
		}
	}

	public static function data_coverage_cmdb(): array {
		$row = self::source_row( Coverage::by_source(), 'cmdb' ) ?? array();

		return array(
			'headers' => array( __( 'Measure', 'vulnhub' ), __( 'Assets', 'vulnhub' ) ),
			'rows'    => array(
				array( __( 'In the CMDB register, in scope', 'vulnhub' ), (int) ( $row['total'] ?? 0 ) ),
				array( __( 'Tenable has a record', 'vulnhub' ), (int) ( $row['covered'] ?? 0 ) ),
				array( __( 'In Tenable, no current scan', 'vulnhub' ), (int) ( $row['unscanned'] ?? 0 ) ),
				array( __( 'Not in Tenable at all', 'vulnhub' ), (int) ( $row['gaps'] ?? 0 ) ),
				array( __( 'Coverage %', 'vulnhub' ), (float) ( $row['percent'] ?? 0 ) ),
			),
		);
	}

	public static function render_defender_cmdb(): void {
		$row = self::source_row( Defender_Coverage::by_source(), 'cmdb' );

		if ( ! $row || (int) $row['total'] < 1 ) {
			echo VulnHub_Dash_Charts::empty_state( __( 'No CMDB import has run yet.', 'vulnhub' ) ); // phpcs:ignore
			return;
		}

		$pct = (float) $row['percent'];

		echo VulnHub_Dash_Charts::meter( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			(float) $row['covered'],
			(float) max( 1, (int) $row['total'] ),
			__( 'CMDB assets Defender onboarded', 'vulnhub' ),
			self::register_tone( $pct )
		);

		echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array(
				'label' => __( 'No Defender sensor', 'vulnhub' ),
				'value' => (int) $row['gaps'],
				'tone'  => $row['gaps'] > 0 ? 'critical' : 'good',
				'meta'  => sprintf(
					/* translators: %s: number of in-scope assets in the register. */
					__( 'of %s in-scope CMDB assets', 'vulnhub' ),
					number_format_i18n( (int) $row['total'] )
				),
				'href'  => VulnHub_Dash_Portal::portal_url(
					'assets',
					array( 'known' => 'cmdb', 'defender' => 'gap', 'life' => 'reportable' )
				),
			)
		);

		if ( (int) $row['unscanned'] > 0 ) {
			printf(
				'<p class="vh-sub">%s</p>',
				esc_html(
					sprintf(
						/* translators: %s: number of assets. */
						_n(
							'%s more is onboarded but the sensor is quiet.',
							'%s more are onboarded but their sensors are quiet.',
							(int) $row['unscanned'],
							'vulnhub'
						),
						number_format_i18n( (int) $row['unscanned'] )
					)
				)
			);
		}
	}

	public static function data_defender_cmdb(): array {
		$row = self::source_row( Defender_Coverage::by_source(), 'cmdb' ) ?? array();

		return array(
			'headers' => array( __( 'Measure', 'vulnhub' ), __( 'Assets', 'vulnhub' ) ),
			'rows'    => array(
				array( __( 'In the CMDB register, in scope', 'vulnhub' ), (int) ( $row['total'] ?? 0 ) ),
				array( __( 'Defender has onboarded', 'vulnhub' ), (int) ( $row['covered'] ?? 0 ) ),
				array( __( 'Onboarded, sensor quiet', 'vulnhub' ), (int) ( $row['unscanned'] ?? 0 ) ),
				array( __( 'No Defender sensor', 'vulnhub' ), (int) ( $row['gaps'] ?? 0 ) ),
				array( __( 'Coverage %', 'vulnhub' ), (float) ( $row['percent'] ?? 0 ) ),
			),
		);
	}

	/**
	 * The same two lists, anchored to the CMDB register.
	 *
	 * Coverage against everything the platform has heard of and coverage
	 * against the asset register are different questions with different
	 * owners. A gap on a machine the CMDB carries has a CI number, a service
	 * and a team behind it, and somebody can be asked about it today; a gap
	 * on a device only a Defender sweep has ever seen usually means the
	 * register is out of date, which is a job for whoever owns the register.
	 * Answering them on one list produced a four-hundred-row page where the
	 * actionable half was buried.
	 */
	public static function render_coverage_gaps_cmdb(): void {
		self::render_coverage_gaps( 'cmdb' );
	}

	public static function data_coverage_gaps_cmdb(): array {
		return self::data_coverage_gaps( 'cmdb' );
	}

	public static function render_defender_gaps_cmdb(): void {
		self::render_defender_gaps( 'cmdb' );
	}

	public static function data_defender_gaps_cmdb(): array {
		return self::data_defender_gaps( 'cmdb' );
	}

	public static function data_defender_gaps( string $source = '' ): array {
		$gaps = Defender_Coverage::gaps( array( 'limit' => 500, 'source' => $source ) );

		return array(
			'headers' => array( __( 'Asset', 'vulnhub' ), __( 'FQDN', 'vulnhub' ), __( 'IP', 'vulnhub' ), __( 'Type', 'vulnhub' ), __( 'Endpoint state', 'vulnhub' ), __( 'Onboarding', 'vulnhub' ), __( 'Sensor health', 'vulnhub' ), __( 'Known by', 'vulnhub' ), __( 'Owner', 'vulnhub' ), __( 'Team', 'vulnhub' ), __( 'Last sensor report', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['hostname'],
					(string) $r['fqdn'],
					(string) $r['ipv4'],
					(string) $r['asset_type'],
					(string) ( $r['defender_coverage_state'] ?? '' ),
					(string) ( $r['defender_onboarding'] ?? '' ),
					(string) ( $r['defender_health'] ?? '' ),
					implode( ' + ', Repo::sources_of( (string) ( $r['sources_json'] ?? '' ) ) ),
					(string) $r['owner_name'],
					(string) $r['team_name'],
					(string) ( $r['defender_last_seen'] ?? '' ),
				),
				$gaps['rows']
			),
		);
	}

	/* =================================================================
	 * Widgets: ownership
	 * ============================================================== */

	/**
	 * @return array<int,array<string,mixed>>
	 */
	private static function team_rows(): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$a = vh_table( 'assets' );
		$t = vh_table( 'teams' );

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT COALESCE(d.name, %s) AS label,
					a.team_id AS team_id,
					COUNT(*) AS total,
					SUM(f.severity = 'critical') AS critical,
					SUM(f.severity = 'high') AS high,
					SUM(f.severity = 'medium') AS medium,
					SUM(f.severity = 'low') AS low,
					SUM(f.severity = 'info') AS info
				 FROM {$f} f
				 INNER JOIN {$a} a ON a.id = f.asset_id
				 LEFT JOIN {$t} d ON d.id = a.team_id
				 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
				 GROUP BY a.team_id
				 ORDER BY critical DESC, high DESC, total DESC
				 LIMIT 8", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				__( 'Unassigned', 'vulnhub' )
			),
			ARRAY_A
		);
	}

	/**
	 * One URL per severity for a team's slice of the exposure chart.
	 *
	 * @param int $team_id Team, or 0 for assets with no team.
	 * @return array<string,string>
	 */
	private static function team_severity_urls( int $team_id ): array {
		if ( $team_id < 1 ) {
			return array();
		}

		$out = array();

		foreach ( array_keys( vh_severities() ) as $sev ) {
			$out[ $sev ] = VulnHub_Dash_Portal::portal_url(
				'vulnerabilities',
				array( 'team_id' => $team_id, 'severity' => $sev, 'state' => 'open_any' )
			);
		}

		return $out;
	}

	public static function render_team_exposure(): void {
		$rows = self::team_rows();

		echo VulnHub_Dash_Charts::severity_stack( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array_map(
				static fn( array $r ): array => array(
					'label'  => vh_trim( (string) $r['label'], 24 ),
					// Team 0 is "no team", which no filter can express.
					'href'   => (int) $r['team_id'] > 0
						? VulnHub_Dash_Portal::portal_url( 'vulnerabilities', array( 'team_id' => (int) $r['team_id'], 'state' => 'open_any' ) )
						: '',
					'seg_hrefs' => self::team_severity_urls( (int) $r['team_id'] ),
					'counts' => array(
						'critical' => (int) $r['critical'],
						'high'     => (int) $r['high'],
						'medium'   => (int) $r['medium'],
						'low'      => (int) $r['low'],
						'info'     => (int) $r['info'],
					),
				),
				$rows
			),
			array( 'caption' => __( 'Open findings by owning team.', 'vulnhub' ) )
		);
	}

	public static function data_team_exposure(): array {
		return array(
			'headers' => array( __( 'Team', 'vulnhub' ), __( 'Critical', 'vulnhub' ), __( 'High', 'vulnhub' ), __( 'Medium', 'vulnhub' ), __( 'Low', 'vulnhub' ), __( 'Info', 'vulnhub' ), __( 'Total', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['label'],
					(int) $r['critical'],
					(int) $r['high'],
					(int) $r['medium'],
					(int) $r['low'],
					(int) $r['info'],
					(int) $r['total'],
				),
				self::team_rows()
			),
		);
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	private static function ownership_gap_rows( int $limit = 8 ): array {
		global $wpdb;

		$a     = vh_table( 'assets' );
		$types = (array) apply_filters( 'vulnhub_user_bound_asset_types', array( 'workstation', 'mobile' ) );
		$in    = "'" . implode( "','", array_map( 'esc_sql', $types ) ) . "'";

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, hostname, asset_type, lifecycle_status, last_seen
				 FROM {$a}
				 WHERE asset_type IN ({$in}) AND owner_person_id = 0
				   AND lifecycle_status IN (" . vh_reportable_sql() . ")
				 ORDER BY risk_score DESC, hostname ASC
				 LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$limit
			),
			ARRAY_A
		);
	}

	public static function render_ownership_gaps(): void {
		$rows = self::ownership_gap_rows();

		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( __( 'Every workstation and mobile resolves to a person.', 'vulnhub' ) ); // phpcs:ignore
			return;
		}

		echo '<ul class="vh-list">';

		foreach ( $rows as $row ) {
			echo '<li class="vh-list__row">'
				. '<a class="vh-mono" href="' . esc_url( VulnHub_Dash_Portal::portal_url( 'assets', array( 'asset' => (int) $row['id'] ) ) ) . '">'
				. esc_html( (string) $row['hostname'] ) . '</a>'
				. '<span class="vh-meta">' . esc_html( vh_asset_type_label( (string) $row['asset_type'] ) ) . '</span>'
				. '</li>';
		}

		echo '</ul>';

		printf(
			'<p class="vh-sub"><a href="%s">%s</a></p>',
			esc_url( VulnHub_Dash_Portal::portal_url( 'assets', array( 'needs_user' => '1', 'life' => 'reportable' ) ) ),
			esc_html__( 'Review all ownership gaps', 'vulnhub' )
		);
	}

	public static function data_ownership_gaps(): array {
		return array(
			'headers' => array( __( 'Asset', 'vulnhub' ), __( 'Type', 'vulnhub' ), __( 'Lifecycle', 'vulnhub' ), __( 'Last seen', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['hostname'],
					(string) $r['asset_type'],
					(string) $r['lifecycle_status'],
					(string) ( $r['last_seen'] ?? '' ),
				),
				self::ownership_gap_rows( 500 )
			),
		);
	}

	/**
	 * @return array<int,array{label:string,value:int}>
	 */
	private static function asset_type_rows(): array {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$rows = (array) $wpdb->get_results(
			"SELECT asset_type AS label, COUNT(*) AS n FROM {$a}
			 WHERE lifecycle_status IN (" . vh_reportable_sql() . ")
			 GROUP BY asset_type ORDER BY n DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		return array_map(
			static fn( array $r ): array => array(
				'label' => vh_asset_type_label( (string) $r['label'] ),
				'value' => (int) $r['n'],
			),
			$rows
		);
	}

	public static function render_assets_by_type(): void {
		$rows    = self::asset_type_rows();
		$palette = self::palette();
		$total   = array_sum( array_column( $rows, 'value' ) );

		echo VulnHub_Dash_Charts::donut( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array_map(
				static function ( array $r, int $i ) use ( $palette ): array {
					return array(
						'label' => $r['label'],
						'value' => $r['value'],
						'color' => $palette[ $i % count( $palette ) ],
					);
				},
				$rows,
				array_keys( $rows )
			),
			array(
				'centre'       => number_format_i18n( $total ),
				'centre_label' => __( 'assets', 'vulnhub' ),
				'title'        => __( 'Estate by device type', 'vulnhub' ),
			)
		);
	}

	public static function data_assets_by_type(): array {
		return array(
			'headers' => array( __( 'Device type', 'vulnhub' ), __( 'Assets', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array( $r['label'], $r['value'] ),
				self::asset_type_rows()
			),
		);
	}

	/* =================================================================
	 * Widget: exposure by product
	 * ============================================================== */

	/**
	 * Products/components ranked by how many in-scope assets they expose.
	 *
	 * Groups on the stamped `product` column, so this is one indexed
	 * aggregate, not 11k titles parsed at read time. "Vulnerable assets" is
	 * the headline number rather than findings, because the unit of work is a
	 * machine to touch -- one libcurl upgrade clears every finding on a host.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	/**
	 * Product exposure rows, from the materialised table where possible.
	 *
	 * Three layers, cheapest first:
	 *
	 *   1. `summary_products`, rebuilt by the warm job. An index range, and
	 *      the only layer a filter can also read -- which is the reason it
	 *      exists. Caching rendered markup makes the default view instant and
	 *      does nothing at all for `?scope=linux`.
	 *   2. A transient, for a scope the summary has not been built for yet.
	 *   3. product_rows_live(), the aggregate itself.
	 *
	 * The live query stays the single definition of what a product row is;
	 * the summary is a durable copy of its output, not a second
	 * implementation that can drift from it.
	 */
	public static function product_rows( int $limit = 14, string $scope = '' ): array {
		$from_summary = self::product_rows_summary( $limit, $scope );

		if ( null !== $from_summary ) {
			return $from_summary;
		}

		$ck  = 'vh_prod_' . md5( $limit . '|' . $scope . '|' . self::epoch() );
		$hit = get_transient( $ck );

		if ( is_array( $hit ) ) {
			return $hit;
		}

		$rows = self::product_rows_live( $limit, $scope );
		set_transient( $ck, $rows, self::stale_ttl() );

		return $rows;
	}

	/**
	 * Read product rows out of the materialised table, or null if it cannot
	 * serve this request.
	 *
	 * Returns null rather than an empty array when the summary is missing,
	 * stale or has no rows for the scope: an empty array is a legitimate
	 * answer ("no products in this scope") and must not be confused with "the
	 * summary has not been built".
	 *
	 * @return array<int,array<string,mixed>>|null
	 */
	private static function product_rows_summary( int $limit, string $scope ): ?array {
		global $wpdb;

		$table = vh_table( 'summary_products' );
		$state = (array) get_option( self::SUMMARY_KEY, array() );

		// Built against a different epoch means the findings moved under it.
		if ( (string) ( $state['epoch'] ?? '' ) !== self::epoch() ) {
			return null;
		}
		if ( ! in_array( $scope, (array) ( $state['scopes'] ?? array() ), true ) ) {
			return null;
		}

		$sql = "SELECT product, product_slug, product_kind, component_class, assets, findings, bundles
			      FROM {$table} WHERE scope = %s ORDER BY rank_in_scope ASC";
		$args = array( $scope );

		if ( $limit > 0 ) {
			$sql   .= ' LIMIT %d';
			$args[] = $limit;
		}

		$rows = (array) $wpdb->get_results( $wpdb->prepare( $sql, ...$args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		foreach ( $rows as $i => $row ) {
			$rows[ $i ]['assets']   = (int) $row['assets'];
			$rows[ $i ]['findings'] = (int) $row['findings'];
		}

		return $rows;
	}

	/** Where the summary's build state lives: which scopes, at which epoch. */
	public const SUMMARY_KEY = 'vulnhub_summary_products_state';

	/**
	 * Rebuild the materialised product table for every scope.
	 *
	 * Runs inside the warm job, so it costs cron time rather than request
	 * time. Five scopes at ~1.1s each is the price of making /products/ and
	 * every scope filter on it an index read.
	 *
	 * Written scope by scope, each one deleted and reinserted in a single
	 * statement pair, so a reader either sees the previous scope's rows or
	 * the new ones and never half of a rebuild.
	 */
	public static function rebuild_product_summary(): array {
		global $wpdb;

		$table  = vh_table( 'summary_products' );
		$now    = vh_now();
		$built  = array();
		$rows_w = 0;

		foreach ( array_keys( self::product_scopes() ) as $scope ) {
			$rows = self::product_rows_live( 0, (string) $scope );

			$values = array();
			$params = array();

			foreach ( array_values( $rows ) as $rank => $row ) {
				$values[] = '(%s,%s,%s,%s,%s,%d,%d,%s,%d,%s)';
				array_push(
					$params,
					(string) $scope,
					(string) $row['product'],
					(string) $row['product_slug'],
					(string) $row['product_kind'],
					(string) $row['component_class'],
					(int) $row['assets'],
					(int) $row['findings'],
					(string) ( $row['bundles'] ?? '' ),
					$rank + 1,
					$now
				);
			}

			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE scope = %s", $scope ) ); // phpcs:ignore

			if ( $values ) {
				$wpdb->query(
					$wpdb->prepare(
						"INSERT INTO {$table}
						 (scope,product,product_slug,product_kind,component_class,assets,findings,bundles,rank_in_scope,computed_at)
						 VALUES " . implode( ',', $values ), // phpcs:ignore
						...$params
					)
				);
			}

			$built[] = (string) $scope;
			$rows_w += count( $rows );
		}

		update_option(
			self::SUMMARY_KEY,
			array(
				'epoch'  => self::epoch(),
				'scopes' => $built,
				'rows'   => $rows_w,
				'at'     => time(),
			),
			false
		);

		return array( 'scopes' => count( $built ), 'rows' => $rows_w );
	}

	/**
	 * The product exposure aggregate itself. The expensive one.
	 */
	private static function product_rows_live( int $limit = 14, string $scope = '' ): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$v = vh_table( 'vulns' );
		$a = vh_table( 'assets' );

		/*
		 * A vulnerable library found inside an application's install folder is
		 * that app's problem, not a loose OS library: the scan path proves it
		 * (see VH_Product::app_from_output(), stamped onto f.bundle_app). So a
		 * library finding with a bundling app is grouped under the app -- one
		 * "Microsoft Teams" row instead of a slice of a huge "libcurl" one --
		 * and the libraries it carries are gathered for the caption. Everything
		 * else keeps its own product grouping.
		 */
		/*
		 * Informational findings are excluded. Tenable ships a large family of
		 * enumeration plugins -- "Ethernet MAC Addresses", "OS Fingerprints
		 * Detected", "Device Hostname", "Inventory Scan", "Common Platform
		 * Enumeration" -- that carry a plugin name but describe no vulnerable
		 * software. VH_Product::classify() works off that plugin name, so each
		 * one became a "product", and they dominated the widget: on this estate
		 * they took 14 of the top 25 rows, every one severity 'info', pushing
		 * real exposure (Chrome, libcurl, Windows updates) down the list.
		 * Exposure means actual vulnerabilities, so the severity filter is the
		 * honest cut -- and it reads the finding's own severity, since a real
		 * product legitimately carries both info and non-info detections.
		 */
		$is_bundled = "v.product_kind = 'library' AND f.bundle_app <> ''";

		/*
		 * The CASE is resolved in an inner query and grouped in the outer one.
		 * Grouping straight on a CASE alias that reads the same columns let
		 * MariaDB collapse distinct groups together (app A's findings landed
		 * under app B); a derived table pins each row's group first.
		 */
		// Scope narrows the list to an asset type or OS platform. Whitelisted
		// in product_scope_sql(), so the fragment is safe to interpolate.
		$scope_sql = self::product_scope_sql( $scope );

		// The dashboard widget wants a top-N; the products page wants the lot
		// (limit 0). Only the bounded case needs prepare().
		$limit_sql = $limit > 0 ? $wpdb->prepare( ' LIMIT %d', $limit ) : '';

		$rows = (array) $wpdb->get_results(
			"SELECT product, product_slug, product_kind, component_class,
				COUNT(DISTINCT asset_id) AS assets,
				COUNT(*) AS findings,
				GROUP_CONCAT(DISTINCT bundled_lib ORDER BY bundled_lib SEPARATOR ', ') AS bundles
			 FROM (
				SELECT f.asset_id,
					CASE WHEN {$is_bundled} THEN f.bundle_app      ELSE v.product END        AS product,
					CASE WHEN {$is_bundled} THEN f.bundle_app_slug ELSE v.product_slug END   AS product_slug,
					CASE WHEN {$is_bundled} THEN 'application'      ELSE v.product_kind END   AS product_kind,
					CASE WHEN {$is_bundled} THEN 'third_party'      ELSE v.component_class END AS component_class,
					CASE WHEN {$is_bundled} THEN v.product END AS bundled_lib
				FROM {$f} f
				INNER JOIN {$v} v ON v.id = f.vuln_id
				INNER JOIN {$a} a ON a.id = f.asset_id
				WHERE f.state IN ('open','reopened') AND f.exception_id = 0
				  AND a.lifecycle_status IN (" . vh_reportable_sql() . ")
				  AND v.product <> ''
				  AND f.severity <> 'info'
				  {$scope_sql}
			 ) t
			 GROUP BY product, product_slug, product_kind, component_class
			 ORDER BY assets DESC, findings DESC{$limit_sql}", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		return $rows;
	}

	/**
	 * The product-page scopes, in display order: everything, then the two
	 * asset kinds people patch on different cadences, then the two OS worlds.
	 *
	 * @return array<string,string> scope key => label.
	 */
	public static function product_scopes(): array {
		return array(
			''            => __( 'All', 'vulnhub' ),
			'workstation' => __( 'Workstations', 'vulnhub' ),
			'server'      => __( 'Servers', 'vulnhub' ),
			'windows'     => __( 'Windows', 'vulnhub' ),
			'linux'       => __( 'Linux', 'vulnhub' ),
		);
	}

	/**
	 * A WHERE fragment (leading AND, or empty) narrowing product_rows() to a
	 * scope. The scope is one of a fixed set of keys, never free text, so the
	 * fragment carries no caller input and is safe to interpolate.
	 */
	public static function product_scope_sql( string $scope ): string {
		switch ( $scope ) {
			case 'workstation':
				return "AND a.asset_type = 'workstation'";
			case 'server':
				return "AND a.asset_type = 'server'";
			case 'windows':
				return "AND a.operating_system LIKE '%windows%'";
			case 'linux':
				// The Linux families Os::families() knows, matched positively so
				// macOS, network gear and blanks do not fall through to "Linux".
				return "AND ( a.operating_system LIKE '%linux%' OR a.operating_system LIKE '%rhel%'"
					. " OR a.operating_system LIKE '%red hat%' OR a.operating_system LIKE '%ubuntu%'"
					. " OR a.operating_system LIKE '%debian%' OR a.operating_system LIKE '%centos%'"
					. " OR a.operating_system LIKE '%rocky%' OR a.operating_system LIKE '%alma%'"
					. " OR a.operating_system LIKE '%suse%' OR a.operating_system LIKE '%amazon%'"
					. " OR a.operating_system LIKE '%oracle linux%' )";
			default:
				return '';
		}
	}

	/** A brand colour for a product, so the chip is recognisable at a glance. */
	private static function product_colour( string $slug, string $class ): string {
		$brand = (array) apply_filters(
			'vulnhub_product_colours',
			array(
				'libcurl' => '#1a7f5a', 'google-chrome' => '#4285F4', 'microsoft-edge' => '#0C7BB3',
				'mozilla-firefox' => '#E66000', 'sqlite' => '#003B57', 'apache-log4j' => '#D22128',
				'apache-tomcat' => '#F8DC75', 'oracle-java-se' => '#EA2D2E', 'openjdk' => '#EA2D2E',
				'azul-zulu-java' => '#0090C5', 'zoom' => '#2D8CFF', 'node-js' => '#5FA04E',
				'openssl' => '#721412', 'oracle-weblogic' => '#F80000', 'oracle-database' => '#F80000',
				'oracle-coherence' => '#F80000', 'microsoft-net' => '#512BD4', 'microsoft-office' => '#D83B01',
				'microsoft-visual-studio-code' => '#007ACC', '7-zip' => '#0B7A0B', 'docker-desktop' => '#2496ED',
				'notepad-plus-plus' => '#8FD400', 'keepassxc' => '#2C3E7B', 'nvidia' => '#76B900',
				'pandas' => '#150458', 'spring-framework' => '#6DB33F', 'apache-commons-fileupload' => '#D22128',
				// bundling applications (from install-path detection)
				'microsoft-office' => '#D83B01', 'microsoft-teams' => '#6264A7', 'microsoft-edge' => '#0C7BB3',
				'microsoft-photos' => '#0078D4', 'microsoft-phone-link' => '#0078D4', 'microsoft-copilot' => '#0078D4',
				'microsoft-power-bi-desktop' => '#F2C811', 'microsoft-sql-server' => '#CC2927',
				'oracle-sql-developer' => '#F80000', 'salesforce-data-loader' => '#00A1E0', 'aws-cli' => '#FF9900',
				'hp-one-agent' => '#0096D6', 'commvault' => '#E92128', 'soapui' => '#5AA700', 'zoom' => '#2D8CFF',
			)
		);
		if ( isset( $brand[ $slug ] ) ) {
			return $brand[ $slug ];
		}
		// Class defaults, then a deterministic hue for the long tail.
		$by_class = array(
			VH_Product::OS_LINUX   => '#EE0000',
			VH_Product::OS_WINDOWS => '#0078D4',
		);
		if ( isset( $by_class[ $class ] ) ) {
			return $by_class[ $class ];
		}
		$h = (int) ( hexdec( substr( md5( $slug ), 0, 2 ) ) / 255 * 360 );
		return sprintf( 'hsl(%d 45%% 42%%)', $h );
	}

	/**
	 * The icon for a product: a real bundled SVG when we have one, otherwise a
	 * brand-coloured monogram chip. Filterable so real logos are a data drop.
	 */
	/**
	 * A vendor's real logo, downloaded and bundled under assets/vendors, with a
	 * brand-neutral monogram when we have no file for that slug.
	 */
	public static function vendor_icon( string $slug, string $name ): string {
		$file = VULNHUB_DASH_DIR . 'assets/vendors/' . $slug . '.png';
		if ( '' !== $slug && is_readable( $file ) ) {
			return '<span class="vh-vendico"><img src="' . esc_url( VULNHUB_DASH_URL . 'assets/vendors/' . $slug . '.png' )
				. '?v=' . (int) filemtime( $file ) . '" alt="" decoding="async" width="40" height="40"></span>';
		}
		$label = strtoupper( substr( (string) preg_replace( '/[^A-Za-z0-9]/', '', $name ), 0, 2 ) );
		return '<span class="vh-vendico vh-vendico--mono">' . esc_html( $label ?: '?' ) . '</span>';
	}

	/**
	 * The URL of a bundled product logo, or '' when we have none for this slug.
	 * Files live under assets/products/<slug>.{svg,png}; the mtime busts caches.
	 */
	private static function product_logo_src( string $slug ): string {
		if ( '' === $slug ) {
			return '';
		}
		foreach ( array( 'svg', 'png' ) as $ext ) {
			$file = VULNHUB_DASH_DIR . 'assets/products/' . $slug . '.' . $ext;
			if ( is_readable( $file ) ) {
				return VULNHUB_DASH_URL . 'assets/products/' . $slug . '.' . $ext . '?v=' . (int) filemtime( $file );
			}
		}
		return '';
	}

	public static function product_icon( string $slug, string $class, string $name ): string {
		// A real brand logo, bundled under assets/products, wins over the
		// monogram — downloaded from the icon sources and stored locally so
		// there is no run-time network dependency. SVG preferred, PNG (from a
		// favicon) as the fallback source.
		$logo = self::product_logo_src( $slug );
		if ( '' !== $logo ) {
			return '<span class="vh-prodico vh-prodico--logo"><img src="' . esc_url( $logo )
				. '" alt="" decoding="async" width="34" height="34"></span>';
		}

		$colour = self::product_colour( $slug, $class );

		/**
		 * Bundled brand SVGs, keyed by product slug. Each value is the inner
		 * markup of a 0 0 24 24 viewBox. Empty by default; ships as a filter so
		 * a real icon set can be dropped in without touching this file.
		 *
		 * @param array<string,string> $icons slug => inner SVG markup.
		 */
		$icons = (array) apply_filters( 'vulnhub_product_icons', array(
			// Windows: the one logo simple enough to render exactly inline.
			'os_windows_glyph' => '<path fill="#fff" d="M3 5.5l7-1v6.5H3zM11 4.3L21 3v8.9h-10zM3 12.5h7V19l-7-1zM11 12.5h10V21l-10-1.4z"/>',
		) );

		$inner = '';
		if ( VH_Product::OS_WINDOWS === $class ) {
			$inner = $icons['os_windows_glyph'];
		} elseif ( isset( $icons[ $slug ] ) ) {
			$inner = $icons[ $slug ];
		}

		if ( '' !== $inner ) {
			return sprintf(
				'<span class="vh-prodico" style="background:%s"><svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">%s</svg></span>',
				esc_attr( $colour ),
				$inner // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static/filtered SVG markup.
			);
		}

		// Monogram fallback: OS classes get a symbol, products get initials.
		if ( VH_Product::OS_LINUX === $class ) {
			$label = 'L';
		} else {
			$clean = trim( preg_replace( '/^(Linux:|Microsoft|Apache|Oracle|Google|Mozilla)\s+/i', '', $name ) );
			$parts = preg_split( '/[\s\-.]+/', $clean ?: $name );
			$label = strtoupper( substr( (string) ( $parts[0] ?? $name ), 0, 1 ) . ( isset( $parts[1] ) ? substr( $parts[1], 0, 1 ) : '' ) );
			$label = $label ?: strtoupper( substr( $name, 0, 2 ) );
		}
		return sprintf(
			'<span class="vh-prodico vh-prodico--mono" style="background:%s">%s</span>',
			esc_attr( $colour ),
			esc_html( $label )
		);
	}

	public static function product_kind_badge( string $kind ): string {
		$labels = array(
			'library'    => __( 'library', 'vulnhub' ),
			'application'=> __( 'app', 'vulnhub' ),
			'os_package' => __( 'OS', 'vulnhub' ),
			'os_update'  => __( 'OS', 'vulnhub' ),
		);
		$label = $labels[ $kind ] ?? $kind;
		return '<span class="vh-kind vh-kind--' . esc_attr( $kind ) . '">' . esc_html( $label ) . '</span>';
	}

	public static function render_product_exposure(): void {
		$rows = self::product_rows();
		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( __( 'No products classified yet. Run "wp vulnhub classify-products".', 'vulnhub' ) ); // phpcs:ignore
			return;
		}

		$max = max( 1, (int) $rows[0]['assets'] );

		echo '<ul class="vh-prodlist">';
		foreach ( $rows as $r ) {
			$assets = (int) $r['assets'];
			$pct    = (int) round( 100 * $assets / $max );
			$url    = VulnHub_Dash_Portal::portal_url(
				'vulnerabilities',
				array( 'product' => (string) $r['product_slug'], 'life' => 'reportable', 'state' => 'open_any' )
			);

			echo '<li class="vh-prodrow">';
			echo self::product_icon( (string) $r['product_slug'], (string) $r['component_class'], (string) $r['product'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<div class="vh-prodrow__main">';
			echo '<div class="vh-prodrow__head">'
				. '<a class="vh-prodrow__name" href="' . esc_url( $url ) . '">' . esc_html( (string) $r['product'] ) . '</a>'
				. self::product_kind_badge( (string) $r['product_kind'] ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				. '<span class="vh-prodrow__nums">'
				. sprintf(
					/* translators: 1: asset count, 2: finding count. */
					esc_html__( '%1$s assets · %2$s findings', 'vulnhub' ),
					'<strong>' . esc_html( number_format_i18n( $assets ) ) . '</strong>',
					esc_html( number_format_i18n( (int) $r['findings'] ) )
				)
				. '</span></div>';
			echo '<div class="vh-prodrow__bar"><span style="width:' . (int) $pct . '%"></span></div>';

			// When this row is an application carrying vulnerable libraries, say
			// which ones and what to do about it -- that is the actionable line.
			$bundles = trim( (string) ( $r['bundles'] ?? '' ) );
			if ( '' !== $bundles ) {
				echo '<p class="vh-prodrow__note">'
					. sprintf(
						/* translators: %s: comma-separated library names, e.g. "libcurl, SQLite". */
						esc_html__( 'Ships a vulnerable %s inside the app. Update the app, or check the vendor for a fixed release.', 'vulnhub' ),
						'<strong>' . esc_html( $bundles ) . '</strong>'
					)
					. '</p>';
			}

			echo '</div></li>';
		}
		echo '</ul>';
		echo '<p class="vh-sub">' . esc_html__( 'Ranked by in-scope assets affected. A bundled library is attributed to the app that ships it, from its install path. Select a row for the findings behind it.', 'vulnhub' ) . '</p>';
		echo '<p class="vh-prodlist__more"><a class="vh-btn vh-btn--ghost vh-btn--sm" href="' . esc_url( VulnHub_Dash_Portal::portal_url( 'products' ) ) . '">' . esc_html__( 'View all products', 'vulnhub' ) . '</a></p>';
	}

	public static function data_product_exposure(): array {
		return array(
			'headers' => array( __( 'Product', 'vulnhub' ), __( 'Class', 'vulnhub' ), __( 'Kind', 'vulnhub' ), __( 'Vulnerable assets', 'vulnhub' ), __( 'Open findings', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['product'],
					(string) $r['component_class'],
					(string) $r['product_kind'],
					(int) $r['assets'],
					(int) $r['findings'],
				),
				self::product_rows( 100 )
			),
		);
	}

	/* =================================================================
	 * Widgets: remediation
	 * ============================================================== */

	public static function render_remediation_health(): void {
		global $wpdb;

		$s   = Repo::summary();
		$a   = vh_table( 'assets' );
		$f   = vh_table( 'findings' );
		$cov = Coverage::summary();

		$open    = (int) $s['open_total'];
		$overdue = (int) $s['overdue'];
		/*
		 * Both halves of the ratio carry the reporting scope. They used to
		 * carry none at all, so the widget read "835 of 848" while the assets
		 * list it links to said 804 -- two numbers for one estate, and the
		 * bigger one on the front page.
		 */
		$scope   = vh_reportable_sql();
		$owned   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE lifecycle_status IN ({$scope}) AND ( owner_person_id > 0 OR team_id > 0 )" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$assets  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE lifecycle_status IN ({$scope})" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		unset( $f );

		echo VulnHub_Dash_Charts::meter( (float) max( 0, $open - $overdue ), (float) max( 1, $open ), __( 'Findings within SLA', 'vulnhub' ), 'ok' ); // phpcs:ignore
		echo VulnHub_Dash_Charts::meter( (float) $owned, (float) max( 1, $assets ), __( 'Assets with an owner or team', 'vulnhub' ), 'ok' ); // phpcs:ignore
		echo VulnHub_Dash_Charts::meter( (float) $cov['covered'], (float) max( 1, $cov['in_scope'] ), __( 'Estate scanned by Tenable', 'vulnhub' ), 'ok' ); // phpcs:ignore
	}

	public static function data_remediation_health(): array {
		global $wpdb;

		$s      = Repo::summary();
		$a      = vh_table( 'assets' );
		$cov    = Coverage::summary();
		$scope  = vh_reportable_sql();
		$owned  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE lifecycle_status IN ({$scope}) AND ( owner_person_id > 0 OR team_id > 0 )" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$assets = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$a} WHERE lifecycle_status IN ({$scope})" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return array(
			'headers' => array( __( 'Measure', 'vulnhub' ), __( 'Value', 'vulnhub' ), __( 'Of', 'vulnhub' ) ),
			'rows'    => array(
				array( __( 'Findings within SLA', 'vulnhub' ), max( 0, (int) $s['open_total'] - (int) $s['overdue'] ), (int) $s['open_total'] ),
				array( __( 'Assets with an owner or team', 'vulnhub' ), $owned, $assets ),
				array( __( 'Estate scanned by Tenable', 'vulnhub' ), (int) $cov['covered'], (int) $cov['in_scope'] ),
			),
		);
	}

	/**
	 * @return array<int,array{label:string,value:int,color:string}>
	 */
	private static function verification_rows(): array {
		global $wpdb;

		$t    = vh_table( 'tickets' );
		$rows = (array) $wpdb->get_results(
			"SELECT COALESCE(NULLIF(verification_state, ''), 'pending') AS state, COUNT(*) AS n
			 FROM {$t} GROUP BY state", // phpcs:ignore
			ARRAY_A
		);

		$labels = array(
			'confirmed'  => array( __( 'Verified fixed', 'vulnhub' ), 'var(--vh-good)' ),
			'still_open' => array( __( 'Still detected', 'vulnhub' ), 'var(--vh-sev-critical)' ),
			'unknown'    => array( __( 'Cannot verify', 'vulnhub' ), 'var(--vh-sev-medium)' ),
			'pending'    => array( __( 'Not yet checked', 'vulnhub' ), 'var(--vh-muted)' ),
		);

		$out = array();

		foreach ( $rows as $row ) {
			$key   = (string) $row['state'];
			$meta  = $labels[ $key ] ?? array( $key, 'var(--vh-muted)' );
			$out[] = array( 'label' => $meta[0], 'value' => (int) $row['n'], 'color' => $meta[1] );
		}

		return $out;
	}

	public static function render_verification(): void {
		$rows = self::verification_rows();

		echo VulnHub_Dash_Charts::donut( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'title'   => __( 'Closure verification', 'vulnhub' ),
				'caption' => __( 'A ticket marked done is a claim; this is what re-checking Tenable found.', 'vulnhub' ),
				'empty'   => __( 'No tickets have been closed yet.', 'vulnhub' ),
			)
		);
	}

	public static function data_verification(): array {
		return array(
			'headers' => array( __( 'Outcome', 'vulnhub' ), __( 'Tickets', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array( $r['label'], $r['value'] ),
				self::verification_rows()
			),
		);
	}

	/**
	 * @return array<int,array{label:string,value:int,color:string}>
	 */
	private static function ticket_rows(): array {
		global $wpdb;

		$t    = vh_table( 'tickets' );
		$rows = (array) $wpdb->get_results(
			"SELECT COALESCE(NULLIF(status_category, ''), 'unknown') AS c, COUNT(*) AS n
			 FROM {$t} GROUP BY c ORDER BY n DESC", // phpcs:ignore
			ARRAY_A
		);

		$labels = array(
			'todo'        => array( __( 'To do', 'vulnhub' ), 'var(--vh-series-1)' ),
			'in_progress' => array( __( 'In progress', 'vulnhub' ), 'var(--vh-series-2)' ),
			'done'        => array( __( 'Done', 'vulnhub' ), 'var(--vh-good)' ),
			'unknown'     => array( __( 'Unknown', 'vulnhub' ), 'var(--vh-muted)' ),
		);

		$out = array();

		foreach ( $rows as $row ) {
			$key   = (string) $row['c'];
			$meta  = $labels[ $key ] ?? array( $key, 'var(--vh-muted)' );
			$out[] = array( 'label' => $meta[0], 'value' => (int) $row['n'], 'color' => $meta[1] );
		}

		return $out;
	}

	public static function render_ticket_flow(): void {
		$rows  = self::ticket_rows();
		$total = array_sum( array_column( $rows, 'value' ) );

		echo VulnHub_Dash_Charts::donut( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'centre'       => number_format_i18n( $total ),
				'centre_label' => __( 'tickets', 'vulnhub' ),
				'title'        => __( 'Ticket flow', 'vulnhub' ),
				'empty'        => __( 'No tickets have been raised yet.', 'vulnhub' ),
			)
		);
	}

	public static function data_ticket_flow(): array {
		return array(
			'headers' => array( __( 'Status', 'vulnhub' ), __( 'Tickets', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array( $r['label'], $r['value'] ),
				self::ticket_rows()
			),
		);
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	private static function expiring_rows( int $limit = 8 ): array {
		global $wpdb;

		$e = vh_table( 'exceptions' );

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, reference, justification, expires_at, approver_name
				 FROM {$e}
				 WHERE status = 'approved' AND expires_at IS NOT NULL
				 ORDER BY expires_at ASC
				 LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$limit
			),
			ARRAY_A
		);
	}

	public static function render_exceptions_expiring(): void {
		$rows = self::expiring_rows();

		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( __( 'No risk acceptance has an expiry date.', 'vulnhub' ) ); // phpcs:ignore
			return;
		}

		echo '<ul class="vh-list">';

		foreach ( $rows as $row ) {
			echo '<li class="vh-list__row">'
				. '<a class="vh-mono" href="' . esc_url( VulnHub_Dash_Portal::portal_url( 'exceptions' ) ) . '">'
				. esc_html( (string) $row['reference'] ) . '</a>'
				. '<span class="vh-meta">' . esc_html( vh_trim( (string) $row['justification'], 46 ) ) . '</span>'
				. '<span class="vh-list__num">' . esc_html( vh_ago( (string) $row['expires_at'] ) ) . '</span>'
				. '</li>';
		}

		echo '</ul>';
	}

	public static function data_exceptions_expiring(): array {
		return array(
			'headers' => array( __( 'Reference', 'vulnhub' ), __( 'Justification', 'vulnhub' ), __( 'Approver', 'vulnhub' ), __( 'Expires', 'vulnhub' ) ),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['reference'],
					(string) $r['justification'],
					(string) $r['approver_name'],
					(string) $r['expires_at'],
				),
				self::expiring_rows( 200 )
			),
		);
	}

	/* =================================================================
	 * Severity by age
	 * ============================================================== */

	/**
	 * Every open vulnerability, counted once, bucketed by severity and age.
	 *
	 * The unit matters and is the whole point of this table. Counting
	 * findings answers "how much work is there"; counting vulnerabilities
	 * answers "how many distinct things do I have to understand", and those
	 * differ by two orders of magnitude here -- 11,669 vulnerabilities
	 * across 228,728 findings. A patch fixes a vulnerability everywhere at
	 * once, so the first number is the one that sizes the reading, and the
	 * second is the one that sizes the rollout. Both are shown.
	 *
	 * A vulnerability is aged by its OLDEST open instance. One machine that
	 * has carried it for six months is the honest answer to "how long have
	 * we had this", even when it was found on ninety others last week.
	 *
	 * @return array{bands:array<string,array<string,mixed>>,rows:array<int,array<string,mixed>>,totals:array<string,mixed>}
	 */
	private static function severity_age_rows(): array {
		global $wpdb;

		$f     = vh_table( 'findings' );
		$bands = Repo::age_bands();

		/*
		 * Collapse to one row per vulnerability first, then bucket. Doing it
		 * the other way -- bucketing findings and counting distinct vulns
		 * per bucket -- puts the same vulnerability in two columns whenever
		 * its instances straddle a boundary, and the columns stop summing to
		 * the total.
		 */
		/*
		 * Grouped by (vulnerability, severity), not by vulnerability alone.
		 * Tenable re-rates plugins, so 36 findings here still carry the
		 * severity they were given at the time while their definition now
		 * says something else. Grouping on the definition's current severity
		 * put those findings in a row the finding filter would never return,
		 * and the cell stopped agreeing with its own link. The finding's own
		 * severity is what every other screen filters on, so it wins.
		 */
		$rows = (array) $wpdb->get_results(
			"SELECT o.severity AS severity,
				CASE
					WHEN o.oldest IS NULL THEN 'unknown'
					WHEN o.oldest >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY) THEN 'new'
					WHEN o.oldest >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 90 DAY) THEN 'mid'
					ELSE 'old'
				END AS band,
				COUNT(DISTINCT o.vuln_id) AS vulns,
				SUM(o.findings) AS findings
			 FROM (
				SELECT vuln_id, severity, MIN(first_found) AS oldest, COUNT(*) AS findings
				FROM {$f}
				WHERE state IN ('open','reopened') AND exception_id = 0
				GROUP BY vuln_id, severity
			 ) o
			 GROUP BY severity, band", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		$movement = self::severity_movement();
		$blank    = array_fill_keys( array_keys( $bands ), array( 'vulns' => 0, 'findings' => 0 ) );
		$out      = array();

		foreach ( vh_severities() as $slug => $meta ) {
			if ( 'info' === $slug ) {
				continue;
			}

			$out[ $slug ] = array(
				'slug'     => $slug,
				'label'    => (string) $meta['label'],
				'bands'    => $blank,
				'movement' => (int) ( $movement[ $slug ] ?? 0 ),
			);
		}

		foreach ( $rows as $row ) {
			$slug = (string) $row['severity'];
			$band = (string) $row['band'];

			if ( ! isset( $out[ $slug ]['bands'][ $band ] ) ) {
				continue;
			}

			$out[ $slug ]['bands'][ $band ] = array(
				'vulns'    => (int) $row['vulns'],
				'findings' => (int) $row['findings'],
			);
		}

		$totals = array( 'bands' => $blank, 'movement' => 0 );

		foreach ( $out as $row ) {
			foreach ( $row['bands'] as $band => $cell ) {
				$totals['bands'][ $band ]['vulns']    += $cell['vulns'];
				$totals['bands'][ $band ]['findings'] += $cell['findings'];
			}
			$totals['movement'] += (int) $row['movement'];
		}

		return array(
			'bands'  => $bands,
			'rows'   => array_values( $out ),
			'totals' => $totals,
		);
	}

	/**
	 * Vulnerabilities that came back, minus the ones that went away.
	 *
	 * Within a single import this is all that can honestly be said: a
	 * reopened finding is one the scanner had marked fixed and has found
	 * again, and a fixed one is the reverse. Comparing two periods properly
	 * needs a previous import to compare against, which is what the note
	 * under the table says.
	 *
	 * @return array<string,int> Severity slug => net movement.
	 */
	private static function severity_movement(): array {
		global $wpdb;

		$f = vh_table( 'findings' );

		$rows = (array) $wpdb->get_results(
			"SELECT severity,
				COUNT(DISTINCT CASE WHEN state = 'reopened' THEN vuln_id END) AS resurfaced,
				COUNT(DISTINCT CASE WHEN state = 'fixed' THEN vuln_id END) AS fixed
			 FROM {$f}
			 WHERE exception_id = 0
			 GROUP BY severity", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		$out = array();

		foreach ( $rows as $row ) {
			$out[ (string) $row['severity'] ] = (int) $row['resurfaced'] - (int) $row['fixed'];
		}

		return $out;
	}

	/**
	 * Link to the finding list, filtered to one cell of the table.
	 *
	 * @param string $severity Severity slug, or empty for every severity.
	 * @param string $band     Age band key, or empty for every age.
	 * @return string
	 */
	private static function severity_age_url( string $severity, string $band ): string {
		$args = array( 'state' => 'open_any' );

		if ( '' !== $severity ) {
			$args['severity'] = $severity;
		}
		if ( '' !== $band ) {
			$args['age'] = $band;
		}

		return VulnHub_Dash_Portal::portal_url( 'vulnerabilities', $args );
	}

	public static function render_severity_age(): void {
		$data  = self::severity_age_rows();
		$bands = $data['bands'];
		?>
		<div class="vh-matrix" data-vh-matrix>
			<p class="vh-sub vh-matrix__note">
				<?php esc_html_e( 'Each vulnerability is counted once and aged by its oldest open instance, however many assets it affects. The small number is how many asset findings it represents.', 'vulnhub' ); ?>
			</p>

			<div class="vh-matrix__tools">
				<button type="button" class="vh-btn vh-btn--sm" data-vh-copy="table"><?php esc_html_e( 'Copy table', 'vulnhub' ); ?></button>
				<button type="button" class="vh-btn vh-btn--sm vh-btn--ghost" data-vh-copy="tsv"><?php esc_html_e( 'Copy as TSV', 'vulnhub' ); ?></button>
			</div>

			<div class="vh-tablewrap">
				<table class="vh-table vh-matrix__table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Severity', 'vulnhub' ); ?></th>
							<?php foreach ( $bands as $band ) : ?>
								<th scope="col"><?php echo esc_html( (string) $band['label'] ); ?></th>
							<?php endforeach; ?>
							<th scope="col"><?php esc_html_e( 'Movement', 'vulnhub' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $data['rows'] as $row ) : ?>
						<tr>
							<th scope="row" class="vh-matrix__sev">
								<span class="vh-matrix__rule" style="background:<?php echo esc_attr( VulnHub_Dash_Charts::severity_var( (string) $row['slug'] ) ); ?>"></span>
								<?php echo esc_html( (string) $row['label'] ); ?>
							</th>
							<?php foreach ( $bands as $key => $band ) : ?>
								<?php $cell = $row['bands'][ $key ]; ?>
								<td class="vh-matrix__cell">
									<?php if ( $cell['vulns'] > 0 ) : ?>
										<?php
										/*
										 * The cell counts vulnerabilities; the list it opens counts
										 * asset findings, and the two numbers are far apart -- 11
										 * critical vulnerabilities are 1,201 findings. The small
										 * number underneath says so, but a link should also state
										 * where it lands before you follow it, so the count you
										 * are about to see is named in the label and the tooltip.
										 */
										$vh_cell_label = sprintf(
											/* translators: 1: vulnerability count, 2: severity, 3: age band, 4: finding count. */
											__( '%1$s %2$s vulnerabilities %3$s — open the %4$s asset findings behind them', 'vulnhub' ),
											number_format_i18n( $cell['vulns'] ),
											strtolower( (string) $row['label'] ),
											strtolower( (string) $band['label'] ),
											number_format_i18n( $cell['findings'] )
										);
										?>
										<a class="vh-matrix__n<?php echo 'old' === $key ? ' is-aged' : ''; ?>"
											style="<?php echo 'old' === $key ? 'color:' . esc_attr( VulnHub_Dash_Charts::severity_var( (string) $row['slug'] ) ) : ''; ?>"
											title="<?php echo esc_attr( $vh_cell_label ); ?>"
											aria-label="<?php echo esc_attr( $vh_cell_label ); ?>"
											href="<?php echo esc_url( self::severity_age_url( (string) $row['slug'], (string) $key ) ); ?>">
											<?php echo esc_html( number_format_i18n( $cell['vulns'] ) ); ?>
										</a>
										<span class="vh-matrix__sub">
											<?php
											printf(
												/* translators: %s: number of asset findings. */
												esc_html( _n( 'on %s asset finding', 'on %s asset findings', $cell['findings'], 'vulnhub' ) ),
												esc_html( number_format_i18n( $cell['findings'] ) )
											);
											?>
										</span>
									<?php else : ?>
										<span class="vh-matrix__n vh-muted">0</span>
									<?php endif; ?>
								</td>
							<?php endforeach; ?>
							<td class="vh-matrix__move">
								<?php echo self::movement_pill( (int) $row['movement'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
					<tfoot>
						<tr>
							<th scope="row"><?php esc_html_e( 'Total', 'vulnhub' ); ?></th>
							<?php foreach ( $bands as $key => $band ) : ?>
								<?php $cell = $data['totals']['bands'][ $key ]; ?>
								<td class="vh-matrix__cell">
									<a class="vh-matrix__n" href="<?php echo esc_url( self::severity_age_url( '', (string) $key ) ); ?>">
										<?php echo esc_html( number_format_i18n( $cell['vulns'] ) ); ?>
									</a>
									<span class="vh-matrix__sub">
										<?php
										printf(
											/* translators: %s: number of asset findings. */
											esc_html( _n( 'on %s asset finding', 'on %s asset findings', $cell['findings'], 'vulnhub' ) ),
											esc_html( number_format_i18n( $cell['findings'] ) )
										);
										?>
									</span>
								</td>
							<?php endforeach; ?>
							<td class="vh-matrix__move">
								<?php echo self::movement_pill( (int) $data['totals']['movement'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
							</td>
						</tr>
					</tfoot>
				</table>
			</div>

			<p class="vh-matrix__foot">
				<span><?php esc_html_e( 'Movement is vulnerabilities that resurfaced minus those fixed, within the data loaded so far.', 'vulnhub' ); ?></span>
				<span><?php esc_html_e( 'Click any count to filter the vulnerability list.', 'vulnhub' ); ?></span>
			</p>
		</div>
		<?php
	}

	/**
	 * The green-down / red-up pill in the movement column.
	 *
	 * Down is good here, which is the opposite of most trend indicators, so
	 * the arrow and the colour have to agree or the table reads backwards.
	 *
	 * @param int $n Net movement.
	 * @return string
	 */
	private static function movement_pill( int $n ): string {
		if ( 0 === $n ) {
			return '<span class="vh-move vh-move--flat">' . esc_html__( 'no change', 'vulnhub' ) . '</span>';
		}

		return sprintf(
			'<span class="vh-move vh-move--%s">%s%s</span>',
			$n < 0 ? 'good' : 'bad',
			$n < 0 ? '&darr;&nbsp;' : '&uarr;&nbsp;',
			esc_html( ( $n > 0 ? '+' : '' ) . number_format_i18n( $n ) )
		);
	}

	/**
	 * @return array{headers:array<int,string>,rows:array<int,array<int,string>>}
	 */
	public static function data_severity_age(): array {
		$data    = self::severity_age_rows();
		$headers = array( __( 'Severity', 'vulnhub' ) );

		foreach ( $data['bands'] as $band ) {
			$headers[] = (string) $band['label'];
			$headers[] = sprintf(
				/* translators: %s: an age band label. */
				__( '%s (asset findings)', 'vulnhub' ),
				(string) $band['label']
			);
		}

		$headers[] = __( 'Movement', 'vulnhub' );
		$out       = array();

		foreach ( $data['rows'] as $row ) {
			$line = array( (string) $row['label'] );

			foreach ( $row['bands'] as $cell ) {
				$line[] = (string) $cell['vulns'];
				$line[] = (string) $cell['findings'];
			}

			$line[] = (string) $row['movement'];
			$out[]  = $line;
		}

		$line = array( __( 'Total', 'vulnhub' ) );

		foreach ( $data['totals']['bands'] as $cell ) {
			$line[] = (string) $cell['vulns'];
			$line[] = (string) $cell['findings'];
		}

		$line[] = (string) $data['totals']['movement'];
		$out[]  = $line;

		return array(
			'headers' => $headers,
			'rows'    => $out,
		);
	}
}
