<?php
/**
 * "Give me this list as a spreadsheet."
 *
 * Every list in the portal is a query the operator has already narrowed:
 * filtered, sorted, paged. An export that ignores that and dumps the whole
 * table is not the same thing at all -- somebody who has spent five minutes
 * getting to "critical, past SLA, owned by Infrastructure" wants those rows,
 * not 228,000 others.
 *
 * So this takes the same query string the view was rendered with, runs the
 * same repository call with the paging removed, and streams the result.
 *
 * COLUMNS ARE DATA, NOT CODE
 *
 * Each view declares its columns once, in file order, with a label and a
 * callable that turns a row into a cell. The header line, the file body and
 * the column picker in the UI all read that one list -- so a column cannot
 * appear in the header and be missing from the rows, and the picker cannot
 * offer a column the writer does not know how to fill.
 *
 * The callables run only for the columns actually chosen, which is why asking
 * for four columns out of twenty-two does not pay for the other eighteen. On
 * the findings view that matters: the CVE column is a json_decode per row and
 * "Patch available" re-derives the patch test per row.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Coverage;
use VulnHub\Core\Defender_Coverage;
use VulnHub\Core\Eol;
use VulnHub\Core\Os;
use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CSV export for the portal's list views.
 */
final class VulnHub_Dash_Export {

	public const ACTION = 'vulnhub_export_csv';

	/**
	 * Hard ceiling on a single export.
	 *
	 * The reader streams, so this is not a memory limit -- it is a courtesy
	 * one. A 228,000-row CSV is a 90 MB download that Excel will refuse to
	 * open, and somebody who genuinely wants the whole finding table wants
	 * the database, not a spreadsheet.
	 */
	private const MAX_ROWS = 50000;

	/**
	 * Rows fetched per repository call while streaming.
	 *
	 * 500 because that is the repository's own ceiling. Asking for 1,000 and
	 * advancing the offset by 1,000 silently exports every other page.
	 */
	private const PAGE = 500;


	public static function init(): void {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
	}

	/**
	 * The views that can be exported, and what each one needs.
	 *
	 * @return array<string,array{label:string,cap:string}>
	 */
	public static function views(): array {
		return array(
			'assets'        => array(
				'label' => __( 'Assets', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'findings'      => array(
				'label' => __( 'Vulnerability findings', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'vuln_assets'   => array(
				'label' => __( 'Vulnerabilities with affected assets', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'product_remediation' => array(
				'label' => __( 'Product remediation and outdated assets', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'coverage_gaps' => array(
				'label' => __( 'Tenable coverage gaps', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'patch_status'  => array(
				'label' => __( 'Vulnerabilities by patch availability', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'eol'           => array(
				'label' => __( 'End-of-life platforms', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'products'      => array(
				'label' => __( 'Products and applications', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'vendors'       => array(
				'label' => __( 'Vendors', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'vendor_assets'   => array(
				'label' => __( 'Vendor assets', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'vendor_products' => array(
				'label' => __( 'Vendor products', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
			'vendor_findings' => array(
				'label' => __( 'Vendor findings', 'vulnhub' ),
				'cap'   => Caps::VIEW,
			),
		);
	}

	/* =================================================================
	 * Columns
	 * ============================================================== */

	/**
	 * Every column a view can write, in file order.
	 *
	 * Each entry is [ group, label, value ]. `group` only organises the
	 * picker. Everything is on by default, so the button behaves exactly as
	 * it did before the picker existed.
	 *
	 * @return array<string,array{group:string,label:string,value:callable,default:bool}>
	 */
	public static function columns( string $view ): array {
		switch ( $view ) {
			case 'assets':
				$id   = __( 'Identity', 'vulnhub' );
				$plat = __( 'Platform', 'vulnhub' );
				$own  = __( 'Ownership', 'vulnhub' );
				$cov  = __( 'Coverage', 'vulnhub' );
				$keys = __( 'Source identifiers', 'vulnhub' );
				$exp  = __( 'Exposure', 'vulnhub' );

				$cols = array(
					'hostname'      => array( $id, __( 'Hostname', 'vulnhub' ), static fn( array $r ): string => (string) $r['hostname'] ),
					'fqdn'          => array( $id, __( 'FQDN', 'vulnhub' ), static fn( array $r ): string => (string) $r['fqdn'] ),
					'ipv4'          => array( $id, __( 'IPv4', 'vulnhub' ), static fn( array $r ): string => (string) $r['ipv4'] ),
					'asset_type'    => array( $id, __( 'Type', 'vulnhub' ), static fn( array $r ): string => vh_asset_type_label( (string) $r['asset_type'] ) ),
					'os'            => array( $plat, __( 'Operating system', 'vulnhub' ), static fn( array $r ): string => (string) $r['operating_system'] ),
					'os_family'     => array( $plat, __( 'OS family', 'vulnhub' ), static fn( array $r ): string => (string) Os::parse( (string) $r['operating_system'] )['label'] ),
					'lifecycle'     => array( $plat, __( 'Lifecycle', 'vulnhub' ), static fn( array $r ): string => (string) $r['lifecycle_status'] ),
					'owner'         => array( $own, __( 'Owner', 'vulnhub' ), static fn( array $r ): string => self::person_name( (int) $r['owner_person_id'] ) ),
					'team'          => array( $own, __( 'Team', 'vulnhub' ), static fn( array $r ): string => self::team_name( (int) $r['team_id'] ) ),
					'site'          => array( $own, __( 'Site', 'vulnhub' ), static fn( array $r ): string => self::location_name( (int) $r['location_id'] ) ),
					'coverage'      => array( $cov, __( 'Tenable coverage', 'vulnhub' ), static fn( array $r ): string => Coverage::label( (string) $r['coverage_state'] ) ),
					'last_scan'     => array( $cov, __( 'Last Tenable scan', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['tenable_last_scan'] ?? '' ) ),
					'edr'           => array( $cov, __( 'EDR coverage', 'vulnhub' ), static fn( array $r ): string => self::edr_label( $r ) ),
					'edr_last_seen' => array( $cov, __( 'Last Defender contact', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['defender_last_seen'] ?? '' ) ),
					'edr_managed'   => array( $cov, __( 'Defender managed by', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['defender_managed_by'] ?? '' ) ),
					'cmdb_id'       => array( $keys, __( 'CMDB id', 'vulnhub' ), static fn( array $r ): string => (string) $r['cmdb_id'] ),
					'intune_id'     => array( $keys, __( 'Intune id', 'vulnhub' ), static fn( array $r ): string => (string) $r['intune_id'] ),
					'tenable_uuid'  => array( $keys, __( 'Tenable UUID', 'vulnhub' ), static fn( array $r ): string => (string) $r['tenable_uuid'] ),
					'critical'      => array( $exp, __( 'Critical', 'vulnhub' ), static fn( array $r ): string => (string) $r['open_critical'] ),
					'high'          => array( $exp, __( 'High', 'vulnhub' ), static fn( array $r ): string => (string) $r['open_high'] ),
					'medium'        => array( $exp, __( 'Medium', 'vulnhub' ), static fn( array $r ): string => (string) $r['open_medium'] ),
					'low'           => array( $exp, __( 'Low', 'vulnhub' ), static fn( array $r ): string => (string) $r['open_low'] ),
					'risk_score'    => array( $exp, __( 'Risk score', 'vulnhub' ), static fn( array $r ): string => (string) $r['risk_score'] ),
				);
				break;

			case 'findings':
				$asset = __( 'Asset', 'vulnhub' );
				$vuln  = __( 'Vulnerability', 'vulnhub' );
				$sev   = __( 'Severity and scoring', 'vulnhub' );
				$rem   = __( 'Remediation', 'vulnhub' );

				$cols = array(
					'hostname'    => array( $asset, __( 'Asset', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['hostname'] ?: $r['fqdn'] ) ),
					'ipv4'        => array( $asset, __( 'IPv4', 'vulnhub' ), static fn( array $r ): string => (string) $r['ipv4'] ),
					'asset_type'  => array( $asset, __( 'Asset type', 'vulnhub' ), static fn( array $r ): string => vh_asset_type_label( (string) $r['asset_type'] ) ),
					'os'          => array( $asset, __( 'Operating system', 'vulnhub' ), static fn( array $r ): string => (string) $r['operating_system'] ),
					'owner'       => array( $asset, __( 'Owner', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['owner_name'] ?? '' ) ),
					'team'        => array( $asset, __( 'Team', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['team_name'] ?? '' ) ),
					'plugin_id'   => array( $vuln, __( 'Plugin', 'vulnhub' ), static fn( array $r ): string => (string) $r['plugin_id'] ),
					'title'       => array( $vuln, __( 'Vulnerability', 'vulnhub' ), static fn( array $r ): string => (string) $r['vuln_title'] ),
					'family'      => array( $vuln, __( 'Family', 'vulnhub' ), static fn( array $r ): string => (string) $r['family'] ),
					'product'     => array( $vuln, __( 'Product / library', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['product'] ?? '' ) ),
					'bundle_app'  => array( $vuln, __( 'Bundled in app', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['bundle_app'] ?? '' ) ),
					'location'    => array( $asset, __( 'Location', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['location_name'] ?? '' ) ),
					'install_path'=> array( $vuln, __( 'Install path', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['zone_path'] ?: self::install_path( (string) ( $r['output'] ?? '' ) ) ) ),
					'path_zone'   => array( $vuln, __( 'Path zone', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['path_zone'] ?? '' ) ),
					'cve'         => array( $vuln, __( 'CVE', 'vulnhub' ), static fn( array $r ): string => self::cve_list( $r ) ),
					'severity'    => array( $sev, __( 'Severity', 'vulnhub' ), static fn( array $r ): string => (string) $r['severity'] ),
					'cvss3'       => array( $sev, __( 'CVSS v3', 'vulnhub' ), static fn( array $r ): string => (string) $r['cvss3_base'] ),
					'vpr'         => array( $sev, __( 'VPR', 'vulnhub' ), static fn( array $r ): string => (string) $r['vpr_score'] ),
					'risk_score'  => array( $sev, __( 'Risk score', 'vulnhub' ), static fn( array $r ): string => (string) $r['risk_score'] ),
					'exploit'     => array( $sev, __( 'Exploit available', 'vulnhub' ), static fn( array $r ): string => self::yn( ! empty( $r['exploit_available'] ) ) ),
					'patch'       => array( $rem, __( 'Patch available', 'vulnhub' ), static fn( array $r ): string => self::yn( Repo::has_patch( $r ) ) ),
					'solution'    => array( $rem, __( 'Solution', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['solution'] ?? '' ) ),
					'state'       => array( $rem, __( 'State', 'vulnhub' ), static fn( array $r ): string => (string) $r['state'] ),
					'first_found' => array( $rem, __( 'First found', 'vulnhub' ), static fn( array $r ): string => (string) $r['first_found'] ),
					'last_found'  => array( $rem, __( 'Last found', 'vulnhub' ), static fn( array $r ): string => (string) $r['last_found'] ),
					'due_at'      => array( $rem, __( 'Due', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['due_at'] ?? '' ) ),
					'ticket'      => array( $rem, __( 'Ticket', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['ticket_key'] ?? '' ) ),
				);
				break;

			case 'coverage_gaps':
				$asset = __( 'Asset', 'vulnhub' );
				$why   = __( 'The gap', 'vulnhub' );
				$keys  = __( 'Source identifiers', 'vulnhub' );

				$cols = array(
					'hostname'     => array( $asset, __( 'Hostname', 'vulnhub' ), static fn( array $r ): string => (string) $r['hostname'] ),
					'fqdn'         => array( $asset, __( 'FQDN', 'vulnhub' ), static fn( array $r ): string => (string) $r['fqdn'] ),
					'ipv4'         => array( $asset, __( 'IPv4', 'vulnhub' ), static fn( array $r ): string => (string) $r['ipv4'] ),
					'asset_type'   => array( $asset, __( 'Type', 'vulnhub' ), static fn( array $r ): string => vh_asset_type_label( (string) $r['asset_type'] ) ),
					'os'           => array( $asset, __( 'Operating system', 'vulnhub' ), static fn( array $r ): string => (string) $r['operating_system'] ),
					'owner'        => array( $asset, __( 'Owner', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['owner_name'] ?? '' ) ),
					'team'         => array( $asset, __( 'Team', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['team_name'] ?? '' ) ),
					'why'          => array( $why, __( 'Why it is a gap', 'vulnhub' ), static fn( array $r ): string => Coverage::label( (string) $r['coverage_state'] ) ),
					'last_scan'    => array( $why, __( 'Last Tenable scan', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['tenable_last_scan'] ?? '' ) ),
					'cmdb_id'      => array( $keys, __( 'CMDB id', 'vulnhub' ), static fn( array $r ): string => (string) $r['cmdb_id'] ),
					'intune_id'    => array( $keys, __( 'Intune id', 'vulnhub' ), static fn( array $r ): string => (string) $r['intune_id'] ),
					'tenable_uuid' => array( $keys, __( 'Tenable UUID', 'vulnhub' ), static fn( array $r ): string => (string) $r['tenable_uuid'] ),
				);
				break;

			case 'patch_status':
				$g = __( 'Columns', 'vulnhub' );

				$cols = array(
					'severity'  => array( $g, __( 'Severity', 'vulnhub' ), static fn( array $r ): string => (string) $r['severity_label'] ),
					'patchable' => array( $g, __( 'Patch available', 'vulnhub' ), static fn( array $r ): string => self::yn( ! empty( $r['patchable'] ) ) ),
					'vulns'     => array( $g, __( 'Vulnerabilities', 'vulnhub' ), static fn( array $r ): string => (string) $r['vulns'] ),
					'findings'  => array( $g, __( 'Open findings', 'vulnhub' ), static fn( array $r ): string => (string) $r['findings'] ),
					'assets'    => array( $g, __( 'Assets affected', 'vulnhub' ), static fn( array $r ): string => (string) $r['assets'] ),
				);
				break;

			case 'eol':
				$g = __( 'Columns', 'vulnhub' );

				$cols = array(
					'kind'       => array( $g, __( 'Kind', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['kind'] ?? '' ) ),
					'label'      => array( $g, __( 'Platform', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['label'] ?? '' ) ),
					'release'    => array( $g, __( 'Release', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['release'] ?? '' ) ),
					'status'     => array( $g, __( 'Status', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['status_label'] ?? '' ) ),
					'eol'        => array( $g, __( 'End of life', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['eol'] ?? '' ) ),
					'mainstream' => array( $g, __( 'Mainstream ends', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['mainstream'] ?? '' ) ),
					'days'       => array( $g, __( 'Days remaining', 'vulnhub' ), static fn( array $r ): string => null === ( $r['days'] ?? null ) ? '' : (string) $r['days'] ),
					'assets'     => array( $g, __( 'Assets', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['assets'] ?? '' ) ),
					'note'       => array( $g, __( 'Note', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['note'] ?? '' ) ),
				);
				break;

			case 'products':
				$g = __( 'Columns', 'vulnhub' );

				$cols = array(
					'product'  => array( $g, __( 'Product / application', 'vulnhub' ), static fn( array $r ): string => (string) $r['product'] ),
					'kind'     => array( $g, __( 'Kind', 'vulnhub' ), static fn( array $r ): string => self::product_kind_label( (string) $r['product_kind'] ) ),
					'class'    => array( $g, __( 'Platform class', 'vulnhub' ), static fn( array $r ): string => (string) $r['component_class'] ),
					'assets'   => array( $g, __( 'Vulnerable assets', 'vulnhub' ), static fn( array $r ): string => (string) $r['assets'] ),
					'findings' => array( $g, __( 'Open findings', 'vulnhub' ), static fn( array $r ): string => (string) $r['findings'] ),
					'bundles'  => array( $g, __( 'Bundled libraries', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['bundles'] ?? '' ) ),
				);
				break;

			case 'vendors':
				$g = __( 'Vendor', 'vulnhub' );
				$x = __( 'Our exposure', 'vulnhub' );
				$c = __( 'Contact', 'vulnhub' );

				$cols = array(
					'name'      => array( $g, __( 'Vendor', 'vulnhub' ), static fn( array $r ): string => (string) $r['name'] ),
					'kind'      => array( $g, __( 'Kind', 'vulnhub' ), static fn( array $r ): string => (string) $r['kind'] ),
					'hq'        => array( $g, __( 'Headquarters', 'vulnhub' ), static fn( array $r ): string => (string) $r['hq'] ),
					'hw_assets' => array( $x, __( 'Hardware assets', 'vulnhub' ), static fn( array $r ): string => (string) $r['hw_assets'] ),
					'uncovered' => array( $x, __( 'Uncovered assets', 'vulnhub' ), static fn( array $r ): string => (string) $r['uncovered'] ),
					'archived'  => array( $x, __( 'Archived assets', 'vulnhub' ), static fn( array $r ): string => (string) $r['archived'] ),
					'products'  => array( $x, __( 'Software products', 'vulnhub' ), static fn( array $r ): string => (string) $r['products'] ),
					'findings'  => array( $x, __( 'Open findings', 'vulnhub' ), static fn( array $r ): string => (string) $r['findings'] ),
					'crit'      => array( $x, __( 'Critical findings', 'vulnhub' ), static fn( array $r ): string => (string) $r['crit'] ),
					'high'      => array( $x, __( 'High findings', 'vulnhub' ), static fn( array $r ): string => (string) $r['high'] ),
					'band'      => array( $x, __( 'Exposure level', 'vulnhub' ), static fn( array $r ): string => VH_Vendor::band_label( (string) $r['band'] ) ),
					'advisory'  => array( $c, __( 'Security advisories URL', 'vulnhub' ), static fn( array $r ): string => (string) $r['advisory'] ),
					'ratings'   => array( $c, __( 'Public risk rating URL', 'vulnhub' ), static fn( array $r ): string => (string) $r['ratings'] ),
					'domain'    => array( $c, __( 'Primary domain', 'vulnhub' ), static fn( array $r ): string => (string) $r['domain'] ),
				);
				break;

			case 'vendor_assets':
				$g = __( 'Asset', 'vulnhub' );
				$cols = array(
					'hostname'         => array( $g, __( 'Host', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['hostname'] ?? '' ) ),
					'ipv4'             => array( $g, __( 'IPv4', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['ipv4'] ?? '' ) ),
					'asset_type'       => array( $g, __( 'Type', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['asset_type'] ?? '' ) ),
					'operating_system' => array( $g, __( 'Operating system', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['operating_system'] ?? '' ) ),
					'tenable'          => array( $g, __( 'Tenable', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['tenable'] ?? '' ) ),
					'defender'         => array( $g, __( 'Defender', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['defender'] ?? '' ) ),
					'cmdb'             => array( $g, __( 'CMDB', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['cmdb'] ?? '' ) ),
					'lifecycle'        => array( $g, __( 'Lifecycle', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['lifecycle'] ?? '' ) ),
				);
				break;

			case 'vendor_products':
				$g = __( 'Product', 'vulnhub' );
				$cols = array(
					'product'  => array( $g, __( 'Product', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['product'] ?? '' ) ),
					'kind'     => array( $g, __( 'Kind', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['kind'] ?? '' ) ),
					'findings' => array( $g, __( 'Open findings', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['findings'] ?? '' ) ),
					'crit'     => array( $g, __( 'Critical', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['crit'] ?? '' ) ),
					'high'     => array( $g, __( 'High', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['high'] ?? '' ) ),
					'assets'   => array( $g, __( 'Assets', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['assets'] ?? '' ) ),
				);
				break;

			case 'vendor_findings':
				$g = __( 'Finding', 'vulnhub' );
				$cols = array(
					'hostname'    => array( $g, __( 'Asset', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['hostname'] ?? '' ) ),
					'ipv4'        => array( $g, __( 'IPv4', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['ipv4'] ?? '' ) ),
					'product'     => array( $g, __( 'Product', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['product'] ?? '' ) ),
					'severity'    => array( $g, __( 'Severity', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['severity'] ?? '' ) ),
					'title'       => array( $g, __( 'Vulnerability', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['title'] ?? '' ) ),
					// Owner leads, matching the popup. Person and team are also
					// offered separately: the popup has one cell to spend and
					// collapses them, but a spreadsheet can sort or pivot on
					// either, and "who" and "which team" are different questions.
					'owner'       => array( $g, __( 'Owner', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['owner'] ?? '' ) ),
					'owner_name'  => array( $g, __( 'Owner (person)', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['owner_name'] ?? '' ) ),
					'team_name'   => array( $g, __( 'Owner (team)', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['team_name'] ?? '' ) ),
					'plugin_id'   => array( $g, __( 'Plugin', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['plugin_id'] ?? '' ) ),
					'cvss3'       => array( $g, __( 'CVSS v3', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['cvss3'] ?? '' ) ),
					'first_found' => array( $g, __( 'First found', 'vulnhub' ), static fn( array $r ): string => (string) ( $r['first_found'] ?? '' ) ),
				);
				break;

			default:
				return array();
		}

		$out = array();

		foreach ( $cols as $key => $def ) {
			$out[ $key ] = array(
				'group'   => (string) $def[0],
				'label'   => (string) $def[1],
				'value'   => $def[2],
				'default' => true,
			);
		}

		return $out;
	}

	private static function yn( bool $v ): string {
		return $v ? __( 'yes', 'vulnhub' ) : __( 'no', 'vulnhub' );
	}

	/** The human label for a product kind, spelled out for the sheet. */
	private static function product_kind_label( string $kind ): string {
		$labels = array(
			'library'     => __( 'library', 'vulnhub' ),
			'application' => __( 'application', 'vulnhub' ),
			'os_package'  => __( 'OS package', 'vulnhub' ),
			'os_update'   => __( 'OS update', 'vulnhub' ),
		);
		return $labels[ $kind ] ?? $kind;
	}

	/**
	 * `unknown` is the pre-migration default rather than a state anybody set,
	 * so it exports as no answer instead of as one.
	 *
	 * @param array<string,mixed> $r Asset row.
	 */
	private static function edr_label( array $r ): string {
		$state = (string) ( $r['defender_coverage_state'] ?? '' );

		return ( '' === $state || 'unknown' === $state ) ? '' : Defender_Coverage::label( $state );
	}

	/** @param array<string,mixed> $r Finding row. */
	/**
	 * The install path out of a finding's plugin output, for the patch list.
	 *
	 * Delegates to VH_Product, which the popup and the vulnerability table
	 * already use. This was a second, stricter copy of the same regex, so the
	 * CSV and the screen disagreed about whether a finding had a path at all:
	 * it required the path to end in .dll/.jar/.exe/.so/.node and so dropped
	 * every directory install.
	 */
	private static function install_path( string $output ): string {
		return \VH_Product::install_path( $output );
	}

	private static function cve_list( array $r ): string {
		$cves = json_decode( (string) ( $r['cve_json'] ?? '[]' ), true );

		return is_array( $cves ) ? implode( ' ', $cves ) : '';
	}

	/**
	 * The columns this request asked for, in file order.
	 *
	 * Intersecting against the declared order rather than trusting the order
	 * the checkboxes arrived in keeps the spreadsheet's column order stable:
	 * a picker cannot reorder the file by accident, and a hand-written URL
	 * cannot ask for a column that does not exist.
	 *
	 * @return array<string,array{group:string,label:string,value:callable,default:bool}>
	 */
	private static function chosen( string $view ): array {
		$all = self::columns( $view );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw = isset( $_GET['cols'] ) && is_array( $_GET['cols'] )
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			? array_map( 'sanitize_key', wp_unslash( $_GET['cols'] ) )
			: array();

		$picked = array_values( array_intersect( array_keys( $all ), $raw ) );

		if ( ! $picked ) {
			$picked = array_keys( array_filter( $all, static fn( array $c ): bool => ! empty( $c['default'] ) ) );
		}

		$out = array();

		foreach ( $picked as $key ) {
			$out[ $key ] = $all[ $key ];
		}

		return $out;
	}

	/* =================================================================
	 * The button
	 * ============================================================== */

	/**
	 * A link that exports whatever is currently on screen, all columns.
	 *
	 * @param string              $view One of views().
	 * @param array<string,mixed> $args Query arguments to carry over.
	 */
	public static function url( string $view, array $args = array() ): string {
		return wp_nonce_url(
			add_query_arg(
				array_merge(
					self::carried( $args ),
					array(
						'action' => self::ACTION,
						'view'   => $view,
					)
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION . '_' . $view
		);
	}

	/**
	 * The filters an export inherits from the screen it was launched from.
	 *
	 * @param array<string,mixed> $args Query arguments.
	 * @return array<string,string>
	 */
	private static function carried( array $args ): array {
		$args = array_filter(
			$args,
			static fn( $v ): bool => '' !== $v && null !== $v && 0 !== $v && ! is_array( $v )
		);

		// Paging is the one thing an export must not inherit: "page 3 of the
		// filtered list" is not a thing anybody wants in a file.
		unset( $args['limit'], $args['offset'], $args['vp'], $args['ap'] );

		return array_map( 'strval', $args );
	}

	/**
	 * The export control: a button that opens a column picker.
	 *
	 * A plain GET form rather than a link with JavaScript behind it, so it
	 * still works with scripting off -- the same standard the rest of the
	 * portal holds to. It is a <details>, so it costs one click for people
	 * who want the whole sheet and two for people who want four columns.
	 *
	 * @param string              $view View key.
	 * @param array<string,mixed> $args Query arguments.
	 */
	public static function button( string $view, array $args = array(), ?int $count = null, string $noun = '' ): void {
		$def  = self::views()[ $view ] ?? null;
		$cols = self::columns( $view );

		if ( ! $def || ! $cols || ! current_user_can( (string) $def['cap'] ) ) {
			return;
		}

		$noun    = '' !== $noun ? $noun : __( 'rows', 'vulnhub' );
		$scope   = null !== $count
			? sprintf(
				/* translators: 1: a formatted row count, 2: the noun for it, e.g. "findings". */
				__( 'Exporting all %1$s %2$s that match these filters.', 'vulnhub' ),
				number_format_i18n( $count ),
				$noun
			)
			: __( 'The filters on this screen still apply.', 'vulnhub' );
		$dl_label = null !== $count
			? sprintf(
				/* translators: 1: a formatted row count, 2: the noun for it, e.g. "findings". */
				__( 'Download %1$s %2$s', 'vulnhub' ),
				number_format_i18n( $count ),
				$noun
			)
			: __( 'Download CSV', 'vulnhub' );

		$groups = array();

		foreach ( $cols as $key => $col ) {
			$groups[ (string) $col['group'] ][ $key ] = $col;
		}
		?>
		<details class="vh-export">
			<summary class="vh-btn vh-btn--ghost vh-btn--sm">
				<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" width="14" height="14">
					<path d="M12 3v11m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>
				<?php esc_html_e( 'Export CSV', 'vulnhub' ); ?>
			</summary>

			<form class="vh-export__panel" method="get" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION ); ?>">
				<input type="hidden" name="view" value="<?php echo esc_attr( $view ); ?>">
				<?php wp_nonce_field( self::ACTION . '_' . $view, '_wpnonce', false ); ?>
				<?php foreach ( self::carried( $args ) as $vh_k => $vh_v ) : ?>
					<input type="hidden" name="<?php echo esc_attr( (string) $vh_k ); ?>" value="<?php echo esc_attr( $vh_v ); ?>">
				<?php endforeach; ?>

				<?php
				/*
				 * Download sits in the header, not under the checkboxes.
				 *
				 * The panel hangs off the button, and on a long screen a
				 * 22-column list pushed a footer button past the bottom of
				 * the window -- where no amount of scrolling reached it,
				 * because an absolutely positioned panel does not lengthen
				 * the page it hangs from. Up here it is always a few pixels
				 * from the control that opened it, whatever the list does.
				 */
				?>
				<div class="vh-export__head">
					<strong><?php esc_html_e( 'Columns to include', 'vulnhub' ); ?></strong>
					<span class="vh-export__toggles">
						<button type="button" class="vh-linkbtn" data-vh-cols="all"><?php esc_html_e( 'All', 'vulnhub' ); ?></button>
						<button type="button" class="vh-linkbtn" data-vh-cols="none"><?php esc_html_e( 'None', 'vulnhub' ); ?></button>
					</span>
					<button type="submit" class="vh-btn vh-btn--primary vh-btn--sm"><?php echo esc_html( $dl_label ); ?></button>
				</div>

				<?php if ( null !== $count ) : ?>
					<p class="vh-export__scope"><?php echo esc_html( $scope ); ?></p>
				<?php endif; ?>

				<div class="vh-export__cols">
					<?php foreach ( $groups as $vh_group => $vh_items ) : ?>
						<fieldset class="vh-export__group">
							<legend><?php echo esc_html( (string) $vh_group ); ?></legend>
							<?php foreach ( $vh_items as $vh_key => $vh_col ) : ?>
								<label>
									<input type="checkbox" name="cols[]" value="<?php echo esc_attr( (string) $vh_key ); ?>" <?php checked( ! empty( $vh_col['default'] ) ); ?>>
									<span><?php echo esc_html( (string) $vh_col['label'] ); ?></span>
								</label>
							<?php endforeach; ?>
						</fieldset>
					<?php endforeach; ?>
				</div>

				<p class="vh-export__note">
					<?php esc_html_e( 'The filters on this screen still apply. With nothing ticked you get every column.', 'vulnhub' ); ?>
				</p>
			</form>
		</details>
		<?php
	}

	/**
	 * A plain export link, for a view whose file shape is fixed and so has no
	 * column picker to offer. Same nonce and carried filters as button(),
	 * just without the <details> and the checkboxes.
	 *
	 * @param string              $view  View key.
	 * @param array<string,mixed> $args  Query arguments to carry over.
	 * @param string              $label Optional button label.
	 */
	public static function link_button( string $view, array $args = array(), string $label = '', ?int $count = null, string $noun = '' ): void {
		$def = self::views()[ $view ] ?? null;

		if ( ! $def || ! current_user_can( (string) $def['cap'] ) ) {
			return;
		}

		if ( '' === $label ) {
			$label = null !== $count
				? sprintf(
					/* translators: 1: a formatted count, 2: the noun for it, e.g. "vulnerabilities". */
					__( 'Export %1$s %2$s', 'vulnhub' ),
					number_format_i18n( $count ),
					'' !== $noun ? $noun : __( 'rows', 'vulnhub' )
				)
				: __( 'Export CSV', 'vulnhub' );
		}
		?>
		<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::url( $view, $args ) ); ?>">
			<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" width="14" height="14">
				<path d="M12 3v11m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
			</svg>
			<?php echo esc_html( $label ); ?>
		</a>
		<?php
	}

	/* =================================================================
	 * The request
	 * ============================================================== */

	public static function handle(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$view = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : '';
		$def  = self::views()[ $view ] ?? null;

		if ( ! $def ) {
			wp_die( esc_html__( 'There is nothing to export at that address.', 'vulnhub' ), '', array( 'response' => 400 ) );
		}

		if ( ! is_user_logged_in() || ! current_user_can( (string) $def['cap'] ) ) {
			wp_die( esc_html__( 'You do not have permission to export that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION . '_' . $view );

		$cols = self::chosen( $view );

		vulnhub()->logger->audit(
			'export.csv',
			sprintf(
				/* translators: %s: the name of the exported view. */
				__( 'Exported %s as CSV', 'vulnhub' ),
				(string) $def['label']
			),
			'export',
			$view,
			array(
				'query'   => self::audited_query(),
				'columns' => implode( ',', array_keys( $cols ) ),
			)
		);

		self::stream( $view, $cols );
	}

	private static function get( string $key, string $default = '' ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET[ $key ] ) || is_array( $_GET[ $key ] ) ) {
			return $default;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) );
	}

	private static function get_int( string $key ): int {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET[ $key ] ) && ! is_array( $_GET[ $key ] ) ? (int) $_GET[ $key ] : 0;
	}

	/**
	 * Send the headers and write the rows.
	 *
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 */
	private static function stream( string $view, array $cols ): void {
		// A wide remediation export aggregates per product and can run past
		// the default request ceiling; it streams as it goes, so let it finish
		// rather than be truncated to a silent partial file.
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}


		$name = sprintf(
			'vulnhub-%s-%s.csv',
			str_replace( '_', '-', $view ),
			wp_date( 'Y-m-d-Hi' )
		);

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $name . '"' );

		// Anything WordPress or a plugin has already emitted would land in the
		// file as a first line of HTML.
		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}

		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $out ) {
			exit;
		}

		/*
		 * A BOM, because the audience for this file opens it in Excel, and
		 * Excel reads a UTF-8 CSV without one as Windows-1252 -- which turns
		 * every hostname with a non-ASCII character into mojibake.
		 */
		fwrite( $out, "\xEF\xBB\xBF" ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		/*
		 * The vulnerability-on-assets export is two tables in one file, each
		 * with its own header, so it writes them itself rather than taking
		 * the single header-then-rows shape the column-picker views share.
		 */
		if ( 'vuln_assets' === $view ) {
			self::vuln_assets( $out );
			fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			exit;
		}

		if ( 'product_remediation' === $view ) {
			self::product_remediation( $out );
			fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			exit;
		}

		self::put( $out, array_map( static fn( array $c ): string => (string) $c['label'], array_values( $cols ) ) );

		switch ( $view ) {
			case 'assets':
				self::assets( $out, $cols );
				break;
			case 'findings':
				self::findings( $out, $cols );
				break;
			case 'coverage_gaps':
				self::coverage_gaps( $out, $cols );
				break;
			case 'patch_status':
				self::patch_status( $out, $cols );
				break;
			case 'eol':
				self::eol( $out, $cols );
				break;
			case 'products':
				self::products( $out, $cols );
				break;
			case 'vendors':
				self::vendors( $out, $cols );
				break;
			case 'vendor_assets':
			case 'vendor_products':
			case 'vendor_findings':
				self::vendor_drill( $view, $out, $cols );
				break;
		}

		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}

	/**
	 * @param resource          $out Output handle.
	 * @param array<int,string> $row Cells.
	 */
	private static function put( $out, array $row ): void {
		/*
		 * One record, one physical line. A Solution or Description carries
		 * hard line breaks, and while RFC 4180 says a quoted field may span
		 * lines, plenty of things people open a CSV in -- a quick `wc -l`, a
		 * naive importer, a preview pane -- count physical lines and report a
		 * 232-row export as far fewer. Collapsing the breaks inside a value to
		 * spaces makes the row count on disk match the row count on screen
		 * whatever opens it; the prose is still readable, and the full text is
		 * a click away on the vulnerability page.
		 */
		$row = array_map(
			static fn( $v ): string => (string) preg_replace( '/[\r\n]+/', '  ', (string) $v ),
			$row
		);


		/*
		 * The empty escape string is not cosmetic. PHP's default is a
		 * backslash, which is not part of RFC 4180 and which Excel does not
		 * undo -- a solution field ending in a path would arrive with its
		 * quoting mangled. Passing '' gives plain doubled-quote escaping,
		 * which every spreadsheet reads correctly.
		 */
		fputcsv( $out, $row, ',', '"', '' );
	}

	/**
	 * One row, through the chosen columns only.
	 *
	 * @param resource                          $out  Output handle.
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 * @param array<string,mixed>               $row  Source row.
	 */
	private static function emit( $out, array $cols, array $row ): void {
		$line = array();

		foreach ( $cols as $col ) {
			$line[] = (string) call_user_func( $col['value'], $row );
		}

		self::put( $out, $line );
	}

	/**
	 * The filters this export ran with, for the audit trail.
	 *
	 * Worth recording: "who downloaded the asset list" and "who downloaded
	 * every unpatchable critical" are different events.
	 *
	 * @return array<string,string>
	 */
	private static function audited_query(): array {
		$out = array();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		foreach ( (array) $_GET as $key => $value ) {
			$key = sanitize_key( (string) $key );

			if ( in_array( $key, array( 'action', 'view', 'cols', '_wpnonce', '_wp_http_referer' ), true ) || is_array( $value ) ) {
				continue;
			}

			$out[ $key ] = sanitize_text_field( wp_unslash( (string) $value ) );
		}

		return $out;
	}

	/**
	 * Owner names without a query per row.
	 *
	 * A 25,000-row asset export has at most a few hundred distinct owners,
	 * so memoising by id turns a query per row into a query per person.
	 */
	private static function person_name( int $id ): string {
		static $cache = array();

		if ( ! $id ) {
			return '';
		}

		if ( ! array_key_exists( $id, $cache ) ) {
			$person       = Repo::person( $id );
			$cache[ $id ] = (string) ( $person['display_name'] ?? '' );
		}

		return $cache[ $id ];
	}

	/** Team names, fetched once for the whole export. */
	private static function team_name( int $id ): string {
		static $map = null;

		if ( null === $map ) {
			$map = array_column( Repo::teams(), 'name', 'id' );
		}

		return (string) ( $map[ $id ] ?? '' );
	}

	/** Site names, fetched once for the whole export. */
	private static function location_name( int $id ): string {
		static $map = null;

		if ( null === $map ) {
			$map = array_column( Repo::locations(), 'name', 'id' );
		}

		return (string) ( $map[ $id ] ?? '' );
	}

	/* =================================================================
	 * The views
	 * ============================================================== */

	/**
	 * @param resource                          $out  Output handle.
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 */
	private static function assets( $out, array $cols ): void {
		$base = array_filter(
			array(
				'search'              => self::get( 'search' ),
				'asset_type'          => self::get( 'asset_type' ),
				'team_id'             => self::get_int( 'team_id' ),
				'location_id'         => self::get( 'location_id' ),
				'coverage'            => self::get( 'coverage' ),
				/*
				 * Carried explicitly. The assets view resolves `known` into
				 * source/without_source/sole_source before the button sees
				 * it, but `defender` reaches Repo under its own name -- so
				 * without this line an export from a Defender-filtered list
				 * quietly returned the whole estate.
				 */
				'defender'            => self::get( 'defender' ),
				'needs_user'          => self::get( 'needs_user' ),
				'primary_source'      => self::get( 'primary_source' ),
				'operating_system'    => self::get( 'operating_system' ),
				'patch_group'         => self::get( 'patch_group' ),
				'source'              => self::get( 'source' ),
				'without_source'      => self::get( 'without_source' ),
				'sole_source'         => self::get( 'sole_source' ),
				/*
				 * The same three the assets list added: `hosting` reaches Repo
				 * through the vulnhub_assets_query extension, `has`/`missing`
				 * through Repo itself. Carried by name for the same reason
				 * `defender` above is -- a file that quietly holds the whole
				 * estate when the screen showed 210 rows is worse than no file.
				 */
				'hosting'             => self::get( 'hosting' ),
				'has'                 => self::get( 'has' ),
				'missing'             => self::get( 'missing' ),
				'eol'                 => self::get( 'eol' ),
				'lifecycle_status'    => self::get( 'lifecycle_status' ),
				'in_service_only'     => self::get( 'in_service_only' ),
				'out_of_service_only' => self::get( 'out_of_service_only' ),
				'reportable_only'     => self::get( 'reportable_only' ),
				'not_reportable_only' => self::get( 'not_reportable_only' ),
				'orderby'             => self::get( 'orderby', 'risk_score' ),
				'order'               => self::get( 'order', 'DESC' ),
			),
			static fn( $v ): bool => '' !== $v && 0 !== $v
		);

		self::each(
			$base,
			static fn( array $a ): array => Repo::assets( $a ),
			static function ( array $r ) use ( $out, $cols ): void {
				self::emit( $out, $cols, $r );
			}
		);
	}

	/**
	 * @param resource                          $out  Output handle.
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 */
	private static function findings( $out, array $cols ): void {
		$base = array_filter(
			array(
				'state'           => self::get( 'state', 'open_any' ),
				'lifecycle'       => self::get( 'lifecycle' ),
				'severity'        => self::get( 'severity' ),
				'age'             => self::get( 'age' ),
				'asset_type'      => self::get( 'asset_type' ),
				'team_id'         => self::get_int( 'team_id' ),
				'department'      => self::get( 'department' ),
				'hosting'         => self::get( 'hosting' ),
				'location_id'     => self::get( 'location_id' ),
				'search'          => self::get( 'search' ),
				'overdue'         => self::get( 'overdue' ),
				/*
				 * Same trap the Defender filter fell into on the assets
				 * export: the list screen holds this as `product_slug` in
				 * its args, so that is the name the picker carries and the
				 * name to read back. Without it, exporting from "findings
				 * attributed to libcurl" handed back all 228,000 rows.
				 */
				'product_slug'    => self::get( 'product_slug' ),
				'route'           => self::get( 'route' ),
				'delivery'        => self::get( 'delivery' ),
				'poc'             => self::get( 'poc' ),
				'vuln_id'         => self::get_int( 'vuln' ),
				'asset_id'        => self::get_int( 'asset' ),
				/*
				 * An explicit finding-id set: the "export exactly the rows I
				 * ticked" path from the selection bar. When present it stands
				 * alongside the filters (the ids came from this filtered list
				 * in the first place), so the file is those rows and no more.
				 */
				'ids'             => self::get( 'ids' ),
				'patch_available' => self::get( 'patch_available' ),
				/*
				 * The lifecycle-support scope (EOL / in-support) and the
				 * severity-exclusion the download-zone view carries are on
				 * this list for the same reason path_zone and os_platform
				 * are: every filter the screen holds has to be read back
				 * here, or the file silently disagrees with the count above
				 * the button. Leaving `support` off exported EOL and
				 * in-support machines alike from an EOL-only list; leaving
				 * `severity_not` off put Tenable's info file-listings back
				 * into a list that had excluded them.
				 */
				'support'         => self::get( 'support' ),
				'severity_not'    => self::get( 'severity_not' ),
				/*
				 * Same trap again, one filter later: carried() forwards every
				 * arg the list held into the form, but this list is what gets
				 * read back, so a filter missing from here is silently dropped
				 * and the export hands back the whole table. Exporting from
				 * "vulnerable files in Downloads, Windows" returned 52,381
				 * rows instead of 1,819 until these two were added.
				 */
				'path_zone'       => self::get( 'path_zone' ),
				'os_platform'     => self::get( 'os_platform' ),
				'orderby'         => self::get( 'orderby', 'risk_score' ),
				'order'           => self::get( 'order', 'DESC' ),
			),
			static fn( $v ): bool => '' !== $v && 0 !== $v
		);

		self::each(
			$base,
			static fn( array $a ): array => Repo::findings( $a ),
			static function ( array $r ) use ( $out, $cols ): void {
				self::emit( $out, $cols, $r );
			}
		);
	}

	/**
	 * The filters the vulnerability-on-assets export inherits from $_GET,
	 * paging removed. The same set the vulnerabilities screen holds, so the
	 * file matches the tab it was launched from -- support (EOL / in-support)
	 * included.
	 *
	 * @return array<string,mixed>
	 */
	private static function vuln_assets_base(): array {
		return array_filter(
			array(
				'state'           => self::get( 'state', 'open_any' ),
				'lifecycle'       => self::get( 'lifecycle' ),
				'severity'        => self::get( 'severity' ),
				'age'             => self::get( 'age' ),
				'asset_type'      => self::get( 'asset_type' ),
				'team_id'         => self::get_int( 'team_id' ),
				'department'      => self::get( 'department' ),
				'hosting'         => self::get( 'hosting' ),
				'location_id'     => self::get( 'location_id' ),
				'search'          => self::get( 'search' ),
				'overdue'         => self::get( 'overdue' ),
				'product_slug'    => self::get( 'product_slug' ),
				'route'           => self::get( 'route' ),
				'poc'             => self::get( 'poc' ),
				'patch_available' => self::get( 'patch_available' ),
				'support'         => self::get( 'support' ),
				'path_zone'       => self::get( 'path_zone' ),
				'os_platform'     => self::get( 'os_platform' ),
			),
			static fn( $v ): bool => '' !== $v && 0 !== $v
		);
	}

	/**
	 * Two tables in one file: the vulnerabilities that match the filters, each
	 * with its shared facts once (title, CVE, scoring, solution, description),
	 * then every affected asset as its own row -- keyed back to the vuln by
	 * CVE and plugin id, and carrying only what differs per asset, so the
	 * solution and the description are not repeated down thousands of rows.
	 * Each asset row also says whether that host is end of life, because that
	 * is the one lifecycle fact that varies asset by asset under one vuln.
	 *
	 * @param resource $out Output handle.
	 */
	private static function vuln_assets( $out ): void {
		$base = self::vuln_assets_base();

		/* ---- Section one: the vulnerabilities. ---- */
		self::put( $out, array( __( 'Vulnerabilities', 'vulnhub' ) ) );
		self::put(
			$out,
			array(
				__( 'CVE', 'vulnhub' ),
				__( 'Plugin', 'vulnhub' ),
				__( 'Vulnerability', 'vulnhub' ),
				__( 'Family', 'vulnhub' ),
				__( 'Severity', 'vulnhub' ),
				__( 'CVSS v3', 'vulnhub' ),
				__( 'VPR', 'vulnhub' ),
				__( 'Exploit available', 'vulnhub' ),
				__( 'Patch available', 'vulnhub' ),
				__( 'Patch published', 'vulnhub' ),
				__( 'Assets affected', 'vulnhub' ),
				__( 'Open findings', 'vulnhub' ),
				__( 'Solution', 'vulnhub' ),
				__( 'Description', 'vulnhub' ),
			)
		);

		$offset = 0;

		do {
			$page  = Repo::findings( array_merge( $base, array( 'group' => 'vuln', 'limit' => 500, 'offset' => $offset ) ) );
			$vulns = (array) ( $page['vulns'] ?? array() );

			foreach ( $vulns as $v ) {
				self::put(
					$out,
					array(
						self::cve_list( $v ),
						(string) ( $v['plugin_id'] ?? '' ),
						(string) ( $v['title'] ?? '' ),
						(string) ( $v['family'] ?? '' ),
						(string) ( $v['severity'] ?? '' ),
						(string) ( $v['cvss3_base'] ?? '' ),
						(string) ( $v['vpr_score'] ?? '' ),
						self::yn( ! empty( $v['exploit_available'] ) ),
						self::yn( Repo::has_patch( $v ) ),
						(string) ( $v['patch_publication_date'] ?? '' ),
						(string) ( $v['assets'] ?? '' ),
						(string) ( $v['findings'] ?? '' ),
						(string) ( $v['solution'] ?? '' ),
						(string) ( $v['description'] ?? '' ),
					)
				);
			}

			flush();
			$offset += 500;
		} while ( $vulns && $offset < min( self::MAX_ROWS, (int) ( $page['total'] ?? 0 ) ) );

		/* A blank line, then the second table. */
		self::put( $out, array() );

		/* ---- Section two: the affected assets. ---- */
		self::put( $out, array( __( 'Affected assets', 'vulnhub' ) ) );
		self::put(
			$out,
			array(
				__( 'CVE', 'vulnhub' ),
				__( 'Plugin', 'vulnhub' ),
				__( 'Vulnerability', 'vulnhub' ),
				__( 'Severity', 'vulnhub' ),
				__( 'Asset', 'vulnhub' ),
				__( 'IPv4', 'vulnhub' ),
				__( 'Asset type', 'vulnhub' ),
				__( 'Operating system', 'vulnhub' ),
				__( 'End of life', 'vulnhub' ),
				__( 'Owner', 'vulnhub' ),
				__( 'Team', 'vulnhub' ),
				__( 'Location', 'vulnhub' ),
				__( 'Install path', 'vulnhub' ),
				__( 'State', 'vulnhub' ),
				__( 'First found', 'vulnhub' ),
				__( 'Due', 'vulnhub' ),
				__( 'Ticket', 'vulnhub' ),
			)
		);

		self::each(
			array_merge( $base, array( 'orderby' => 'vuln_id', 'order' => 'ASC' ) ),
			static fn( array $a ): array => Repo::findings( $a ),
			static function ( array $r ) use ( $out, $eol ): void {
				self::put(
					$out,
					array(
						self::cve_list( $r ),
						(string) ( $r['plugin_id'] ?? '' ),
						(string) ( $r['vuln_title'] ?? '' ),
						(string) ( $r['severity'] ?? '' ),
						(string) ( $r['hostname'] ?: ( $r['fqdn'] ?? '' ) ),
						(string) ( $r['ipv4'] ?? '' ),
						vh_asset_type_label( (string) ( $r['asset_type'] ?? '' ) ),
						(string) ( $r['operating_system'] ?? '' ),
						self::yn( Eol::finding_is_eol( (int) $r['asset_id'], (int) $r['vuln_id'], (string) ( $r['component_class'] ?? '' ) ) ),
						(string) ( $r['owner_name'] ?? '' ),
						(string) ( $r['team_name'] ?? '' ),
						(string) ( $r['location_name'] ?? '' ),
						(string) ( $r['zone_path'] ?: self::install_path( (string) ( $r['output'] ?? '' ) ) ),
						(string) ( $r['state'] ?? '' ),
						(string) ( $r['first_found'] ?? '' ),
						(string) ( $r['due_at'] ?? '' ),
						(string) ( $r['ticket_key'] ?? '' ),
					)
				);
			}
		);
	}

	/**
	 * The remediation export: for each product in scope, the one update that
	 * clears it and the assets still on an old version. De-duplicated by
	 * design -- no per-version "X is vulnerable, Y is vulnerable" repetition,
	 * just "update to the newest release, and here is who has not". Two
	 * sections: a product summary, then the outdated assets under each.
	 *
	 * @param resource $out Output handle.
	 */
	private static function product_remediation( $out ): void {
		$base = self::vuln_assets_base();

		$products = (array) ( Repo::findings( array_merge( $base, array( 'group' => 'product', 'limit' => 500 ) ) )['products'] ?? array() );

		/* ---- Section one: what to update. ---- */
		self::put( $out, array( __( 'Remediation', 'vulnhub' ) ) );
		self::put(
			$out,
			array(
				__( 'Product', 'vulnhub' ),
				__( 'Update to (or later)', 'vulnhub' ),
				__( 'Vulnerabilities fixed', 'vulnhub' ),
				__( 'CVEs', 'vulnhub' ),
				__( 'Outdated assets', 'vulnhub' ),
				__( 'Highest severity', 'vulnhub' ),
				__( 'Exploit available', 'vulnhub' ),
				__( 'Patch available', 'vulnhub' ),
				__( 'CVE list', 'vulnhub' ),
			)
		);

		$remediations = array();

		foreach ( $products as $p ) {
			$slug = (string) $p['product_slug'];
			$rem  = VulnHub_Dash_App::product_remediation( $slug, $base );

			if ( ! $rem['assets'] ) {
				continue;
			}

			$remediations[] = $rem;

			self::put(
				$out,
				array(
					(string) $rem['product'],
					(string) $rem['target'],
					(string) $rem['vulns'],
					(string) $rem['cves'],
					(string) count( $rem['assets'] ),
					(string) $rem['max_severity'],
					self::yn( (bool) $rem['exploit'] ),
					self::yn( (bool) $rem['patchable'] ),
					implode( ' ', $rem['cve_list'] ),
				)
			);
			flush();
		}

		self::put( $out, array() );

		/* ---- Section two: who is outdated. ---- */
		self::put( $out, array( __( 'Outdated assets', 'vulnhub' ) ) );
		self::put(
			$out,
			array(
				__( 'Product', 'vulnhub' ),
				__( 'Update to (or later)', 'vulnhub' ),
				__( 'Asset', 'vulnhub' ),
				__( 'IPv4', 'vulnhub' ),
				__( 'Asset type', 'vulnhub' ),
				__( 'Operating system', 'vulnhub' ),
				__( 'Owner', 'vulnhub' ),
				__( 'Team', 'vulnhub' ),
				__( 'Location', 'vulnhub' ),
				__( 'Vulnerabilities on asset', 'vulnhub' ),
				__( 'Due', 'vulnhub' ),
				__( 'Ticket', 'vulnhub' ),
			)
		);

		foreach ( $remediations as $rem ) {
			foreach ( $rem['assets'] as $a ) {
				self::put(
					$out,
					array(
						(string) $rem['product'],
						(string) $rem['target'],
						(string) $a['hostname'],
						(string) $a['ipv4'],
						vh_asset_type_label( (string) $a['asset_type'] ),
						(string) $a['os'],
						(string) $a['owner_name'],
						(string) $a['team_name'],
						(string) $a['location'],
						(string) $a['findings'],
						(string) $a['due_at'],
						(string) $a['ticket_key'],
					)
				);
			}
			flush();
		}
	}

	/**
	 * @param resource                          $out  Output handle.
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 */
	private static function coverage_gaps( $out, array $cols ): void {
		$offset = 0;

		do {
			$page = Coverage::gaps(
				array(
					'state'      => self::get( 'state' ),
					'asset_type' => self::get( 'asset_type' ),
					'team_id'    => self::get_int( 'team_id' ),
					'search'     => self::get( 'search' ),
					'limit'      => 500,
					'offset'     => $offset,
				)
			);

			foreach ( $page['rows'] as $r ) {
				self::emit( $out, $cols, $r );
			}

			$offset += 500;
		} while ( $page['rows'] && $offset < min( self::MAX_ROWS, (int) $page['total'] ) );
	}

	/**
	 * @param resource                          $out  Output handle.
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 */
	private static function patch_status( $out, array $cols ): void {
		foreach ( VulnHub_Dash_Patching::matrix() as $row ) {
			self::emit( $out, $cols, $row );
		}
	}

	/**
	 * Everything the lifecycle screen knows, in one file.
	 *
	 * Platforms, software and hardware go into the same CSV with a `Kind`
	 * column rather than into three downloads, because the question people
	 * take away from this screen -- "what is the estate's lifecycle debt?" --
	 * is answered by all three together.
	 *
	 * @param resource                          $out  Output handle.
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 */
	private static function eol( $out, array $cols ): void {
		$sections = array(
			__( 'Operating system', 'vulnhub' ) => Eol::estate(),
			__( 'Software', 'vulnhub' )         => Eol::software(),
		);

		foreach ( $sections as $kind => $rows ) {
			foreach ( $rows as $row ) {
				$row['kind'] = (string) $kind;
				self::emit( $out, $cols, $row );
			}
		}

		foreach ( Eol::hardware() as $row ) {
			self::emit(
				$out,
				$cols,
				array(
					'kind'   => __( 'Hardware support', 'vulnhub' ),
					'label'  => (string) $row['label'],
					'assets' => (string) $row['assets'],
					'days'   => null,
				)
			);
		}
	}

	/**
	 * Every detected product and bundling application, in the current scope.
	 *
	 * The same query the dashboard widget and the products page run (limit 0,
	 * all rows), through VulnHub_Dash_Widgets so there is one definition of
	 * "a product row" and the CSV can never drift from the screen. The scope
	 * filter rides in on the query string, exactly as the page passed it.
	 *
	 * @param resource                          $out  Output handle.
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 */
	private static function products( $out, array $cols ): void {
		$scope = self::get( 'scope' );

		foreach ( VulnHub_Dash_Widgets::product_rows( 0, $scope ) as $row ) {
			self::emit( $out, $cols, $row );
		}
	}

	/**
	 * Every vendor in the estate, in the current scope. The scope filter rides
	 * in on the query string, exactly as the page passed it.
	 *
	 * @param resource                          $out  Output handle.
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 */
	private static function vendors( $out, array $cols ): void {
		$scope = self::get( 'scope' );

		foreach ( VH_Vendor::vendors( $scope ) as $row ) {
			self::emit( $out, $cols, $row );
		}
	}

	/**
	 * A vendor drill list (assets / products / findings), unpaginated, through
	 * the same VH_Vendor::drill() the modal reads, so the CSV and the popup are
	 * the same rows. The metric, search and severity ride in on the query
	 * string exactly as the modal passed them.
	 *
	 * @param resource                          $out  Output handle.
	 * @param array<string,array<string,mixed>> $cols Chosen columns.
	 */
	private static function vendor_drill( string $view, $out, array $cols ): void {
		$slug   = self::get( 'vendor' );
		$metric = self::get( 'metric' );
		if ( 'vendor_products' === $view ) {
			$metric = 'products';
		} elseif ( 'vendor_findings' === $view && '' === $metric ) {
			$metric = 'findings';
		} elseif ( 'vendor_assets' === $view && ! in_array( $metric, array( 'assets', 'uncovered', 'archived' ), true ) ) {
			$metric = 'assets';
		}
		$res = VH_Vendor::drill(
			$slug,
			$metric,
			array( 'per' => 0, 'q' => self::get( 'q' ), 'severity' => self::get( 'severity' ) )
		);
		foreach ( (array) $res['rows'] as $row ) {
			self::emit( $out, $cols, $row );
		}
	}

	/* =================================================================
	 * Streaming
	 * ============================================================== */

	/**
	 * Page through a repository call, writing as we go.
	 *
	 * The repository already caps a single call at 500 rows, and holding
	 * 50,000 hydrated findings in memory to write them afterwards would put
	 * the request back into the swap-and-die territory the importer was built
	 * to avoid. One page in memory at a time, flushed after each.
	 *
	 * @param array<string,mixed>                $base  Query arguments.
	 * @param callable(array):array              $query Repository call.
	 * @param callable(array<string,mixed>):void $write Row writer.
	 */
	private static function each( array $base, callable $query, callable $write ): void {
		$offset = 0;

		do {
			$page = $query( array_merge( $base, array( 'limit' => self::PAGE, 'offset' => $offset ) ) );
			$rows = (array) ( $page['rows'] ?? array() );

			foreach ( $rows as $row ) {
				$write( $row );
			}

			flush();

			$offset += self::PAGE;
		} while ( $rows && $offset < min( self::MAX_ROWS, (int) ( $page['total'] ?? 0 ) ) );
	}
}

