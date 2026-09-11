<?php
/**
 * Database schema installer / migrator.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Creates and migrates every VulnHub table via dbDelta.
 *
 * dbDelta is picky: two spaces after PRIMARY KEY, lowercase column types,
 * KEY (not INDEX), and no backticks around index names.
 */
final class Install {

	public static function run(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		self::pre_migrate();

		$charset = $wpdb->get_charset_collate();
		$p       = $wpdb->prefix . 'vulnhub_';

		$sql = array();

		/* ---------------------------------------------------------------
		 * People (owners) — sourced from Intune/Entra, CMDB or manual.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}people (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			source varchar(32) NOT NULL DEFAULT 'manual',
			source_uid varchar(191) NOT NULL DEFAULT '',
			upn varchar(191) NOT NULL DEFAULT '',
			email varchar(191) NOT NULL DEFAULT '',
			display_name varchar(191) NOT NULL DEFAULT '',
			given_name varchar(100) NOT NULL DEFAULT '',
			surname varchar(100) NOT NULL DEFAULT '',
			job_title varchar(191) NOT NULL DEFAULT '',
			department varchar(191) NOT NULL DEFAULT '',
			company varchar(191) NOT NULL DEFAULT '',
			employee_id varchar(64) NOT NULL DEFAULT '',
			manager_upn varchar(191) NOT NULL DEFAULT '',
			manager_name varchar(191) NOT NULL DEFAULT '',
			office_location varchar(191) NOT NULL DEFAULT '',
			city varchar(100) NOT NULL DEFAULT '',
			state varchar(100) NOT NULL DEFAULT '',
			country varchar(100) NOT NULL DEFAULT '',
			usage_location varchar(8) NOT NULL DEFAULT '',
			team_id bigint(20) unsigned NOT NULL DEFAULT 0,
			location_id bigint(20) unsigned NOT NULL DEFAULT 0,
			wp_user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			is_active tinyint(1) NOT NULL DEFAULT 1,
			groups_json longtext NULL,
			raw_json longtext NULL,
			last_synced_at datetime NULL,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY source_uid (source,source_uid),
			KEY upn (upn),
			KEY email (email),
			KEY team_id (team_id),
			KEY location_id (location_id),
			KEY department (department)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Teams — the unit that owns remediation and carries SLAs.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}teams (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			name varchar(191) NOT NULL DEFAULT '',
			slug varchar(191) NOT NULL DEFAULT '',
			source varchar(32) NOT NULL DEFAULT 'manual',
			source_uid varchar(191) NOT NULL DEFAULT '',
			description text NULL,
			manager_email varchar(191) NOT NULL DEFAULT '',
			jira_project_key varchar(64) NOT NULL DEFAULT '',
			jira_default_assignee varchar(191) NOT NULL DEFAULT '',
			jira_issue_type varchar(64) NOT NULL DEFAULT '',
			sla_critical_days smallint(5) unsigned NOT NULL DEFAULT 7,
			sla_high_days smallint(5) unsigned NOT NULL DEFAULT 30,
			sla_medium_days smallint(5) unsigned NOT NULL DEFAULT 90,
			sla_low_days smallint(5) unsigned NOT NULL DEFAULT 180,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY slug (slug),
			KEY source_uid (source,source_uid)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Locations — office / site / region.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}locations (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			name varchar(191) NOT NULL DEFAULT '',
			slug varchar(191) NOT NULL DEFAULT '',
			source varchar(32) NOT NULL DEFAULT 'manual',
			city varchar(100) NOT NULL DEFAULT '',
			state varchar(100) NOT NULL DEFAULT '',
			country varchar(100) NOT NULL DEFAULT '',
			region varchar(100) NOT NULL DEFAULT '',
			timezone varchar(64) NOT NULL DEFAULT '',
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY slug (slug),
			KEY country (country)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Assets — the merged view across Tenable / Intune / CMDB.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}assets (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			primary_source varchar(32) NOT NULL DEFAULT 'tenable',
			tenable_uuid varchar(64) NOT NULL DEFAULT '',
			intune_id varchar(64) NOT NULL DEFAULT '',
			azure_ad_device_id varchar(64) NOT NULL DEFAULT '',
			azure_vm_id varchar(191) NOT NULL DEFAULT '',
			aws_instance_id varchar(128) NOT NULL DEFAULT '',
			gcp_instance_id varchar(128) NOT NULL DEFAULT '',
			cloud_provider varchar(32) NOT NULL DEFAULT '',
			cloud_account_id varchar(64) NOT NULL DEFAULT '',
			cloud_region varchar(64) NOT NULL DEFAULT '',
			patch_group varchar(96) NOT NULL DEFAULT '',
			cmdb_key varchar(64) NOT NULL DEFAULT '',
			sources_json varchar(191) NOT NULL DEFAULT '',
			support_end_date date NULL,
			cmdb_last_scan datetime NULL,
			cmdb_id varchar(191) NOT NULL DEFAULT '',
			hostname varchar(191) NOT NULL DEFAULT '',
			fqdn varchar(255) NOT NULL DEFAULT '',
			netbios_name varchar(191) NOT NULL DEFAULT '',
			ipv4 varchar(45) NOT NULL DEFAULT '',
			ipv4s text NULL,
			ipv6 varchar(64) NOT NULL DEFAULT '',
			mac_address varchar(64) NOT NULL DEFAULT '',
			serial_number varchar(128) NOT NULL DEFAULT '',
			asset_type varchar(32) NOT NULL DEFAULT 'unknown',
			operating_system varchar(191) NOT NULL DEFAULT '',
			os_version varchar(100) NOT NULL DEFAULT '',
			manufacturer varchar(128) NOT NULL DEFAULT '',
			model varchar(128) NOT NULL DEFAULT '',
			criticality varchar(16) NOT NULL DEFAULT 'medium',
			environment varchar(32) NOT NULL DEFAULT '',
			business_service varchar(191) NOT NULL DEFAULT '',
			compliance_state varchar(32) NOT NULL DEFAULT '',
			lifecycle_status varchar(32) NOT NULL DEFAULT 'unknown',
			tenable_last_scan datetime NULL,
			defender_id varchar(64) NOT NULL DEFAULT '',
			defender_first_seen datetime NULL,
			defender_last_seen datetime NULL,
			defender_onboarding varchar(32) NOT NULL DEFAULT '',
			defender_health varchar(32) NOT NULL DEFAULT '',
			defender_risk varchar(24) NOT NULL DEFAULT '',
			defender_exposure varchar(24) NOT NULL DEFAULT '',
			defender_managed_by varchar(64) NOT NULL DEFAULT '',
			defender_coverage_state varchar(24) NOT NULL DEFAULT 'unknown',
			coverage_state varchar(24) NOT NULL DEFAULT 'unknown',
			enrollment_type varchar(64) NOT NULL DEFAULT '',
			join_type varchar(32) NOT NULL DEFAULT '',
			has_agent tinyint(1) NOT NULL DEFAULT 0,
			is_managed tinyint(1) NOT NULL DEFAULT 0,
			owner_person_id bigint(20) unsigned NOT NULL DEFAULT 0,
			owner_source varchar(32) NOT NULL DEFAULT '',
			owner_confidence varchar(16) NOT NULL DEFAULT '',
			owner_rule varchar(191) NOT NULL DEFAULT '',
			team_id bigint(20) unsigned NOT NULL DEFAULT 0,
			location_id bigint(20) unsigned NOT NULL DEFAULT 0,
			tags_json longtext NULL,
			software_json longtext NULL,
			raw_json longtext NULL,
			first_seen datetime NULL,
			last_seen datetime NULL,
			last_intune_sync datetime NULL,
			last_synced_at datetime NULL,
			open_critical int(10) unsigned NOT NULL DEFAULT 0,
			open_high int(10) unsigned NOT NULL DEFAULT 0,
			open_medium int(10) unsigned NOT NULL DEFAULT 0,
			open_low int(10) unsigned NOT NULL DEFAULT 0,
			risk_score decimal(8,2) NOT NULL DEFAULT 0.00,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			KEY tenable_uuid (tenable_uuid),
			KEY intune_id (intune_id),
			KEY azure_vm_id (azure_vm_id),
			KEY azure_ad_device_id (azure_ad_device_id),
			KEY hostname (hostname),
			KEY asset_type (asset_type),
			KEY owner_person_id (owner_person_id),
			KEY team_id (team_id),
			KEY location_id (location_id),
			KEY risk_score (risk_score),
			KEY serial_number (serial_number),
			KEY mac_address (mac_address),
			KEY fqdn (fqdn),
			KEY lifecycle_status (lifecycle_status),
			KEY coverage_state (coverage_state,asset_type),
			KEY cloud_account_id (cloud_account_id),
			KEY patch_group (patch_group),
			KEY support_end_date (support_end_date),
			KEY cmdb_last_scan (cmdb_last_scan),
			KEY sources_json (sources_json),
			KEY tenable_last_scan (tenable_last_scan),
			KEY defender_id (defender_id),
			KEY defender_last_seen (defender_last_seen),
			KEY defender_onboarding (defender_onboarding),
			KEY defender_coverage_state (defender_coverage_state,asset_type),
			KEY criticality (criticality),
			KEY primary_source (primary_source),
			KEY operating_system (operating_system),
			KEY environment (environment),
			KEY compliance_state (compliance_state)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Vulnerability definitions (the plugin/CVE catalogue).
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}vulns (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			source varchar(32) NOT NULL DEFAULT 'tenable',
			plugin_id varchar(64) NOT NULL DEFAULT '',
			title varchar(255) NOT NULL DEFAULT '',
			family varchar(191) NOT NULL DEFAULT '',
			severity varchar(16) NOT NULL DEFAULT 'info',
			severity_id tinyint(3) unsigned NOT NULL DEFAULT 0,
			cve_json text NULL,
			cvss2_base decimal(4,1) NOT NULL DEFAULT 0.0,
			cvss3_base decimal(4,1) NOT NULL DEFAULT 0.0,
			vpr_score decimal(4,1) NOT NULL DEFAULT 0.0,
			exploit_available tinyint(1) NOT NULL DEFAULT 0,
			patch_publication_date date NULL,
			description longtext NULL,
			solution longtext NULL,
			see_also text NULL,
			component_class varchar(16) NOT NULL DEFAULT '',
			product varchar(191) NOT NULL DEFAULT '',
			product_kind varchar(16) NOT NULL DEFAULT '',
			product_slug varchar(191) NOT NULL DEFAULT '',
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY source_plugin (source,plugin_id),
			KEY severity (severity),
			KEY vpr_score (vpr_score),
			KEY product_slug (product_slug),
			KEY component_class (component_class)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Findings — one row per (asset, vuln, port). The working set.
		 *
		 * The composite keys below were measured against 25,112 assets and
		 * 425,289 findings; see docs/LOADTEST.md. Two things to know before
		 * changing them:
		 *
		 * 1. Column ORDER matters more than the column set. `state` has two
		 *    useful values and `state IN ('open','reopened')` matches 83% of
		 *    the table, so it is a poor leading column. `exc_state_sev` leads
		 *    on exception_id (an equality) for exactly that reason;
		 *    (state,exception_id,severity) was measurably worse.
		 * 2. Single-column keys that are leading prefixes of these composites
		 *    are not merely redundant, they mislead the optimiser -- a bare
		 *    `exception_id` key had `GROUP BY severity` scanning 416,890 rows.
		 *    pre_migrate() drops asset_id, vuln_id, state, exception_id and
		 *    state_severity (superseded by state_sev_risk, whose trailing
		 *    risk_score makes the severity-filtered listing covering rather
		 *    than "Using index condition" plus a filesort of 18,608 rows).
		 * 3. state_risk carries vuln_id and asset_id it never filters on, so
		 *    that the default listing stays covering when the search rewrite
		 *    adds `f.vuln_id IN (...) OR f.asset_id IN (...)`. Without them
		 *    the ordered scan did a primary-key lookup per row to test
		 *    membership: 9 seconds for a search on "CVE", 0.13 with them.
		 *
		 * dbDelta parses this SQL a line at a time, so no comments in here.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}findings (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			fingerprint char(64) NOT NULL DEFAULT '',
			asset_id bigint(20) unsigned NOT NULL DEFAULT 0,
			vuln_id bigint(20) unsigned NOT NULL DEFAULT 0,
			source varchar(32) NOT NULL DEFAULT 'tenable',
			severity varchar(16) NOT NULL DEFAULT 'info',
			state varchar(16) NOT NULL DEFAULT 'open',
			port int(10) unsigned NOT NULL DEFAULT 0,
			protocol varchar(16) NOT NULL DEFAULT '',
			service varchar(64) NOT NULL DEFAULT '',
			output longtext NULL,
			risk_score decimal(8,2) NOT NULL DEFAULT 0.00,
			ticket_id bigint(20) unsigned NOT NULL DEFAULT 0,
			exception_id bigint(20) unsigned NOT NULL DEFAULT 0,
			first_found datetime NULL,
			last_found datetime NULL,
			last_fixed datetime NULL,
			due_at datetime NULL,
			verification_state varchar(24) NOT NULL DEFAULT '',
			verified_at datetime NULL,
			prev_state varchar(16) NOT NULL DEFAULT '',
			archived_at datetime NULL,
			scan_uuid varchar(64) NOT NULL DEFAULT '',
			bundle_app varchar(191) NOT NULL DEFAULT '',
			bundle_app_slug varchar(191) NOT NULL DEFAULT '',
			last_synced_at datetime NULL,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY fingerprint (fingerprint),
			KEY bundle_app_slug (bundle_app_slug),
			KEY severity (severity),
			KEY ticket_id (ticket_id),
			KEY due_at (due_at),
			KEY state_sev_risk (state,severity,risk_score),
			KEY verification_state (verification_state),
			KEY state_risk (state,risk_score,vuln_id,asset_id),
			KEY state_last_fixed (state,last_fixed),
			KEY exc_state_sev (exception_id,state,severity),
			KEY vuln_state_exc (vuln_id,state,exception_id,severity,ticket_id,asset_id),
			KEY exc_state_first (exception_id,state,first_found,severity),
			KEY asset_state_exc (asset_id,state,exception_id,severity),
			KEY archived_at (archived_at)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Tickets — Jira issues raised from findings.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}tickets (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			provider varchar(32) NOT NULL DEFAULT 'jira',
			external_id varchar(64) NOT NULL DEFAULT '',
			external_key varchar(64) NOT NULL DEFAULT '',
			url varchar(255) NOT NULL DEFAULT '',
			project_key varchar(64) NOT NULL DEFAULT '',
			issue_type varchar(64) NOT NULL DEFAULT '',
			summary varchar(255) NOT NULL DEFAULT '',
			status varchar(64) NOT NULL DEFAULT '',
			status_category varchar(32) NOT NULL DEFAULT '',
			resolution varchar(64) NOT NULL DEFAULT '',
			priority varchar(32) NOT NULL DEFAULT '',
			assignee varchar(191) NOT NULL DEFAULT '',
			assignee_id varchar(128) NOT NULL DEFAULT '',
			reporter varchar(191) NOT NULL DEFAULT '',
			team_id bigint(20) unsigned NOT NULL DEFAULT 0,
			asset_id bigint(20) unsigned NOT NULL DEFAULT 0,
			finding_count int(10) unsigned NOT NULL DEFAULT 0,
			grouping_key varchar(191) NOT NULL DEFAULT '',
			created_by bigint(20) unsigned NOT NULL DEFAULT 0,
			created_via varchar(32) NOT NULL DEFAULT 'manual',
			automation_id bigint(20) unsigned NOT NULL DEFAULT 0,
			verification_state varchar(24) NOT NULL DEFAULT 'not_required',
			verification_note text NULL,
			verified_at datetime NULL,
			remote_closed_at datetime NULL,
			last_synced_at datetime NULL,
			payload_json longtext NULL,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY provider_key (provider,external_key),
			KEY status_category (status_category),
			KEY asset_id (asset_id),
			KEY team_id (team_id),
			KEY grouping_key (grouping_key),
			KEY verification_state (verification_state)
		) {$charset};";

		/* Join table so one ticket can cover many findings. */
		$sql[] = "CREATE TABLE {$p}ticket_findings (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ticket_id bigint(20) unsigned NOT NULL DEFAULT 0,
			finding_id bigint(20) unsigned NOT NULL DEFAULT 0,
			state_at_close varchar(16) NOT NULL DEFAULT '',
			verified tinyint(1) NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY ticket_finding (ticket_id,finding_id),
			KEY finding_id (finding_id)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Exceptions / risk acceptances.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}exceptions (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			reference varchar(32) NOT NULL DEFAULT '',
			title varchar(255) NOT NULL DEFAULT '',
			scope_type varchar(24) NOT NULL DEFAULT 'finding',
			scope_ref varchar(191) NOT NULL DEFAULT '',
			scope_label varchar(255) NOT NULL DEFAULT '',
			asset_id bigint(20) unsigned NOT NULL DEFAULT 0,
			vuln_id bigint(20) unsigned NOT NULL DEFAULT 0,
			team_id bigint(20) unsigned NOT NULL DEFAULT 0,
			severity varchar(16) NOT NULL DEFAULT '',
			reason varchar(64) NOT NULL DEFAULT '',
			justification longtext NULL,
			compensating_controls longtext NULL,
			business_impact text NULL,
			status varchar(24) NOT NULL DEFAULT 'draft',
			requested_by bigint(20) unsigned NOT NULL DEFAULT 0,
			requested_by_name varchar(191) NOT NULL DEFAULT '',
			approver_id bigint(20) unsigned NOT NULL DEFAULT 0,
			approver_name varchar(191) NOT NULL DEFAULT '',
			decision_note text NULL,
			jira_key varchar(64) NOT NULL DEFAULT '',
			expires_at datetime NULL,
			review_at datetime NULL,
			requested_at datetime NULL,
			decided_at datetime NULL,
			revoked_at datetime NULL,
			affected_count int(10) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY reference (reference),
			KEY status (status),
			KEY scope (scope_type,scope_ref),
			KEY expires_at (expires_at),
			KEY asset_id (asset_id)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Automation rules — configurable ticket flow.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}automations (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			name varchar(191) NOT NULL DEFAULT '',
			description text NULL,
			enabled tinyint(1) NOT NULL DEFAULT 0,
			priority int(10) NOT NULL DEFAULT 10,
			trigger_event varchar(64) NOT NULL DEFAULT 'finding.discovered',
			match_all tinyint(1) NOT NULL DEFAULT 1,
			conditions_json longtext NULL,
			actions_json longtext NULL,
			grouping varchar(32) NOT NULL DEFAULT 'per_finding',
			throttle_minutes int(10) unsigned NOT NULL DEFAULT 0,
			max_per_run int(10) unsigned NOT NULL DEFAULT 25,
			last_run_at datetime NULL,
			run_count bigint(20) unsigned NOT NULL DEFAULT 0,
			action_count bigint(20) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			KEY enabled (enabled),
			KEY trigger_event (trigger_event)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Ownership mapping rules.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}mapping_rules (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			name varchar(191) NOT NULL DEFAULT '',
			enabled tinyint(1) NOT NULL DEFAULT 1,
			priority int(10) NOT NULL DEFAULT 10,
			match_field varchar(64) NOT NULL DEFAULT 'tag',
			match_operator varchar(24) NOT NULL DEFAULT 'equals',
			match_value varchar(255) NOT NULL DEFAULT '',
			assign_type varchar(32) NOT NULL DEFAULT 'team',
			assign_value varchar(255) NOT NULL DEFAULT '',
			stop_processing tinyint(1) NOT NULL DEFAULT 0,
			match_count bigint(20) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			KEY enabled_priority (enabled,priority)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Sync runs — one row per connector execution.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}sync_runs (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			connector varchar(64) NOT NULL DEFAULT '',
			mode varchar(24) NOT NULL DEFAULT 'scheduled',
			status varchar(24) NOT NULL DEFAULT 'running',
			started_at datetime NULL,
			finished_at datetime NULL,
			duration_ms int(10) unsigned NOT NULL DEFAULT 0,
			processed int(10) unsigned NOT NULL DEFAULT 0,
			created int(10) unsigned NOT NULL DEFAULT 0,
			updated int(10) unsigned NOT NULL DEFAULT 0,
			skipped int(10) unsigned NOT NULL DEFAULT 0,
			failed int(10) unsigned NOT NULL DEFAULT 0,
			message text NULL,
			stats_json longtext NULL,
			log_text longtext NULL,
			triggered_by bigint(20) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			KEY connector (connector),
			KEY status (status),
			KEY started_at (started_at)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Audit trail — who did what.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}audit (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			logged_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			actor varchar(191) NOT NULL DEFAULT '',
			action varchar(64) NOT NULL DEFAULT '',
			object_type varchar(48) NOT NULL DEFAULT '',
			object_id varchar(64) NOT NULL DEFAULT '',
			summary varchar(255) NOT NULL DEFAULT '',
			detail_json longtext NULL,
			ip varchar(45) NOT NULL DEFAULT '',
			severity varchar(16) NOT NULL DEFAULT 'info',
			PRIMARY KEY  (id),
			KEY logged_at (logged_at),
			KEY action (action),
			KEY object (object_type,object_id),
			KEY user_id (user_id)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Metric snapshots for trend charts.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}metrics (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			snapshot_date date NOT NULL DEFAULT '1970-01-01',
			metric_key varchar(64) NOT NULL DEFAULT '',
			dimension varchar(191) NOT NULL DEFAULT '',
			value decimal(14,2) NOT NULL DEFAULT 0.00,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY snapshot (snapshot_date,metric_key,dimension),
			KEY metric_key (metric_key)
		) {$charset};";

		/* ---------------------------------------------------------------
		 * Records held out of the inventory: a name, and nothing to act on.
		 * ------------------------------------------------------------- */
		$sql[] = "CREATE TABLE {$p}stale_records (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			source varchar(32) NOT NULL DEFAULT 'cmdb',
			name varchar(191) NOT NULL DEFAULT '',
			payload_json longtext NULL,
			times_seen int(10) unsigned NOT NULL DEFAULT 1,
			first_held_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			last_held_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			released_at datetime NULL,
			released_asset_id bigint(20) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			UNIQUE KEY source_name (source,name),
			KEY released_at (released_at)
		) {$charset};";

		foreach ( $sql as $statement ) {
			dbDelta( $statement );
		}

		// v14 added coverage columns; they mean nothing until they are filled.
		if ( class_exists( '\\VulnHub\\Core\\Coverage' ) ) {
			Coverage::recalculate();
		}

		update_option( 'vulnhub_db_version', VULNHUB_DB_VERSION, false );

		self::seed_defaults();
	}

	/**
	 * Schema changes dbDelta cannot make for us.
	 *
	 * dbDelta only ever adds columns and indexes — it will not drop or alter
	 * one. Anything destructive has to be done by hand, before dbDelta runs.
	 */
	private static function pre_migrate(): void {
		global $wpdb;

		$assets = $wpdb->prefix . 'vulnhub_assets';

		// Nothing to migrate on a fresh install.
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $assets ) ) !== $assets ) {
			return;
		}

		// v11: tenable_uuid was UNIQUE, which meant only one asset in the whole
		// table could have an empty one. Every device that exists in Intune or
		// the CMDB but has never been scanned by Tenable therefore failed to
		// insert with "Duplicate entry '' for key 'tenable_uuid'". Demote it to
		// a plain index.
		$unique = $wpdb->get_results(
			$wpdb->prepare( "SHOW INDEX FROM {$assets} WHERE Key_name = %s", 'tenable_uuid' ), // phpcs:ignore
			ARRAY_A
		);
		if ( $unique && 0 === (int) $unique[0]['Non_unique'] ) {
			$wpdb->query( "ALTER TABLE {$assets} DROP INDEX tenable_uuid" ); // phpcs:ignore
			$wpdb->query( "ALTER TABLE {$assets} ADD INDEX tenable_uuid (tenable_uuid)" ); // phpcs:ignore

			// Clear any placeholder values a connector wrote to work around the
			// old constraint, so real Tenable UUIDs can land there later.
			$wpdb->query(
				$wpdb->prepare(
					"UPDATE {$assets} SET tenable_uuid = '' WHERE tenable_uuid LIKE %s", // phpcs:ignore
					$wpdb->esc_like( 'vh-' ) . '%'
				)
			);
		}

		// v13: findings carried four single-column indexes that are leading
		// prefixes of the composites added in the same version, so they only
		// cost write time and tempt the optimiser into the wrong plan --
		// `GROUP BY severity` was picking the exception_id index and scanning
		// 416,890 rows. dbDelta cannot drop an index, so do it here.
		$findings = $wpdb->prefix . 'vulnhub_findings';

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $findings ) ) === $findings ) {
			foreach ( array( 'asset_id', 'vuln_id', 'state', 'exception_id', 'state_severity' ) as $legacy ) {
				$exists = $wpdb->get_results(
					$wpdb->prepare( "SHOW INDEX FROM {$findings} WHERE Key_name = %s", $legacy ), // phpcs:ignore
					ARRAY_A
				);
				if ( $exists ) {
					$wpdb->query( "ALTER TABLE {$findings} DROP INDEX `{$legacy}`" ); // phpcs:ignore
				}
			}

			// Fresh statistics, or the optimiser keeps the plan it learned
			// from the indexes that just went away.
			$wpdb->query( "ANALYZE TABLE {$findings}" ); // phpcs:ignore
		}
	}

	/**
	 * First-run reference data so the UI is never an empty shell.
	 */
	private static function seed_defaults(): void {
		global $wpdb;

		if ( get_option( 'vulnhub_seeded' ) ) {
			return;
		}

		$now = vh_now();

		$teams = array(
			array( 'End User Computing', 'end-user-computing', 'EUC', 7, 30, 90, 180 ),
			array( 'Infrastructure', 'infrastructure', 'INFRA', 7, 21, 60, 180 ),
			array( 'Application Support', 'application-support', 'APPS', 5, 21, 60, 180 ),
			array( 'Network Operations', 'network-operations', 'NETOPS', 3, 14, 45, 120 ),
			array( 'Cloud Platform', 'cloud-platform', 'CLOUD', 3, 14, 45, 120 ),
			array( 'Unassigned', 'unassigned', '', 7, 30, 90, 180 ),
		);
		foreach ( $teams as $t ) {
			$wpdb->insert(
				vh_table( 'teams' ),
				array(
					'name'             => $t[0],
					'slug'             => $t[1],
					'jira_project_key' => $t[2],
					'sla_critical_days' => $t[3],
					'sla_high_days'    => $t[4],
					'sla_medium_days'  => $t[5],
					'sla_low_days'     => $t[6],
					'source'           => 'seed',
					'created_at'       => $now,
					'updated_at'       => $now,
				)
			);
		}

		$locations = array(
			array( 'Auckland HQ', 'auckland-hq', 'Auckland', 'New Zealand', 'APAC', 'Pacific/Auckland' ),
			array( 'Wellington Office', 'wellington-office', 'Wellington', 'New Zealand', 'APAC', 'Pacific/Auckland' ),
			array( 'Christchurch Office', 'christchurch-office', 'Christchurch', 'New Zealand', 'APAC', 'Pacific/Auckland' ),
			array( 'Sydney Office', 'sydney-office', 'Sydney', 'Australia', 'APAC', 'Australia/Sydney' ),
			array( 'Remote / Home', 'remote', '', '', 'Global', '' ),
		);
		foreach ( $locations as $l ) {
			$wpdb->insert(
				vh_table( 'locations' ),
				array(
					'name'       => $l[0],
					'slug'       => $l[1],
					'city'       => $l[2],
					'country'    => $l[3],
					'region'     => $l[4],
					'timezone'   => $l[5],
					'source'     => 'seed',
					'created_at' => $now,
					'updated_at' => $now,
				)
			);
		}

		// Default mapping rules that express the user's core requirement:
		// a workstation must resolve to a person; servers resolve to a team.
		$rules = array(
			array( 'Workstations follow their Intune primary user', 10, 'asset_type', 'equals', 'workstation', 'person_from_intune', '', 0 ),
			array( 'Mobile devices follow their Intune primary user', 20, 'asset_type', 'equals', 'mobile', 'person_from_intune', '', 0 ),
			array( 'Tenable tag Team maps to team', 30, 'tag:Team', 'exists', '', 'team_from_tag', 'Team', 0 ),
			array( 'Servers default to Infrastructure', 80, 'asset_type', 'equals', 'server', 'team', 'infrastructure', 0 ),
			array( 'Network gear defaults to Network Operations', 85, 'asset_type', 'equals', 'network', 'team', 'network-operations', 0 ),
			array( 'Cloud resources default to Cloud Platform', 90, 'asset_type', 'equals', 'cloud', 'team', 'cloud-platform', 0 ),
		);
		foreach ( $rules as $r ) {
			$wpdb->insert(
				vh_table( 'mapping_rules' ),
				array(
					'name'            => $r[0],
					'priority'        => $r[1],
					'match_field'     => $r[2],
					'match_operator'  => $r[3],
					'match_value'     => $r[4],
					'assign_type'     => $r[5],
					'assign_value'    => $r[6],
					'stop_processing' => $r[7],
					'enabled'         => 1,
					'created_at'      => $now,
					'updated_at'      => $now,
				)
			);
		}

		update_option( 'vulnhub_seeded', 1, false );
	}
}

