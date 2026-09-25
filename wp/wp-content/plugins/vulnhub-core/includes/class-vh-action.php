<?php
/**
 * What can somebody actually do about this finding?
 *
 * Severity says what to worry about and patch availability says whether a
 * vendor shipped something. Neither answers the question a platform team asks
 * on a Monday: of these 256,000 open findings, which ones can we act on this
 * week, and which are weather?
 *
 * On this estate the difference is brutal. 219,741 of the open findings are
 * Tenable's "Linux Distros Unpatched Vulnerability : CVE-…" plugins -- the
 * distribution has not shipped a fix, so nobody can patch them today. 6,337
 * sit on machines whose operating system is past end of life, where the fix is
 * not a patch at all but a replacement (tracked as a programme, on the EOL
 * plan screen). What is left -- 29,872 patchable and 692 that need a setting
 * or a group policy changed -- is the actual queue. A list that mixes all four
 * together is the reason "we have 256,000 vulnerabilities" is a number nobody
 * can act on.
 *
 * ## The classes, and why the order is what it is
 *
 * Precedence runs top to bottom; the first class that matches wins.
 *
 * 1. `excepted`    -- somebody accepted this risk deliberately. That decision
 *                     outranks every technical fact about the finding, which
 *                     is the whole point of having a register.
 * 2. `patch`       -- a vendor fix exists. Deliberately ABOVE `blocked_eol`:
 *                     an application patch still applies on an old operating
 *                     system. 844 findings here are patchable Java and .NET
 *                     updates sitting on RHEL 6 boxes, and burying them as
 *                     "EOL noise" would hide real, schedulable work behind a
 *                     replacement project that will take quarters.
 * 3. `remove`      -- no vendor fix, but the scanner says to uninstall the
 *                     software. Cheap and immediate.
 * 4. `config`      -- no vendor fix, but a setting, registry value or group
 *                     policy closes it. Also cheap, and different work from
 *                     patching: it ships as a GPO, not as a package.
 * 5. `blocked_eol` -- no fix of any kind, and the machine's OS is past end of
 *                     life. Cannot be fixed in place; it needs replacing.
 * 6. `await_fix`   -- no fix of any kind, on a supported OS. Nobody can do
 *                     anything yet. Worth watching, not worth queueing.
 *
 * ## Why `patch` is not simply `Repo::patch_sql()`
 *
 * `patch_sql()` answers a narrower question -- "did the vendor say anything at
 * all?" -- by treating ANY non-empty solution text as a fix. That is right for
 * the patch-availability chart, and wrong here: it would swallow `remove` and
 * `config` whole, because those findings also carry solution text, leaving two
 * of the six classes permanently empty. Measured against this estate: 692
 * findings whose only instruction is "Disable the macro execution trust
 * settings" or "Add and enable registry value EnableCertPaddingCheck" have no
 * patch date at all. Calling those "patch available" tells a patching team to
 * go and find a package that does not exist.
 *
 * So `patch` here means a real vendor patch: a publication date, or solution
 * text that instructs an upgrade. The 1,083 findings reading "Upgrade to
 * Oracle JDK / JRE …, if necessary remove any affected versions" stay in
 * `patch`, correctly -- removal is a footnote to an upgrade, not the fix.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Eol;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The remediation-action classification, as SQL and as a row test.
 */
final class VH_Action {

	public const EXCEPTED    = 'excepted';
	public const PATCH       = 'patch';
	public const UPDATE_APP  = 'update_app';
	public const REMOVE      = 'remove';
	public const CONFIG      = 'config';
	public const BLOCKED_EOL = 'blocked_eol';
	public const AWAIT_FIX   = 'await_fix';

	/**
	 * The classes in precedence order, with labels written for somebody
	 * deciding what to do rather than for somebody reading a schema.
	 *
	 * @return array<string,string>
	 */
	public static function classes(): array {
		return array(
			self::PATCH       => __( 'Patch available', 'vulnhub' ),
			self::UPDATE_APP  => __( 'Update the app that ships it', 'vulnhub' ),
			self::REMOVE      => __( 'Remove the software', 'vulnhub' ),
			self::CONFIG      => __( 'Change a setting', 'vulnhub' ),
			self::BLOCKED_EOL => __( 'Blocked: OS past end of life', 'vulnhub' ),
			self::AWAIT_FIX   => __( 'No vendor fix yet', 'vulnhub' ),
			self::EXCEPTED    => __( 'Accepted risk', 'vulnhub' ),
		);
	}

	/**
	 * The three classes somebody can act on this week.
	 *
	 * @return array<int,string>
	 */
	public static function actionable(): array {
		return array( self::PATCH, self::UPDATE_APP, self::REMOVE, self::CONFIG );
	}

	public static function label( string $class ): string {
		$classes = self::classes();

		return (string) ( $classes[ $class ] ?? $class );
	}

	public static function is_class( string $class ): bool {
		return array_key_exists( $class, self::classes() );
	}

	/**
	 * A one-line explanation of each class, for a filter's help text or a
	 * chart legend. Says what to do, not what the rule is.
	 */
	public static function description( string $class ): string {
		switch ( $class ) {
			case self::PATCH:
				return __( 'A vendor fix exists: schedule it.', 'vulnhub' );
			case self::UPDATE_APP:
				return __( 'The vulnerable component ships inside another application: update that application. If it is already current, its vendor has not shipped the fix yet.', 'vulnhub' );
			case self::REMOVE:
				return __( 'No fix, but the software can be uninstalled.', 'vulnhub' );
			case self::CONFIG:
				return __( 'No fix, but a setting or group policy closes it.', 'vulnhub' );
			case self::BLOCKED_EOL:
				return __( 'The operating system is past end of life, so this cannot be fixed in place — the machine needs replacing.', 'vulnhub' );
			case self::AWAIT_FIX:
				return __( 'Nobody can fix this yet: the vendor has not shipped anything.', 'vulnhub' );
			case self::EXCEPTED:
				return __( 'Covered by an approved exception.', 'vulnhub' );
		}

		return '';
	}

	/* =================================================================
	 * The rule, in SQL
	 * ============================================================== */

	/**
	 * Does the vendor have a patch? A date, or an instruction to upgrade.
	 *
	 * @param string $v Alias of the vulns table.
	 */
	/*
	 * LOCATE(), not LIKE '%needle%', and it matters.
	 *
	 * These fragments are embedded in queries that `Repo::findings()` may or
	 * may not hand to `wpdb::prepare()` -- it prepares only when a filter
	 * bound a parameter. A literal % in a prepared string is read as a
	 * placeholder, so the same clause worked on the screen and then broke the
	 * CSV export with "the query does not contain the correct number of
	 * placeholders (5) for the number of arguments passed (2)", which is a
	 * notice, not an error: the export simply returned the wrong rows.
	 *
	 * LOCATE carries no % at all, so it cannot be misread by either caller,
	 * and it is the same test: a substring, case-insensitively, under this
	 * column's collation.
	 */
	private static function patch_expr( string $v = 'v' ): string {
		// Materialised: see fix_action_sql() and Repo::derived_ready().
		if ( \VulnHub\Core\Repo::derived_ready() ) {
			return "( {$v}.vh_fix_action = '" . self::PATCH . "' )";
		}

		return self::patch_test( $v );
	}

	/**
	 * Does the solution say to uninstall it?
	 *
	 * Only ever asked after patch_expr() has said no (sql_case() checks in
	 * that order), which is why the materialised form can be a plain
	 * equality: vh_fix_action is 'remove' exactly when this test holds and
	 * the patch test does not.
	 *
	 * @param string $v Alias of the vulns table.
	 */
	private static function remove_expr( string $v = 'v' ): string {
		if ( \VulnHub\Core\Repo::derived_ready() ) {
			return "( {$v}.vh_fix_action = '" . self::REMOVE . "' )";
		}

		return self::remove_test( $v );
	}

	/**
	 * Does the solution say to change a setting?
	 *
	 * Same ordering note as remove_expr(): asked only after patch and remove.
	 *
	 * @param string $v Alias of the vulns table.
	 */
	private static function config_expr( string $v = 'v' ): string {
		if ( \VulnHub\Core\Repo::derived_ready() ) {
			return "( {$v}.vh_fix_action = '" . self::CONFIG . "' )";
		}

		return self::config_test( $v );
	}

	/* -----------------------------------------------------------------
	 * The tests themselves, against the raw columns
	 *
	 * Each read of the classification used to run up to fourteen LOCATE()s
	 * over `solution` -- a longtext -- for every joined finding, on every
	 * page and every widget, although the answer belongs to the
	 * vulnerability and only changes when Tenable rewrites it. So the tests
	 * are evaluated once, by MariaDB, into vulns.vh_fix_action (a STORED
	 * generated column built from fix_action_sql() below), and the *_expr()
	 * methods above compare against it. Measured on 258k open findings: the
	 * classification count went from 10.8s to 5.1s.
	 *
	 * These stay the one definition. The column is generated from them, and
	 * they are what runs when the column is absent (a fresh install before
	 * Install has run, or a restore of a backup taken before it existed).
	 * $v may be '' for an unaliased expression.
	 * --------------------------------------------------------------- */

	private static function col( string $v, string $column ): string {
		return '' === $v ? $column : "{$v}.{$column}";
	}

	private static function patch_test( string $v ): string {
		$d = self::col( $v, 'patch_publication_date' );
		$s = self::col( $v, 'solution' );

		return "( ( {$d} IS NOT NULL AND {$d} > '1970-01-02' )"
			. " OR LOCATE('upgrade', {$s}) > 0"
			. " OR LOCATE('update', {$s}) > 0"
			// "apply … patch" and "install … patch": both words, in that order.
			. " OR ( LOCATE('apply', {$s}) > 0"
			. " AND LOCATE('patch', {$s}, LOCATE('apply', {$s}) + 5) > 0 )"
			. " OR ( LOCATE('install', {$s}) > 0"
			. " AND LOCATE('patch', {$s}, LOCATE('install', {$s}) + 7) > 0 ) )";
	}

	private static function remove_test( string $v ): string {
		$s = self::col( $v, 'solution' );

		return "( LOCATE('remove', {$s}) > 0 OR LOCATE('uninstall', {$s}) > 0 )";
	}

	private static function config_test( string $v ): string {
		$s = self::col( $v, 'solution' );

		return "( LOCATE('disable', {$s}) > 0"
			. " OR LOCATE('registry', {$s}) > 0"
			. " OR LOCATE('group policy', {$s}) > 0"
			. " OR LOCATE('configure', {$s}) > 0"
			. " OR LOCATE('setting', {$s}) > 0 )";
	}

	/**
	 * The generation expression for vulns.vh_fix_action.
	 *
	 * The vulnerability-only part of sql_case(), in sql_case()'s order:
	 * 'patch', 'remove', 'config', or '' when the solution says none of
	 * those. Everything that depends on the finding (exception, component,
	 * end-of-life host) stays in sql_case(), because it is not a property of
	 * the vulnerability.
	 */
	public static function fix_action_sql(): string {
		return 'CASE'
			. ' WHEN ' . self::patch_test( '' ) . " THEN '" . self::PATCH . "'"
			. ' WHEN ' . self::remove_test( '' ) . " THEN '" . self::REMOVE . "'"
			. ' WHEN ' . self::config_test( '' ) . " THEN '" . self::CONFIG . "'"
			. " ELSE '' END";
	}

	/**
	 * Assets whose operating system is past end of life, as a SQL fragment.
	 *
	 * An inlined id list, which is what `Repo::findings()`'s own `support`
	 * filter already does with the same set. The list is bounded by how many
	 * machines run an expired release -- 83 of 1,149 here -- and the ids are
	 * integer-cast, so the interpolation is safe and the query stays legible
	 * in a slow log.
	 *
	 * It is inlined rather than joined because the set is a PHP judgement,
	 * not a column: matching a release to a lifecycle table happens in
	 * `Eol::match_os()`, including the build-number correction that catches
	 * machines the inventory mislabels. If this estate ever ran thousands of
	 * expired machines the right answer would be a materialised column on
	 * assets, refreshed where coverage is -- at which point this method is
	 * the one place to change.
	 *
	 * With nothing end of life the expression is `1=0`: `blocked_eol` then
	 * matches nothing, which is the truth, rather than matching everything.
	 *
	 * @param string $f Alias of the findings table.
	 */
	private static function eol_expr( string $f = 'f' ): string {
		$ids = self::eol_asset_ids();

		if ( ! $ids ) {
			return '1=0';
		}

		return "{$f}.asset_id IN ( " . implode( ',', $ids ) . ' )';
	}

	/**
	 * Memoised per request: this is read once per class in a CASE, and the
	 * underlying scan re-matches every asset against the lifecycle table.
	 *
	 * @return array<int,int>
	 */
	private static function eol_asset_ids(): array {
		static $ids = null;

		if ( null !== $ids ) {
			return $ids;
		}

		$ids = class_exists( '\\VulnHub\\Core\\Eol' )
			? array_values( array_filter( array_map( 'intval', Eol::eol_os_asset_ids() ) ) )
			: array();

		return $ids;
	}

	/**
	 * The classification as one CASE expression, evaluating to a class slug.
	 *
	 * Requires the vulns table joined (solution and patch date) and reads
	 * `asset_id` and `exception_id` off findings.
	 *
	 * @param string $f Alias of the findings table.
	 * @param string $v Alias of the vulns table.
	 */
	public static function sql_case( string $f = 'f', string $v = 'v' ): string {
		return 'CASE'
			. " WHEN {$f}.exception_id > 0 THEN '" . self::EXCEPTED . "'"
			// A component shipped inside another application: the fix is that
			// application's update, not the component's (Repo::component_sql()).
			. ' WHEN ' . self::patch_expr( $v ) . ' AND ' . \VulnHub\Core\Repo::component_sql( $f, $v ) . " THEN '" . self::UPDATE_APP . "'"
			. ' WHEN ' . self::patch_expr( $v ) . " THEN '" . self::PATCH . "'"
			. ' WHEN ' . self::remove_expr( $v ) . " THEN '" . self::REMOVE . "'"
			. ' WHEN ' . self::config_expr( $v ) . " THEN '" . self::CONFIG . "'"
			. ' WHEN ' . self::eol_expr( $f ) . " THEN '" . self::BLOCKED_EOL . "'"
			. " ELSE '" . self::AWAIT_FIX . "' END";
	}

	/**
	 * A WHERE fragment matching exactly one class.
	 *
	 * Deliberately written as the CASE compared to a literal rather than as a
	 * hand-rolled clause per class: the chart counts with the CASE and the
	 * list filters with this, so expressing them twice is how a segment comes
	 * to disagree with the rows it opens. An unknown class matches nothing.
	 *
	 * @param string $class Class slug.
	 * @param string $f     Alias of the findings table.
	 * @param string $v     Alias of the vulns table.
	 */
	public static function sql_for( string $class, string $f = 'f', string $v = 'v' ): string {
		if ( ! self::is_class( $class ) ) {
			return '1=0';
		}

		return '( ' . self::sql_case( $f, $v ) . " ) = '" . esc_sql( $class ) . "'";
	}

	/* =================================================================
	 * The same rule, against a row already in memory
	 * ============================================================== */

	/**
	 * Classify a hydrated finding row (as `Repo::findings()` returns it,
	 * carrying the vulnerability's solution and patch date alongside the
	 * finding's own columns).
	 *
	 * @param array<string,mixed> $row Finding row.
	 */
	public static function for_row( array $row ): string {
		if ( (int) ( $row['exception_id'] ?? 0 ) > 0 ) {
			return self::EXCEPTED;
		}

		$solution = strtolower( trim( (string) ( $row['solution'] ?? '' ) ) );
		$date     = trim( (string) ( $row['patch_publication_date'] ?? '' ) );
		$has_date = '' !== $date && '0000-00-00' !== $date && $date > '1970-01-02';

		if ( $has_date || self::matches( $solution, array( 'upgrade', 'update', 'apply patch', 'install patch' ) ) ) {
			return \VulnHub\Core\Repo::is_component( $row ) ? self::UPDATE_APP : self::PATCH;
		}

		if ( self::matches( $solution, array( 'remove', 'uninstall' ) ) ) {
			return self::REMOVE;
		}

		if ( self::matches( $solution, array( 'disable', 'registry', 'group policy', 'configure', 'setting' ) ) ) {
			return self::CONFIG;
		}

		if ( in_array( (int) ( $row['asset_id'] ?? 0 ), self::eol_asset_ids(), true ) ) {
			return self::BLOCKED_EOL;
		}

		return self::AWAIT_FIX;
	}

	/**
	 * `LIKE '%needle%'` in PHP, so the row test and the SQL agree on what
	 * counts as a match -- substring, case-insensitive, anywhere in the text.
	 *
	 * @param string            $haystack Lower-cased solution text.
	 * @param array<int,string> $needles  Terms to look for.
	 */
	private static function matches( string $haystack, array $needles ): bool {
		if ( '' === $haystack ) {
			return false;
		}

		foreach ( $needles as $needle ) {
			// 'apply patch' stands for SQL's '%apply%patch%': the two words in
			// order, not necessarily adjacent.
			$parts = explode( ' ', $needle );

			if ( 1 === count( $parts ) ) {
				if ( str_contains( $haystack, $needle ) ) {
					return true;
				}
				continue;
			}

			$offset = 0;
			$all    = true;

			foreach ( $parts as $part ) {
				$at = strpos( $haystack, $part, $offset );

				if ( false === $at ) {
					$all = false;
					break;
				}

				$offset = $at + strlen( $part );
			}

			if ( $all ) {
				return true;
			}
		}

		return false;
	}
}
