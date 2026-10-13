<?php
/**
 * What gets copied between instances, and how two copies of a table are
 * compared without moving the table.
 *
 * Both ends run this same code: the source to describe itself and fingerprint
 * its tables, the copy to fingerprint its own and to decide what to ask for.
 * A fingerprint is computed in the database, never in PHP, so comparing a
 * million-row table costs one scan and a few kilobytes on the wire.
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Table inventory, fingerprints, row encoding and the option rules.
 */
final class VulnHub_Replica_Schema {

	/**
	 * Ids per fingerprint bucket on an integer-keyed table. A changed row
	 * costs re-sending its whole bucket, so this trades fingerprint size
	 * against re-send size; 1,000 ids is a few hundred kilobytes of
	 * fingerprints for the largest table here and a bucket rarely over a
	 * megabyte.
	 */
	public const BUCKET_WIDTH = 1000;

	/** Suffixes of the copy's own scratch tables, never inventoried. */
	public const STAGE_SUFFIX = '__vhr_new';
	public const OLD_SUFFIX   = '__vhr_old';

	/**
	 * Tables that describe this instance rather than the estate: who ran
	 * what, its own credentials, its own background jobs. Copying them would
	 * hand one instance's access to another, or make one instance's history
	 * read as another's.
	 */
	private const EXCLUDED_TABLES = array(
		'audit',
		'sync_runs',
		'mcp_tokens',
		'backup_jobs',
		'import_jobs',
		'replica_tokens',
	);

	/**
	 * Options never sent and never written, whatever the rules below say.
	 * Secrets, this instance's own identity and schema markers (each
	 * instance migrates its own schema), page ids that only mean something
	 * in the database they came from, cache epochs, job state.
	 */
	private const EXCLUDED_OPTIONS = array(
		'/^vulnhub_sec_/',
		'/^vulnhub_replica/',
		'/^vulnhub_cfg_(replica|mail)$/',
		'/_db_version$/',
		'/_db$/',
		'/_schema$/',
		'/_seeded$/',
		'/^vulnhub_seeded$/',
		'/^vulnhub_roles_version$/',
		'/^vulnhub_fallback_key$/',
		'/^vulnhub_auth_/',
		'/^vulnhub_dash_pages$/',
		'/^vulnhub_elementor_/',
		'/^vulnhub_widget_/',
		'/^vulnhub_mcp_/',
		'/^vulnhub_backup_/',
		'/^vulnhub_dl_est_/',
		'/^vulnhub_aws_run_profiles$/',
		'/^vh_ticket_check_/',
		'/_progress$/',
		'/_polled_at$/',
		'/(secret|token|passw|oauth|credential|api_?key|private)/i',
	);

	/**
	 * Keys stripped out of a connector's settings before they leave the
	 * source. Settings travel so the copy shows the same links, mappings
	 * and thresholds; anything that identifies an account or carries a
	 * position in a remote export stays behind.
	 */
	private const STRIPPED_SETTING_KEYS = '/(secret|token|passw|oauth|credential|client_id|access_key|api_?key|^key$|session|cookie|export_jobs|watermark|lock|^email$|^user(name)?$)/i';

	/* -----------------------------------------------------------------
	 * Tables
	 * --------------------------------------------------------------- */

	public static function prefix(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_';
	}

	public static function full( string $short ): string {
		return self::prefix() . $short;
	}

	/**
	 * @return array<int,string>
	 */
	public static function excluded_tables(): array {
		return (array) apply_filters( 'vulnhub_replica_excluded_tables', self::EXCLUDED_TABLES );
	}

	/**
	 * Every copyable table on this instance.
	 *
	 * @return array<string,array{pk:array<int,string>,int_pk:bool,cols:array<int,string>,rows:int,update_time:string}>
	 */
	public static function tables(): array {
		global $wpdb;

		$prefix = self::prefix();
		$len    = strlen( $prefix );
		$skip   = self::excluded_tables();

		$meta = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT TABLE_NAME AS t, TABLE_ROWS AS r, UPDATE_TIME AS u, TIMESTAMPDIFF(SECOND, UPDATE_TIME, NOW()) AS age FROM information_schema.TABLES
				 WHERE TABLE_SCHEMA = DATABASE() AND LEFT(TABLE_NAME, %d) = %s',
				$len,
				$prefix
			),
			ARRAY_A
		);

		$cols = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT TABLE_NAME AS t, COLUMN_NAME AS c, DATA_TYPE AS d, EXTRA AS e FROM information_schema.COLUMNS
				 WHERE TABLE_SCHEMA = DATABASE() AND LEFT(TABLE_NAME, %d) = %s ORDER BY TABLE_NAME, ORDINAL_POSITION',
				$len,
				$prefix
			),
			ARRAY_A
		);

		$keys = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT TABLE_NAME AS t, COLUMN_NAME AS c FROM information_schema.STATISTICS
				 WHERE TABLE_SCHEMA = DATABASE() AND LEFT(TABLE_NAME, %d) = %s AND INDEX_NAME = 'PRIMARY' ORDER BY TABLE_NAME, SEQ_IN_INDEX",
				$len,
				$prefix
			),
			ARRAY_A
		);

		$types = array();
		$by    = array();
		foreach ( $cols as $c ) {
			$t = (string) $c['t'];
			$types[ $t ][ (string) $c['c'] ] = strtolower( (string) $c['d'] );
			// A generated column is computed by the database that holds it;
			// writing one is an error, and fingerprinting one adds nothing.
			if ( false !== stripos( (string) $c['e'], 'GENERATED' ) ) {
				continue;
			}
			$by[ $t ][] = (string) $c['c'];
		}

		$pks = array();
		foreach ( $keys as $k ) {
			$pks[ (string) $k['t'] ][] = (string) $k['c'];
		}

		$out = array();
		foreach ( $meta as $m ) {
			$full  = (string) $m['t'];
			$short = substr( $full, $len );

			if ( in_array( $short, $skip, true ) ) {
				continue;
			}
			if ( str_ends_with( $short, self::STAGE_SUFFIX ) || str_ends_with( $short, self::OLD_SUFFIX ) ) {
				continue;
			}
			if ( empty( $pks[ $full ] ) || empty( $by[ $full ] ) ) {
				continue; // No primary key: nothing to line rows up by.
			}

			$pk     = $pks[ $full ];
			$int_pk = 1 === count( $pk ) && in_array( $types[ $full ][ $pk[0] ] ?? '', array( 'tinyint', 'smallint', 'mediumint', 'int', 'bigint' ), true );

			$out[ $short ] = array(
				'pk'          => $pk,
				'int_pk'      => $int_pk,
				'cols'        => $by[ $full ],
				'rows'        => (int) $m['r'],
				// Only a write time old enough to be settled is worth caching
				// against: it has one-second resolution, and a write in the
				// same second as a fingerprint would otherwise be missed.
				'update_time' => ( null !== $m['age'] && (int) $m['age'] > 5 ) ? (string) $m['u'] : '',
			);
		}

		ksort( $out );

		return $out;
	}

	/**
	 * The columns both ends have, in the source's order. Fingerprints are
	 * only comparable over the same columns in the same order.
	 *
	 * @param array<int,string> $source Source columns.
	 * @param array<int,string> $local  Local columns.
	 * @return array<int,string>
	 */
	public static function shared_columns( array $source, array $local ): array {
		return array_values( array_intersect( $source, $local ) );
	}

	/**
	 * Is $name a plain column identifier? Every identifier that reaches SQL
	 * here has come out of information_schema, and is checked again anyway.
	 */
	public static function ident( string $name ): string {
		if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $name ) ) {
			throw new \InvalidArgumentException( 'Unexpected identifier.' );
		}
		return '`' . $name . '`';
	}

	/**
	 * How to create a table, with its name left as a placeholder.
	 *
	 * Some tables are created the first time a feature runs, not when its
	 * plugin is activated -- so a fresh copy can lack a table the source has
	 * had for months. The copy creates it from this rather than skipping it.
	 */
	public static function ddl( string $short ): string {
		global $wpdb;

		$full = self::full( $short );
		$row  = $wpdb->get_row( 'SHOW CREATE TABLE ' . self::ident( $full ), ARRAY_N ); // phpcs:ignore WordPress.DB.PreparedSQL -- identifier checked.
		if ( ! $row || empty( $row[1] ) ) {
			return '';
		}
		$sql = (string) $row[1];
		$sql = preg_replace( '/\s+AUTO_INCREMENT=\d+/', '', $sql );
		return str_replace( 'CREATE TABLE `' . $full . '`', 'CREATE TABLE `{table}`', (string) $sql );
	}

	/**
	 * Create a missing local table from a source's DDL. Only a single
	 * CREATE TABLE for exactly the expected name is accepted.
	 */
	public static function create_from_ddl( string $short, string $ddl ): bool {
		global $wpdb;

		if ( ! preg_match( '/^[a-z0-9_]+$/', $short ) || ! str_starts_with( $ddl, 'CREATE TABLE `{table}` (' ) || false !== strpos( $ddl, ';' ) ) {
			return false;
		}
		$sql = str_replace( 'CREATE TABLE `{table}`', 'CREATE TABLE IF NOT EXISTS ' . self::ident( self::full( $short ) ), $ddl );
		return false !== $wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL -- validated above.
	}

	/* -----------------------------------------------------------------
	 * Fingerprints
	 * --------------------------------------------------------------- */

	/**
	 * Fingerprint a table.
	 *
	 * Per row: the first 64 bits of an MD5 over every shared column, NULL
	 * kept distinct from the empty string. Per bucket: the row count and the
	 * XOR of the row hashes. XOR is order-free, so the database never has to
	 * sort, and a changed, added or removed row changes its bucket.
	 *
	 * `buckets` mode groups an integer-keyed table by key range; `table`
	 * mode gives one fingerprint for the whole table.
	 *
	 * Cached against the table's own last-write time, so a table nothing
	 * has touched since the last run costs nothing to fingerprint again.
	 *
	 * @param string            $short Table, without prefix.
	 * @param array<int,string> $cols  Columns to cover.
	 * @param string            $pk    Integer key column (buckets mode).
	 * @param string            $mode  buckets|table.
	 * @return array<string,array{0:int,1:string}>
	 */
	public static function fingerprint( string $short, array $cols, string $pk, string $mode, string $update_time = '' ): array {
		global $wpdb;

		$width = self::BUCKET_WIDTH;
		$cache = '';
		if ( '' !== $update_time ) {
			// On disk, not in the object cache: that is an LRU with a memory
			// cap, and a large table's fingerprints are exactly what it would
			// evict first.
			$cache = self::dir( 'fp' ) . '/' . md5( $short . '|' . implode( ',', $cols ) . '|' . $pk . '|' . $mode . '|' . $width . '|' . $update_time ) . '.json';
			if ( is_readable( $cache ) && filemtime( $cache ) > time() - 6 * HOUR_IN_SECONDS ) {
				$hit = json_decode( (string) file_get_contents( $cache ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				if ( is_array( $hit ) ) {
					return $hit;
				}
			}
		}

		$parts = array();
		foreach ( $cols as $c ) {
			$parts[] = 'IFNULL(' . self::ident( $c ) . ', CHAR(0))';
		}
		$row_hash = 'CAST(CONV(LEFT(MD5(CONCAT_WS(CHAR(31), ' . implode( ', ', $parts ) . ')), 16), 16, 10) AS UNSIGNED)';
		$table    = self::ident( self::full( $short ) );

		if ( 'buckets' === $mode ) {
			$sql = 'SELECT FLOOR(' . self::ident( $pk ) . ' / ' . $width . ') AS b, COUNT(*) AS n, BIT_XOR(' . $row_hash . ') AS x FROM ' . $table . ' GROUP BY b';
		} else {
			$sql = "SELECT 'all' AS b, COUNT(*) AS n, BIT_XOR(" . $row_hash . ') AS x FROM ' . $table;
		}

		$rows = (array) $wpdb->get_results( $sql, ARRAY_N ); // phpcs:ignore WordPress.DB.PreparedSQL -- identifiers only, checked by ident().
		if ( $wpdb->last_error ) {
			throw new \RuntimeException( 'Could not fingerprint ' . $short . ': ' . $wpdb->last_error );
		}

		$out = array();
		foreach ( $rows as $r ) {
			if ( 'table' === $mode && 0 === (int) $r[1] ) {
				$out['all'] = array( 0, '0' );
				continue;
			}
			$out[ (string) $r[0] ] = array( (int) $r[1], (string) $r[2] );
		}

		if ( '' !== $cache ) {
			foreach ( (array) glob( dirname( $cache ) . '/*.json' ) as $old ) {
				if ( filemtime( (string) $old ) < time() - 6 * HOUR_IN_SECONDS ) {
					@unlink( (string) $old ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				}
			}
			file_put_contents( $cache, (string) wp_json_encode( $out ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		return $out;
	}

	/**
	 * Fingerprint mode for a table, from its key.
	 *
	 * @param array{pk:array<int,string>,int_pk:bool} $info Table info.
	 */
	public static function mode_for( array $info ): string {
		return ! empty( $info['int_pk'] ) ? 'buckets' : 'table';
	}

	/* -----------------------------------------------------------------
	 * Row encoding
	 * --------------------------------------------------------------- */

	/**
	 * One row as a JSON line. Values travel as the strings the database
	 * gave us, so nothing is reinterpreted on the way; a value that is not
	 * valid UTF-8 travels base64'd and marked, rather than being mangled by
	 * the JSON encoder into something that would never fingerprint equal.
	 *
	 * @param array<int,mixed> $row Row values.
	 */
	public static function encode_row( array $row ): string {
		foreach ( $row as $i => $v ) {
			if ( null !== $v && ! mb_check_encoding( (string) $v, 'UTF-8' ) ) {
				$row[ $i ] = array( '~b', base64_encode( (string) $v ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions -- binary-safe transport.
			}
		}
		return (string) wp_json_encode( $row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	}

	/**
	 * @return array<int,string|null>|null
	 */
	public static function decode_row( string $line ): ?array {
		$row = json_decode( $line, true );
		if ( ! is_array( $row ) ) {
			return null;
		}
		foreach ( $row as $i => $v ) {
			if ( is_array( $v ) && 2 === count( $v ) && '~b' === ( $v[0] ?? '' ) ) {
				$row[ $i ] = base64_decode( (string) $v[1], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
			} elseif ( null !== $v && ! is_string( $v ) ) {
				$row[ $i ] = (string) $v;
			}
		}
		return $row;
	}

	/* -----------------------------------------------------------------
	 * Options
	 * --------------------------------------------------------------- */

	public static function option_excluded( string $name ): bool {
		global $wpdb;

		if ( $wpdb->prefix . 'user_roles' === $name ) {
			return true;
		}
		foreach ( self::EXCLUDED_OPTIONS as $re ) {
			if ( preg_match( $re, $name ) ) {
				return true;
			}
		}
		return ! str_starts_with( $name, 'vulnhub_' ) && ! str_starts_with( $name, 'vh_' );
	}

	/**
	 * Strip a connector's settings down to what can travel, and switch it
	 * off: on the copy, nothing reaches out to a real system.
	 *
	 * @param mixed $value Stored settings.
	 * @return mixed
	 */
	public static function travel_settings( mixed $value ): mixed {
		if ( ! is_array( $value ) ) {
			return $value;
		}
		foreach ( array_keys( $value ) as $key ) {
			if ( preg_match( self::STRIPPED_SETTING_KEYS, (string) $key ) ) {
				unset( $value[ $key ] );
			}
		}
		$value['enabled'] = 0;
		$value['mock']    = 0;

		return $value;
	}

	/**
	 * The options the source sends, already made safe to travel.
	 *
	 * @return array<string,array{v:string,a:string}>
	 */
	public static function export_options(): array {
		global $wpdb;

		$rows = (array) $wpdb->get_results(
			"SELECT option_name, autoload FROM {$wpdb->options}
			 WHERE LEFT(option_name, 8) = 'vulnhub_' OR LEFT(option_name, 3) = 'vh_'",
			ARRAY_A
		);

		$out = array();
		foreach ( $rows as $r ) {
			$name = (string) $r['option_name'];
			if ( self::option_excluded( $name ) ) {
				continue;
			}
			$value = get_option( $name );
			if ( str_starts_with( $name, 'vulnhub_cfg_' ) ) {
				$value = self::travel_settings( $value );
			}
			if ( 'vulnhub_platform' === $name && is_array( $value ) ) {
				$value['mock_mode'] = 0;
			}
			$out[ $name ] = array(
				'v' => base64_encode( serialize( $value ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions -- exact round trip of a stored option.
				'a' => in_array( (string) $r['autoload'], array( 'yes', 'on', 'auto-on', 'auto' ), true ) ? 'yes' : 'no',
			);
		}

		ksort( $out );

		return $out;
	}

	/**
	 * Write received options on the copy. Returns the names written.
	 *
	 * @param array<string,array{v:string,a:string}> $options  Received options.
	 * @param array<int,string>                      $previous Names written by the last run.
	 * @return array<int,string>
	 */
	public static function import_options( array $options, array $previous ): array {
		$written = array();

		foreach ( $options as $name => $o ) {
			$name = (string) $name;
			// Checked again here: a source running older rules must still
			// never be able to write a secret or this copy's own settings.
			if ( self::option_excluded( $name ) ) {
				continue;
			}
			$raw = base64_decode( (string) ( $o['v'] ?? '' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
			if ( false === $raw ) {
				continue;
			}
			$value = @unserialize( $raw, array( 'allowed_classes' => false ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions,WordPress.PHP.NoSilencedErrors -- no objects, ever.
			if ( false === $value && 'b:0;' !== $raw ) {
				continue;
			}
			if ( str_starts_with( $name, 'vulnhub_cfg_' ) ) {
				$value = self::travel_settings( $value );
			}
			update_option( $name, $value, 'yes' === ( $o['a'] ?? 'no' ) );
			$written[] = $name;
		}

		// Gone at the source since the last run: gone here.
		foreach ( array_diff( $previous, $written ) as $gone ) {
			if ( ! self::option_excluded( (string) $gone ) ) {
				delete_option( (string) $gone );
			}
		}

		return $written;
	}

	/* -----------------------------------------------------------------
	 * Identity and storage
	 * --------------------------------------------------------------- */

	/**
	 * This instance's own id, so a copy can refuse to sync from itself.
	 */
	public static function instance_id(): string {
		$id = (string) get_option( 'vulnhub_replica_instance', '' );
		if ( '' === $id ) {
			$id = wp_generate_uuid4();
			update_option( 'vulnhub_replica_instance', $id, false );
		}
		return $id;
	}

	/**
	 * Working directory for packages, outside uploads and closed to the web.
	 */
	public static function dir( string $sub ): string {
		$base = trailingslashit( WP_CONTENT_DIR ) . 'vulnhub-replica';
		if ( ! is_dir( $base ) ) {
			wp_mkdir_p( $base );
		}
		if ( ! file_exists( $base . '/.htaccess' ) ) {
			file_put_contents( $base . '/.htaccess', "Require all denied\nDeny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			file_put_contents( $base . '/index.php', "<?php\n// Silence.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		$path = $base . '/' . $sub;
		if ( ! is_dir( $path ) ) {
			wp_mkdir_p( $path );
		}
		return $path;
	}

	public static function rmdir( string $path ): void {
		if ( ! is_dir( $path ) || false === strpos( $path, 'vulnhub-replica' ) ) {
			return;
		}
		foreach ( (array) scandir( $path ) as $f ) {
			if ( '.' === $f || '..' === $f ) {
				continue;
			}
			$p = $path . '/' . $f;
			is_dir( $p ) ? self::rmdir( $p ) : @unlink( $p ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		@rmdir( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Plugin versions, so a copy can say when it is running different code.
	 *
	 * @return array<string,string>
	 */
	public static function versions(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = array();
		foreach ( get_plugins() as $file => $p ) {
			if ( str_starts_with( (string) $file, 'vulnhub-' ) && is_plugin_active( (string) $file ) ) {
				$out[ dirname( (string) $file ) ] = (string) ( $p['Version'] ?? '' );
			}
		}
		ksort( $out );
		return $out;
	}
}

