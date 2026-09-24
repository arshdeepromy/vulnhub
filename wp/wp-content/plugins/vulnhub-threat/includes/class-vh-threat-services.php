<?php
/**
 * Which network service a vulnerability lives in, and on what ports.
 *
 * CVSS says whether a bug *can* be reached over a network, not whether
 * anything on the machine exposes it. On this estate most "network, no
 * credentials, no click" findings on servers are in the kernel, perl, rsync or
 * a container runtime: nothing listens for them, so an open port 22 does not
 * make a perl bug reachable. A finding only becomes a way in when the
 * component it is in *is* the thing answering on an open port.
 *
 * The component comes from three places:
 *
 *   the product             VulnHub's normalised product (`product_slug`)
 *   the package             a distro advisory's title ("RHEL 9 : openssh
 *                           (RHSA-…)"), or the package list an unpatched-CVE
 *                           check prints in its output
 *   the scanner's port      only for a remote check -- a local one reports
 *                           the port it logged in over
 *
 * A component that is not a network service answers null, and the finding is
 * left where the lanes put it. The mapping is deliberately to *services*, not
 * to CVEs: "OpenSSH on 22" is a statement about the machine that a person can
 * check with one connection; "CVE-X is reachable" is not.
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Threat_Services {

	/**
	 * Services, with the ports they are normally found on. Protocol is TCP
	 * unless the port is written "udp/N".
	 */
	private const SERVICES = array(
		'ssh'     => array( 'SSH server', array( 22 ) ),
		'web'     => array( 'Web server', array( 80, 443, 8080, 8443, 8000, 8008, 8888 ) ),
		'tomcat'  => array( 'Tomcat', array( 8080, 8443, 80, 443, 8009 ) ),
		'appweb'  => array( 'Web application', array( 80, 443, 8080, 8443, 7001, 7002, 8000, 3000, 5000, 9443 ) ),
		'smb'     => array( 'SMB file sharing', array( 445, 139 ) ),
		'dns'     => array( 'DNS server', array( 53, 'udp/53' ) ),
		'mail'    => array( 'Mail server', array( 25, 465, 587, 110, 143, 993, 995 ) ),
		'ftp'     => array( 'FTP server', array( 21, 990 ) ),
		'mssql'   => array( 'SQL Server', array( 1433 ) ),
		'oracle'  => array( 'Oracle Database', array( 1521 ) ),
		'mysql'   => array( 'MySQL / MariaDB', array( 3306 ) ),
		'postgres' => array( 'PostgreSQL', array( 5432 ) ),
		'redis'   => array( 'Redis', array( 6379 ) ),
		'mongodb' => array( 'MongoDB', array( 27017 ) ),
		'search'  => array( 'Elasticsearch', array( 9200, 9300 ) ),
		'cache'   => array( 'Memcached', array( 11211, 'udp/11211' ) ),
		'tls'     => array( 'TLS service', array( 443, 8443, 465, 993, 995, 636, 9443 ) ),
		'rdp'     => array( 'Remote Desktop', array( 3389, 'udp/3389' ) ),
		'windows' => array( 'Windows network services', array( 3389, 445, 139, 135, 5985, 5986, 80, 443, 88, 389, 636, 53 ) ),
		'ntp'     => array( 'NTP', array( 'udp/123' ) ),
		'queue'   => array( 'Message broker', array( 5672, 5671, 61616, 8161 ) ),
		'proxy'   => array( 'Proxy', array( 3128, 8080 ) ),
		'vpn'     => array( 'VPN', array( 'udp/500', 'udp/4500', 'udp/1194', 1194, 443, 943 ) ),
	);

	/**
	 * Normalised products, exact or by prefix (a trailing `*`).
	 */
	private const PRODUCTS = array(
		'openssh'                    => 'ssh',
		'apache-http-server'         => 'web',
		'apache-httpd'               => 'web',
		'nginx'                      => 'web',
		'microsoft-iis'              => 'web',
		'haproxy'                    => 'web',
		'apache-tomcat'              => 'tomcat',
		'oracle-weblogic*'           => 'appweb',
		'oracle-coherence'           => 'appweb',
		'oracle-identity-manager'    => 'appweb',
		'oracle-business-process*'   => 'appweb',
		'oracle-enterprise-manager*' => 'appweb',
		'oracle-global-lifecycle*'   => 'appweb',
		'ibm-websphere*'             => 'appweb',
		'jboss*'                     => 'appweb',
		'wildfly'                    => 'appweb',
		'eclipse-jetty'              => 'appweb',
		'jetty'                      => 'appweb',
		'apache-log4j'               => 'appweb',
		'spring-framework'           => 'appweb',
		'spring'                     => 'appweb',
		'spring-boot'                => 'appweb',
		'apache-struts'              => 'appweb',
		'apache-commons-text'        => 'appweb',
		'apache-commons-fileupload'  => 'appweb',
		'jackson-databind'           => 'appweb',
		'node-js'                    => 'appweb',
		'aiohttp'                    => 'appweb',
		'python-library-aiohttp'     => 'appweb',
		'python-library-tornado'     => 'appweb',
		'openssl'                    => 'tls',
		'samba'                      => 'smb',
		'isc-bind'                   => 'dns',
		'unbound'                    => 'dns',
		'dnsmasq'                    => 'dns',
		'oracle-database*'           => 'oracle',
		'microsoft-sql-server'       => 'mssql',
		'mysql'                      => 'mysql',
		'mariadb'                    => 'mysql',
		'postgresql'                 => 'postgres',
		'redis'                      => 'redis',
		'mongodb'                    => 'mongodb',
		'elasticsearch'              => 'search',
		'apache-activemq'            => 'queue',
		'rabbitmq'                   => 'queue',
		'microsoft-exchange-server'  => 'mail',
		'exim'                       => 'mail',
		'postfix'                    => 'mail',
		'windows-microsoft-updates'  => 'windows',
		'openvpn'                    => 'vpn',
	);

	/**
	 * Distro package names, as regular expressions over one package name.
	 * Server packages only: `openssh-clients`, `libssh`, `bind-utils` and
	 * `samba-client-libs` are on machines that serve nothing.
	 */
	private const PACKAGES = array(
		'/^openssh(-server)?$/'                                   => 'ssh',
		'/^(httpd|mod_ssl|mod_http2|mod_proxy_html|apache2|nginx(-core)?|haproxy)$/' => 'web',
		'/^tomcat\d*$/'                                           => 'tomcat',
		'/^samba$/'                                               => 'smb',
		'/^(bind|bind9|bind-chroot|named|unbound|dnsmasq)$/'      => 'dns',
		'/^(postfix|exim\d*|sendmail|dovecot(-core)?)$/'          => 'mail',
		'/^(vsftpd|proftpd|pure-ftpd)$/'                          => 'ftp',
		// A distro advisory names the source package ("postgresql"), not the
		// server sub-package, so the bare name has to count too.
		'/^(mariadb-server|mysql-server|mysql-community-server)$/' => 'mysql',
		'/^postgresql\d*(-server)?$/'                             => 'postgres',
		'/^redis\d*$/'                                            => 'redis',
		'/^mongodb-org-server$/'                                  => 'mongodb',
		'/^elasticsearch$/'                                       => 'search',
		'/^memcached$/'                                           => 'cache',
		'/^(openssl|openssl-libs|openssl\d+|gnutls)$/'            => 'tls',
		'/^xrdp$/'                                                => 'rdp',
		'/^(ntp|chrony)$/'                                        => 'ntp',
		'/^squid$/'                                               => 'proxy',
		'/^(openvpn|strongswan|libreswan)$/'                      => 'vpn',
	);

	/**
	 * The service a finding's component is, or null when it is not one.
	 *
	 * @param array<string,mixed> $f Finding joined to its definition: port,
	 *                               protocol, product_slug, product_kind,
	 *                               title, and output for package checks.
	 * @return array{key:string,label:string,ports:array<int,string>,component:string}|null
	 *         Ports as "tcp/22" / "udp/53"; component is the package or
	 *         product it matched, for the advice line.
	 */
	public static function of( array $f ): ?array {
		$slug = (string) ( $f['product_slug'] ?? '' );

		foreach ( self::PRODUCTS as $match => $key ) {
			if ( str_ends_with( $match, '*' ) ? str_starts_with( $slug, rtrim( $match, '*' ) ) : $slug === $match ) {
				return self::service( $key, (string) ( $f['product'] ?? '' ) ?: $slug );
			}
		}

		if ( 'os_package' === (string) ( $f['product_kind'] ?? '' ) ) {
			foreach ( self::packages( (string) ( $f['title'] ?? '' ), (string) ( $f['output'] ?? '' ) ) as $pkg ) {
				foreach ( self::PACKAGES as $rx => $key ) {
					if ( preg_match( $rx, $pkg ) ) {
						return self::service( $key, $pkg );
					}
				}
			}

			return null;
		}

		/*
		 * The scanner's port, last and only for a remote check. A local check
		 * reports the port it *logged in* over -- 445 for every credentialed
		 * Windows scan, so a SQLite DLL, a 7-Zip install and a .NET runtime
		 * all arrive "on 445". Taking that as where the bug lives would call
		 * every one of them an SMB exposure.
		 */
		$port = (int) ( $f['port'] ?? 0 );

		if ( $port > 0 && self::is_remote_check( $f ) ) {
			$proto = strtolower( (string) ( $f['protocol'] ?? 'tcp' ) ) ?: 'tcp';

			return array(
				'key'       => 'port',
				'label'     => self::name_port( $port ),
				'ports'     => array( $proto . '/' . $port ),
				'component' => '',
			);
		}

		return null;
	}

	/**
	 * Whether a check talked to the service rather than reading the disk:
	 * its family is one of the network ones, or its title says it ran
	 * without credentials.
	 *
	 * @param array<string,mixed> $f Finding with family and title.
	 */
	private static function is_remote_check( array $f ): bool {
		$title = strtolower( (string) ( $f['title'] ?? '' ) );

		if ( str_contains( $title, 'uncredentialed check' ) || str_contains( $title, 'remote check' ) ) {
			return true;
		}

		return in_array(
			(string) ( $f['family'] ?? '' ),
			array( 'Web Servers', 'CGI abuses', 'CGI abuses : XSS', 'Service detection', 'Gain a shell remotely', 'Firewalls', 'FTP', 'DNS', 'SMTP problems', 'SNMP', 'RPC', 'Backdoors', 'Denial of Service', 'Peer-To-Peer File Sharing', 'Default Unix Accounts' ),
			true
		);
	}

	/**
	 * Whether a finding needs its output read to be placed: only a package
	 * check whose title does not name the package. Lets a caller skip loading
	 * a longtext column for every other row.
	 */
	public static function needs_output( array $f ): bool {
		$title = (string) ( $f['title'] ?? '' );

		return 'os_package' === (string) ( $f['product_kind'] ?? '' )
			&& ( ! str_contains( $title, ' : ' ) || str_starts_with( $title, 'Linux Distros Unpatched' ) );
	}

	/**
	 * The package names a package check is about.
	 *
	 * "RHEL 9 : openssh (RHSA-…)" and "Amazon Linux 2 : bind, --advisory …"
	 * name them after the colon; the unpatched-CVE family lists them in its
	 * output as "  - openssh-server".
	 *
	 * @return string[]
	 */
	private static function packages( string $title, string $output ): array {
		$out = array();

		if ( preg_match( '/ : ([^()]+)/', $title, $m ) && ! str_contains( $m[1], 'CVE-' ) ) {
			foreach ( explode( ',', $m[1] ) as $p ) {
				$p = strtolower( trim( $p ) );

				if ( '' !== $p && ! str_starts_with( $p, '--' ) ) {
					$out[] = $p;
				}
			}
		}

		if ( '' !== $output && preg_match_all( '/^\s*-\s+([A-Za-z0-9][A-Za-z0-9._+-]*)\s*$/m', $output, $m ) ) {
			foreach ( $m[1] as $p ) {
				$out[] = strtolower( $p );
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * @return array{key:string,label:string,ports:array<int,string>,component:string}
	 */
	private static function service( string $key, string $component ): array {
		[ $label, $ports ] = self::SERVICES[ $key ];

		return array(
			'key'       => $key,
			'label'     => $label,
			'ports'     => array_map( static fn( $p ): string => is_int( $p ) ? 'tcp/' . $p : (string) $p, $ports ),
			'component' => $component,
		);
	}

	/** A name for a bare port a scanner reported. */
	private static function name_port( int $port ): string {
		foreach ( self::SERVICES as $def ) {
			if ( 1 === count( $def[1] ) && $port === $def[1][0] ) {
				return $def[0];
			}
		}

		return match ( $port ) {
			445, 139   => 'SMB file sharing',
			3389       => 'Remote Desktop',
			80, 443    => 'Web server',
			default    => sprintf( /* translators: %d: port. */ __( 'Service on port %d', 'vulnhub' ), $port ),
		};
	}

	/**
	 * Which of a service's ports a way in admits, preferring one the host is
	 * known to listen on -- DNS answers on udp/53 more often than tcp/53, and
	 * "the first port that fits" said "not listening" about a live resolver.
	 *
	 * @param array<int,string>   $ports     "tcp/22" / "udp/53".
	 * @param array<string,mixed> $way       {protocol, port_from, port_to}.
	 * @param array<int,string>   $listening Ports seen listening, if known.
	 */
	public static function pick( array $ports, array $way, array $listening ): string {
		$first = '';

		foreach ( $ports as $p ) {
			if ( '' === self::admitted( array( $p ), $way ) ) {
				continue;
			}
			if ( in_array( $p, $listening, true ) ) {
				return $p;
			}
			if ( '' === $first ) {
				$first = $p;
			}
		}

		return $first;
	}

	/**
	 * The first of a service's ports that a way in admits, or ''.
	 *
	 * @param array<int,string>   $ports "tcp/22" / "udp/53".
	 * @param array<string,mixed> $way   {protocol, port_from, port_to}.
	 */
	public static function admitted( array $ports, array $way ): string {
		foreach ( $ports as $p ) {
			[ $proto, $n ] = explode( '/', $p, 2 );
			$n             = (int) $n;
			$wp            = (string) ( $way['protocol'] ?? 'tcp' );

			if ( ( in_array( $wp, array( 'all', 'any', '-1' ), true ) || $wp === $proto ) && $n >= (int) $way['port_from'] && $n <= (int) $way['port_to'] ) {
				return $p;
			}
		}

		return '';
	}
}
