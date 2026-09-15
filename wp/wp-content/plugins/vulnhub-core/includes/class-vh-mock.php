<?php
/**
 * Deterministic mock dataset shared by every connector.
 *
 * This matters: the Tenable fixture and the Intune fixture must describe the
 * SAME devices, or the ownership-mapping engine has nothing to join on. The
 * generator is seeded so every connector sees an identical fleet.
 *
 * Field names deliberately mirror the real vendor payloads so the mock path
 * and the live path run through the same normalisation code.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mock {

	private const SEED = 20260907;

	private static ?array $people  = null;
	private static ?array $devices = null;
	private static ?array $vulns   = null;

	private static int $cursor = 0;

	/**
	 * Tiny deterministic LCG so the fleet is stable across runs and processes.
	 */
	private static function rnd( int $max ): int {
		self::$cursor = ( self::$cursor * 1103515245 + 12345 ) & 0x7FFFFFFF;
		return $max > 0 ? self::$cursor % $max : 0;
	}

	private static function pick( array $list ): mixed {
		return $list[ self::rnd( count( $list ) ) ];
	}

	private static function reset(): void {
		self::$cursor = self::SEED;
	}

	/* =================================================================
	 * People — shaped like Microsoft Graph /users
	 * ============================================================== */

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public static function people(): array {
		if ( null !== self::$people ) {
			return self::$people;
		}
		self::reset();

		$first = array( 'Aroha', 'Avi', 'Chloe', 'Daniel', 'Eleni', 'Finn', 'Grace', 'Hemi', 'Isla', 'James', 'Kiri', 'Liam', 'Maia', 'Noah', 'Olivia', 'Priya', 'Quinn', 'Rangi', 'Sofia', 'Tane', 'Uma', 'Vikram', 'Willow', 'Xavier', 'Yasmin', 'Zach', 'Anahera', 'Bruno', 'Catherine', 'Dev', 'Emma', 'Farid', 'Georgia', 'Harold', 'Ines', 'Jonas', 'Kavya', 'Lucas', 'Mereana', 'Nikau' );
		$last  = array( 'Whitiora', 'Clarke', 'Nguyen', 'Patel', 'Kowalski', 'Tapu', 'Robinson', 'Ngata', 'Fernandez', 'Wright', 'Kaur', 'Osei', 'Silva', 'Andersen', 'Brown', 'Chen', 'Dubois', 'Eriksen', 'Foster', 'Gallagher', 'Hughes', 'Ivanov', 'Jenkins', 'Kim', 'Lopez', 'Murray', 'Novak', 'Ohara', 'Pereira', 'Rahman', 'Stewart', 'Thompson', 'Ueda', 'Vargas', 'Wallace', 'Yildiz', 'Zhang', 'Ashford', 'Beckett', 'Cormack' );

		$departments = array(
			'End User Computing'  => array( 'Service Desk Analyst', 'Desktop Engineer', 'EUC Team Lead' ),
			'Infrastructure'      => array( 'Systems Engineer', 'Platform Engineer', 'Infrastructure Manager' ),
			'Application Support' => array( 'Application Analyst', 'Integration Developer', 'Support Lead' ),
			'Network Operations'  => array( 'Network Engineer', 'Network Architect', 'NOC Analyst' ),
			'Cloud Platform'      => array( 'Cloud Engineer', 'SRE', 'Cloud Security Engineer' ),
			'Finance'             => array( 'Financial Analyst', 'Accounts Payable Officer', 'Finance Manager' ),
			'People & Culture'    => array( 'HR Advisor', 'Recruitment Partner', 'P&C Manager' ),
			'Sales'               => array( 'Account Manager', 'Sales Engineer', 'Regional Sales Lead' ),
			'Operations'          => array( 'Operations Coordinator', 'Logistics Analyst', 'Operations Manager' ),
			'Legal & Risk'        => array( 'Legal Counsel', 'Risk Analyst', 'Compliance Manager' ),
		);

		$offices = array(
			array( 'Auckland HQ', 'Auckland', 'Auckland', 'New Zealand' ),
			array( 'Wellington Office', 'Wellington', 'Wellington', 'New Zealand' ),
			array( 'Christchurch Office', 'Christchurch', 'Canterbury', 'New Zealand' ),
			array( 'Sydney Office', 'Sydney', 'NSW', 'Australia' ),
			array( 'Remote / Home', '', '', 'New Zealand' ),
		);

		$dept_names = array_keys( $departments );
		$people     = array();

		// One manager per department first, so manager_upn resolves.
		$managers = array();
		foreach ( $dept_names as $i => $dept ) {
			$fn     = $first[ $i % count( $first ) ];
			$ln     = $last[ ( $i * 3 + 7 ) % count( $last ) ];
			$upn    = strtolower( "{$fn}.{$ln}@example.com" );
			$office = $offices[ $i % count( $offices ) ];

			$managers[ $dept ] = $upn;
			$people[]          = array(
				'id'                => sprintf( '%08x-mgr%d-4a1b-9c2d-%012x', 0xA0000000 + $i, $i, 0xB00000000000 + $i ),
				'displayName'       => "{$fn} {$ln}",
				'givenName'         => $fn,
				'surname'           => $ln,
				'userPrincipalName' => $upn,
				'mail'              => $upn,
				'jobTitle'          => end( $departments[ $dept ] ),
				'department'        => $dept,
				'companyName'       => 'Romy NZ Limited',
				'officeLocation'    => $office[0],
				'city'              => $office[1],
				'state'             => $office[2],
				'country'           => $office[3],
				'usageLocation'     => 'Australia' === $office[3] ? 'AU' : 'NZ',
				'employeeId'        => sprintf( 'E%05d', 1000 + $i ),
				'accountEnabled'    => true,
				'manager'           => null,
				'isManager'         => true,
			);
		}

		for ( $i = 0; $i < 46; $i++ ) {
			$fn     = $first[ self::rnd( count( $first ) ) ];
			$ln     = $last[ self::rnd( count( $last ) ) ];
			$dept   = $dept_names[ self::rnd( count( $dept_names ) ) ];
			$titles = $departments[ $dept ];
			$office = $offices[ self::rnd( count( $offices ) ) ];
			$upn    = strtolower( "{$fn}.{$ln}{$i}@example.com" );

			$people[] = array(
				'id'                => sprintf( '%08x-%04x-4b2c-8d3e-%012x', 0xC0000000 + $i * 977, $i, 0xD00000000000 + $i * 31 ),
				'displayName'       => "{$fn} {$ln}",
				'givenName'         => $fn,
				'surname'           => $ln,
				'userPrincipalName' => $upn,
				'mail'              => $upn,
				'jobTitle'          => $titles[ self::rnd( count( $titles ) ) ],
				'department'        => $dept,
				'companyName'       => 'Romy NZ Limited',
				'officeLocation'    => $office[0],
				'city'              => $office[1],
				'state'             => $office[2],
				'country'           => $office[3],
				'usageLocation'     => 'Australia' === $office[3] ? 'AU' : 'NZ',
				'employeeId'        => sprintf( 'E%05d', 2000 + $i ),
				'accountEnabled'    => self::rnd( 100 ) > 4,
				'manager'           => array(
					'userPrincipalName' => $managers[ $dept ],
					'displayName'       => '',
				),
				'isManager'         => false,
			);
		}

		self::$people = $people;
		return $people;
	}

	/* =================================================================
	 * Devices — the shared fleet
	 * ============================================================== */

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public static function devices(): array {
		if ( null !== self::$devices ) {
			return self::$devices;
		}

		$people = self::people();
		self::reset();
		self::rnd( 999 ); // Advance so device ids differ from people ids.

		$devices = array();

		$laptops = array(
			array( 'Dell', 'Latitude 7440' ),
			array( 'Dell', 'Latitude 5540' ),
			array( 'Lenovo', 'ThinkPad X1 Carbon Gen 11' ),
			array( 'Lenovo', 'ThinkPad T14 Gen 4' ),
			array( 'HP', 'EliteBook 840 G10' ),
			array( 'Apple', 'MacBook Pro 14-inch M3' ),
			array( 'Apple', 'MacBook Air 13-inch M2' ),
			array( 'Microsoft', 'Surface Laptop 5' ),
		);
		$win_versions = array( '10.0.19045.4529', '10.0.22631.3737', '10.0.22621.3593', '10.0.19045.3803' );
		$mac_versions = array( '14.5', '14.4.1', '13.6.7', '15.0' );

		// --- Workstations -------------------------------------------------
		$n = 0;
		foreach ( $people as $person ) {
			if ( ! $person['accountEnabled'] ) {
				continue;
			}
			$count = self::rnd( 100 ) < 12 ? 2 : 1; // A few people have two machines.
			for ( $c = 0; $c < $count; $c++ ) {
				++$n;
				$hw      = $laptops[ self::rnd( count( $laptops ) ) ];
				$is_mac  = 'Apple' === $hw[0];
				$host    = sprintf( '%s-%s%03d', $is_mac ? 'MAC' : 'NZWS', strtoupper( substr( (string) $person['surname'], 0, 3 ) ), $n );
				$devices[] = self::device_record(
					$n,
					$host,
					'workstation',
					$is_mac ? 'macOS' : 'Windows',
					$is_mac ? $mac_versions[ self::rnd( count( $mac_versions ) ) ] : $win_versions[ self::rnd( count( $win_versions ) ) ],
					$hw[0],
					$hw[1],
					$person
				);
			}
		}

		// --- Mobile devices ------------------------------------------------
		$phones = array(
			array( 'Apple', 'iPhone 15 Pro', 'iOS', '17.5.1' ),
			array( 'Apple', 'iPhone 14', 'iOS', '17.4.1' ),
			array( 'Samsung', 'Galaxy S24', 'Android', '14' ),
			array( 'Google', 'Pixel 8', 'Android', '14' ),
		);
		for ( $i = 0; $i < 18; $i++ ) {
			++$n;
			$person = $people[ self::rnd( count( $people ) ) ];
			$hw     = $phones[ self::rnd( count( $phones ) ) ];
			$devices[] = self::device_record(
				$n,
				sprintf( 'MOB-%s%03d', strtoupper( substr( (string) $person['surname'], 0, 2 ) ), $n ),
				'mobile',
				$hw[2],
				$hw[3],
				$hw[0],
				$hw[1],
				$person
			);
		}

		// --- Servers (team-owned, NOT user-owned) ---------------------------
		$servers = array(
			array( 'NZAKLDC01', 'Windows Server', '10.0.20348.2402', 'Infrastructure', 'production', 'Active Directory' ),
			array( 'NZAKLDC02', 'Windows Server', '10.0.20348.2402', 'Infrastructure', 'production', 'Active Directory' ),
			array( 'NZAKLFS01', 'Windows Server', '10.0.17763.5936', 'Infrastructure', 'production', 'File Services' ),
			array( 'NZAKLSQL01', 'Windows Server', '10.0.20348.2402', 'Application Support', 'production', 'Finance ERP' ),
			array( 'NZAKLSQL02', 'Windows Server', '10.0.17763.5936', 'Application Support', 'production', 'Finance ERP' ),
			array( 'NZWLGAPP01', 'Windows Server', '10.0.20348.2402', 'Application Support', 'production', 'Intranet' ),
			array( 'NZWLGAPP02', 'Windows Server', '10.0.20348.2402', 'Application Support', 'staging', 'Intranet' ),
			array( 'NZAKLWEB01', 'Ubuntu', '22.04.4 LTS', 'Cloud Platform', 'production', 'Customer Portal' ),
			array( 'NZAKLWEB02', 'Ubuntu', '22.04.4 LTS', 'Cloud Platform', 'production', 'Customer Portal' ),
			array( 'NZAKLWEB03', 'Ubuntu', '20.04.6 LTS', 'Cloud Platform', 'staging', 'Customer Portal' ),
			array( 'NZAKLAPI01', 'Ubuntu', '22.04.4 LTS', 'Cloud Platform', 'production', 'Partner API' ),
			array( 'NZAKLK8S01', 'Ubuntu', '22.04.4 LTS', 'Cloud Platform', 'production', 'Container Platform' ),
			array( 'NZAKLK8S02', 'Ubuntu', '22.04.4 LTS', 'Cloud Platform', 'production', 'Container Platform' ),
			array( 'NZAKLK8S03', 'Ubuntu', '22.04.4 LTS', 'Cloud Platform', 'production', 'Container Platform' ),
			array( 'NZAKLBKP01', 'Windows Server', '10.0.17763.5936', 'Infrastructure', 'production', 'Backup' ),
			array( 'NZAKLPRT01', 'Windows Server', '10.0.17763.5936', 'End User Computing', 'production', 'Print Services' ),
			array( 'NZCHCFS01', 'Windows Server', '10.0.20348.2402', 'Infrastructure', 'production', 'File Services' ),
			array( 'NZAKLMON01', 'Debian', '12.5', 'Infrastructure', 'production', 'Monitoring' ),
			array( 'NZAKLLEG01', 'Windows Server', '6.3.9600', 'Application Support', 'production', 'Legacy Payroll' ),
			array( 'NZAKLDEV01', 'Ubuntu', '22.04.4 LTS', 'Cloud Platform', 'development', 'Build Agent' ),
			array( 'NZAKLDEV02', 'Ubuntu', '22.04.4 LTS', 'Cloud Platform', 'development', 'Build Agent' ),
			array( 'NZAKLVPN01', 'Ubuntu', '22.04.4 LTS', 'Network Operations', 'production', 'Remote Access' ),
		);
		foreach ( $servers as $s ) {
			++$n;
			$devices[] = self::device_record( $n, $s[0], 'server', $s[1], $s[2], 'VMware', 'Virtual Machine', null, $s[3], $s[4], $s[5] );
		}

		// --- Network devices ------------------------------------------------
		$network = array(
			array( 'NZAKLSW-CORE01', 'Cisco', 'Catalyst 9300', 'IOS-XE 17.09.04a' ),
			array( 'NZAKLSW-CORE02', 'Cisco', 'Catalyst 9300', 'IOS-XE 17.09.04a' ),
			array( 'NZAKLSW-EDGE01', 'Cisco', 'Catalyst 2960X', 'IOS 15.2(7)E6' ),
			array( 'NZWLGSW-EDGE01', 'Aruba', 'CX 6300', 'AOS-CX 10.11' ),
			array( 'NZAKLFW01', 'Palo Alto', 'PA-3220', 'PAN-OS 11.0.3' ),
			array( 'NZAKLFW02', 'Palo Alto', 'PA-3220', 'PAN-OS 10.2.7' ),
			array( 'NZAKLWLC01', 'Cisco', 'Catalyst 9800', 'IOS-XE 17.09.04a' ),
			array( 'NZCHCSW-EDGE01', 'Aruba', 'CX 6200', 'AOS-CX 10.10' ),
		);
		foreach ( $network as $d ) {
			++$n;
			$devices[] = self::device_record( $n, $d[0], 'network', $d[1], $d[3], $d[1], $d[2], null, 'Network Operations', 'production', 'Core Network' );
		}

		self::$devices = $devices;
		return $devices;
	}

	/**
	 * @param array<string,mixed>|null $person Assigned user, when the device has one.
	 * @return array<string,mixed>
	 */
	private static function device_record(
		int $n,
		string $hostname,
		string $type,
		string $os,
		string $os_version,
		string $manufacturer,
		string $model,
		?array $person = null,
		string $team = '',
		string $environment = '',
		string $service = ''
	): array {
		$octet3 = match ( $type ) {
			'workstation' => 20 + ( $n % 6 ),
			'mobile'      => 40,
			'server'      => 10,
			'network'     => 1,
			default       => 30,
		};

		$office  = $person['officeLocation'] ?? ( str_starts_with( $hostname, 'NZWLG' ) ? 'Wellington Office' : ( str_starts_with( $hostname, 'NZCHC' ) ? 'Christchurch Office' : 'Auckland HQ' ) );
		$is_mac  = 'macOS' === $os;
		$managed = in_array( $type, array( 'workstation', 'mobile' ), true );

		return array(
			'seq'                => $n,
			'hostname'           => $hostname,
			'fqdn'               => strtolower( $hostname ) . '.corp.example.com',
			'asset_type'         => $type,
			'ipv4'               => sprintf( '10.%d.%d.%d', 'server' === $type ? 20 : 10, $octet3, 10 + ( $n % 240 ) ),
			'mac'                => strtoupper( implode( ':', str_split( substr( md5( $hostname ), 0, 12 ), 2 ) ) ),
			'serial'             => strtoupper( substr( sha1( $hostname . 'serial' ), 0, 10 ) ),
			'operating_system'   => $os,
			'os_version'         => $os_version,
			'manufacturer'       => $manufacturer,
			'model'              => $model,
			'tenable_uuid'       => self::uuid( 'tenable' . $hostname ),
			'intune_id'          => $managed ? self::uuid( 'intune' . $hostname ) : '',
			'azure_ad_device_id' => $managed ? self::uuid( 'aad' . $hostname ) : '',
			'cmdb_id'            => sprintf( 'CI%06d', 100000 + $n ),
			'owner_upn'          => $person['userPrincipalName'] ?? '',
			'owner_name'         => $person['displayName'] ?? '',
			'owner_id'           => $person['id'] ?? '',
			'department'         => $person['department'] ?? $team,
			'office_location'    => $office,
			'team'               => $team ?: ( $person['department'] ?? '' ),
			'environment'        => $environment ?: ( 'workstation' === $type ? 'corporate' : '' ),
			'business_service'   => $service,
			'compliance_state'   => $managed ? ( self::rnd( 100 ) < 82 ? 'compliant' : 'noncompliant' ) : '',
			'enrollment_type'    => $managed ? ( $is_mac ? 'appleUserEnrollment' : 'windowsAzureADJoin' ) : '',
			'join_type'          => $managed ? 'azureADJoined' : '',
			'criticality'        => match ( $type ) {
				'server'  => in_array( $environment, array( 'production' ), true ) ? 'high' : 'medium',
				'network' => 'critical',
				default   => 'medium',
			},
			'last_seen'          => gmdate( 'Y-m-d H:i:s', time() - self::rnd( 72 ) * HOUR_IN_SECONDS ),
			'first_seen'         => gmdate( 'Y-m-d H:i:s', time() - ( 90 + self::rnd( 500 ) ) * DAY_IN_SECONDS ),
			'has_agent'          => 'network' !== $type,
		);
	}

	private static function uuid( string $seed ): string {
		$h = md5( $seed );
		return sprintf(
			'%s-%s-4%s-a%s-%s',
			substr( $h, 0, 8 ),
			substr( $h, 8, 4 ),
			substr( $h, 13, 3 ),
			substr( $h, 17, 3 ),
			substr( $h, 20, 12 )
		);
	}

	/* =================================================================
	 * Vulnerability catalogue — shaped like Tenable plugin data
	 * ============================================================== */

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public static function vulns(): array {
		if ( null !== self::$vulns ) {
			return self::$vulns;
		}

		self::$vulns = array(
			array( '19506', 'Nessus Scan Information', 'info', 0.0, 0.0, 0.0, 'General', array(), 'Informational plugin describing the scan.', 'n/a', false, array( 'Windows', 'Ubuntu', 'macOS', 'Debian' ) ),
			array( '182291', 'Microsoft Windows 10 / 11 Cumulative Update Missing (June 2026)', 'critical', 9.8, 9.8, 9.4, 'Windows : Microsoft Bulletins', array( 'CVE-2026-21762', 'CVE-2026-21798' ), 'The remote Windows host is missing the latest cumulative security update. An unauthenticated attacker can achieve remote code execution via a crafted network request to the affected service.', 'Apply the June 2026 cumulative update via Windows Update or WSUS.', true, array( 'Windows' ) ),
			array( '180411', 'Google Chrome < 126.0.6478.114 Multiple Vulnerabilities', 'high', 8.8, 8.8, 7.8, 'Windows', array( 'CVE-2026-5493', 'CVE-2026-5494', 'CVE-2026-5495' ), 'The version of Google Chrome installed on the remote host is affected by multiple memory-corruption vulnerabilities in V8 and WebRTC that allow remote code execution when a user visits a malicious page.', 'Upgrade Google Chrome to 126.0.6478.114 or later.', true, array( 'Windows', 'macOS' ) ),
			array( '176321', 'OpenSSH < 9.6 Remote Code Execution (regreSSHion)', 'critical', 9.8, 9.8, 9.1, 'Misc.', array( 'CVE-2026-6387' ), 'A signal-handler race condition in OpenSSH server allows unauthenticated remote code execution as root on glibc-based Linux systems.', 'Upgrade OpenSSH to 9.6 or later, or set LoginGraceTime to 0 as a temporary mitigation.', true, array( 'Ubuntu', 'Debian' ) ),
			array( '156032', 'Apache Log4j 1.2 Deprecated and Unsupported', 'high', 7.5, 7.5, 6.7, 'Web Servers', array( 'CVE-2022-23305' ), 'An unsupported version of Apache Log4j is installed. Log4j 1.x reached end of life in 2015 and receives no security fixes.', 'Migrate to Log4j 2.17.1 or later.', false, array( 'Ubuntu', 'Windows Server' ) ),
			array( '171953', 'SSL Certificate Expired', 'medium', 5.3, 5.3, 3.6, 'General', array(), 'The SSL certificate presented by the service has expired, so clients cannot validate the identity of the server.', 'Renew the certificate and redeploy it to the affected service.', false, array( 'Ubuntu', 'Windows Server', 'Debian' ) ),
			array( '157288', 'SMB Signing Not Required', 'medium', 5.3, 5.3, 4.2, 'Misc.', array(), 'Signing is not required on the remote SMB server, which permits man-in-the-middle attacks against SMB clients.', 'Enforce message signing in the host\'s configuration (Group Policy: Microsoft network server: Digitally sign communications).', false, array( 'Windows', 'Windows Server' ) ),
			array( '168746', 'TLS Version 1.0 and 1.1 Protocol Detection', 'medium', 6.5, 6.5, 3.9, 'Service detection', array(), 'The remote service accepts connections using TLS 1.0 or 1.1. These versions have known weaknesses and are deprecated.', 'Disable TLS 1.0 and 1.1 and enable TLS 1.2 or 1.3 only.', false, array( 'Windows Server', 'Ubuntu', 'Debian', 'IOS-XE' ) ),
			array( '186122', 'Microsoft Exchange Server Elevation of Privilege', 'critical', 9.1, 9.1, 8.9, 'Windows : Microsoft Bulletins', array( 'CVE-2026-21410' ), 'A NTLM relay vulnerability in Exchange Server allows an attacker to elevate privileges to those of another user.', 'Apply the latest Exchange Server cumulative update and enable Extended Protection.', true, array( 'Windows Server' ) ),
			array( '183211', 'Cisco IOS XE Web UI Privilege Escalation', 'critical', 10.0, 10.0, 9.6, 'CISCO', array( 'CVE-2023-20198' ), 'An unauthenticated remote attacker can create a level 15 account on the affected device via the web UI, giving full control of the device.', 'Disable the HTTP/HTTPS server feature or upgrade to a fixed IOS XE release.', true, array( 'IOS-XE', 'IOS' ) ),
			array( '179322', 'PAN-OS Command Injection in GlobalProtect', 'critical', 10.0, 10.0, 9.8, 'Palo Alto Networks', array( 'CVE-2026-3400' ), 'Command injection in the GlobalProtect feature allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.', 'Upgrade to PAN-OS 11.0.4-h1 or later and rotate all device credentials.', true, array( 'PAN-OS' ) ),
			array( '148921', 'Unsupported Windows Server Version (2012 R2)', 'high', 8.1, 8.1, 7.4, 'Windows', array(), 'The remote host runs a version of Windows Server that is no longer supported and receives no security updates.', 'Upgrade to a supported release of Windows Server.', false, array( 'Windows Server' ) ),
			array( '162055', 'Ubuntu 20.04 LTS : linux vulnerabilities (USN-6800-1)', 'high', 7.8, 7.8, 6.4, 'Ubuntu Local Security Checks', array( 'CVE-2026-26925', 'CVE-2026-27397' ), 'The remote Ubuntu host is missing kernel security updates that address local privilege escalation flaws.', 'Update the affected linux-image packages and reboot.', false, array( 'Ubuntu' ) ),
			array( '169400', 'Mozilla Firefox < 127.0 Multiple Vulnerabilities', 'high', 8.8, 8.8, 6.9, 'Windows', array( 'CVE-2026-5687', 'CVE-2026-5688' ), 'The installed Firefox build is affected by multiple memory-safety issues that could be exploited to run arbitrary code.', 'Upgrade Firefox to 127.0 or later.', false, array( 'Windows', 'macOS', 'Ubuntu' ) ),
			array( '158911', 'Adobe Acrobat Reader Multiple Vulnerabilities (APSB26-29)', 'high', 7.8, 7.8, 6.1, 'Windows', array( 'CVE-2026-30279', 'CVE-2026-30280' ), 'The installed Adobe Acrobat Reader is missing a security update and is affected by use-after-free vulnerabilities leading to code execution.', 'Update Acrobat Reader to the latest release.', false, array( 'Windows', 'macOS' ) ),
			array( '174088', 'macOS 14.x < 14.5 Multiple Vulnerabilities', 'high', 7.8, 7.8, 5.9, 'MacOS X Local Security Checks', array( 'CVE-2026-27834' ), 'The remote macOS host is missing a security update that addresses kernel and WebKit vulnerabilities.', 'Upgrade to macOS 14.5 or later.', false, array( 'macOS' ) ),
			array( '166123', 'Weak Password Policy Detected', 'medium', 5.5, 5.5, 3.1, 'Policy Compliance', array(), 'The account lockout threshold and minimum password length do not meet baseline requirements.', 'Tighten the domain password policy to the organisation\'s baseline.', false, array( 'Windows Server' ) ),
			array( '163777', 'Java SE Multiple Vulnerabilities (April 2026 CPU)', 'high', 7.5, 7.5, 5.8, 'Windows', array( 'CVE-2026-21094' ), 'The Java runtime installed on the host is missing the April 2026 Critical Patch Update.', 'Upgrade the JRE/JDK to the latest patched release.', false, array( 'Windows', 'Ubuntu', 'Windows Server' ) ),
			array( '154002', 'ICMP Timestamp Request Remote Date Disclosure', 'low', 2.1, 0.0, 0.9, 'General', array( 'CVE-1999-0524' ), 'The remote host answers ICMP timestamp requests, disclosing the system time.', 'Filter ICMP timestamp requests and replies at the firewall.', false, array( 'Windows', 'Ubuntu', 'Debian', 'Windows Server', 'IOS-XE' ) ),
			array( '155444', 'Terminal Services Encryption Level is Medium or Low', 'low', 4.3, 4.3, 1.9, 'Misc.', array(), 'The remote Terminal Services service is not configured to use strong cryptography.', 'Set the encryption level to High or FIPS Compliant.', false, array( 'Windows', 'Windows Server' ) ),
			array( '187330', 'VMware Tools Out of Date', 'low', 3.3, 3.3, 1.4, 'Misc.', array(), 'The version of VMware Tools installed on the guest is out of date.', 'Update VMware Tools to the version bundled with the current ESXi build.', false, array( 'Windows Server', 'Ubuntu' ) ),
			array( '181002', 'Microsoft Office Remote Code Execution', 'critical', 8.8, 8.8, 8.4, 'Windows : Microsoft Bulletins', array( 'CVE-2026-30103' ), 'A remote code execution vulnerability exists in Microsoft Outlook when parsing a specially crafted message.', 'Apply the latest Microsoft Office security update.', true, array( 'Windows' ) ),
			array( '184555', 'Docker Engine Privilege Escalation', 'high', 8.6, 8.6, 7.2, 'Misc.', array( 'CVE-2026-21626' ), 'A file-descriptor leak in runc allows a container process to escape to the host.', 'Upgrade Docker Engine / containerd to a patched release.', true, array( 'Ubuntu', 'Debian' ) ),
			array( '176900', 'Nginx < 1.25.4 HTTP/3 Vulnerabilities', 'medium', 6.5, 6.5, 4.4, 'Web Servers', array( 'CVE-2026-24989' ), 'The remote nginx build is affected by flaws in the HTTP/3 QUIC module that can crash the worker process.', 'Upgrade nginx to 1.25.4 or later, or disable HTTP/3.', false, array( 'Ubuntu', 'Debian' ) ),
			array( '170233', 'MySQL / MariaDB Multiple Vulnerabilities', 'medium', 6.5, 6.5, 4.0, 'Databases', array( 'CVE-2026-21096' ), 'The database server is missing security updates addressing denial-of-service and partial data disclosure flaws.', 'Apply the vendor security update for the database engine.', false, array( 'Ubuntu', 'Windows Server' ) ),
		);

		return self::$vulns;
	}

	/**
	 * Vulnerability rows applicable to a device's OS.
	 *
	 * @param array<string,mixed> $device Device record.
	 * @return array<int,array<string,mixed>>
	 */
	public static function vulns_for_device( array $device ): array {
		$os  = (string) $device['operating_system'];
		$out = array();

		foreach ( self::vulns() as $v ) {
			foreach ( (array) $v[11] as $applies ) {
				if ( str_contains( $os, $applies ) || str_contains( $applies, $os ) ) {
					$out[] = $v;
					break;
				}
			}
		}

		return $out;
	}

	/**
	 * Deterministically decide whether a device has a given vulnerability,
	 * so repeated syncs are idempotent rather than random churn.
	 */
	public static function has_vuln( string $hostname, string $plugin_id, string $severity ): bool {
		$hash = hexdec( substr( md5( $hostname . ':' . $plugin_id ), 0, 6 ) ) % 100;

		return match ( $severity ) {
			'critical' => $hash < 18,
			'high'     => $hash < 34,
			'medium'   => $hash < 52,
			'low'      => $hash < 46,
			default    => $hash < 90,
		};
	}

	/**
	 * Reset the memoised fixtures (used by tests).
	 */
	public static function flush(): void {
		self::$people  = null;
		self::$devices = null;
		self::$vulns   = null;
	}
}

