<?php
/**
 * Mock Microsoft Graph transport.
 *
 * This is NOT a second code path. It reshapes core's shared fixtures
 * (\VulnHub\Core\Mock) into real Graph payloads — `value` collections,
 * `@odata.nextLink` paging, `$batch` response envelopes — and hands them back
 * to VulnHub_Intune_Client, which then runs the exact same paging, batching and
 * normalisation code it uses against live Graph. If the mock sync resolves
 * ownership, the live sync will too.
 *
 * Two deliberate quirks are baked in because they are real:
 *  - the fixtures are served in small pages, so the nextLink loop is genuinely
 *    exercised rather than short-circuited by a single page;
 *  - a few devices have no primary user at all (shared / kiosk machines), which
 *    is what the "unresolved workstations" screen exists to surface.
 *
 * @package VulnHub\Intune
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generates Graph-shaped payloads from the shared mock fleet.
 */
final class VulnHub_Intune_Mock_Graph {

	/**
	 * Graph base URL being emulated.
	 *
	 * @var string
	 */
	private string $base_url;

	/**
	 * Page size used for generated collections.
	 *
	 * @var int
	 */
	private int $page_size;

	/**
	 * Memoised Graph user objects.
	 *
	 * @var array<int,array<string,mixed>>|null
	 */
	private ?array $users = null;

	/**
	 * Memoised Graph managedDevice objects.
	 *
	 * @var array<int,array<string,mixed>>|null
	 */
	private ?array $devices = null;

	/**
	 * Memoised group membership map: user id => group objects.
	 *
	 * @var array<string,array<int,array<string,mixed>>>|null
	 */
	private ?array $memberships = null;

	/**
	 * Constructor.
	 *
	 * @param string $base_url  Graph base URL, e.g. https://graph.microsoft.com/v1.0.
	 * @param int    $page_size Records per generated page.
	 */
	public function __construct( string $base_url, int $page_size = 25 ) {
		$this->base_url  = rtrim( $base_url, '/' );
		$this->page_size = max( 1, $page_size );
	}

	/* -----------------------------------------------------------------
	 * Routing
	 * --------------------------------------------------------------- */

	/**
	 * Answer a GET for an absolute Graph URL.
	 *
	 * @param string $url Absolute URL the client wants to fetch.
	 * @return array<string,mixed> Graph payload.
	 */
	public function respond( string $url ): array {
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		$path = $this->strip_version( $path );

		if ( str_starts_with( $path, 'organization' ) ) {
			return array(
				'@odata.context' => $this->base_url . '/$metadata#organization',
				'value'          => array( $this->tenant() ),
			);
		}

		if ( str_starts_with( $path, 'deviceManagement/managedDevices' ) ) {
			return $this->page( $this->devices(), $url, 'deviceManagement/managedDevices' );
		}

		// /users/{id}/memberOf[/microsoft.graph.group]
		if ( preg_match( '~^users/([^/]+)/(?:transitiveMemberOf|memberOf)~', $path, $matches ) ) {
			$uid = strtolower( rawurldecode( $matches[1] ) );
			return array(
				'@odata.context' => $this->base_url . '/$metadata#directoryObjects',
				'value'          => $this->memberships()[ $uid ] ?? array(),
			);
		}

		if ( str_starts_with( $path, 'users' ) ) {
			return $this->page( $this->users(), $url, 'users' );
		}

		return array( 'value' => array() );
	}

	/**
	 * Answer a POST /$batch payload.
	 *
	 * Responses are deliberately returned in REVERSE request order, because
	 * Graph makes no ordering promise and correlation must be by `id`. If the
	 * connector ever regresses to positional correlation, the mock sync breaks
	 * immediately instead of silently in production.
	 *
	 * @param array<int,array<string,mixed>> $entries Batch request entries.
	 * @return array<string,mixed> Batch response envelope.
	 */
	public function batch( array $entries ): array {
		$responses = array();

		foreach ( array_reverse( $entries ) as $entry ) {
			$url  = (string) ( $entry['url'] ?? '' );
			$body = $this->respond( $this->base_url . '/' . ltrim( $url, '/' ) );

			$responses[] = array(
				'id'      => (string) ( $entry['id'] ?? '' ),
				'status'  => 200,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => $body,
			);
		}

		return array( 'responses' => $responses );
	}

	/**
	 * The generated tenant, as an organization object.
	 *
	 * @return array<string,mixed>
	 */
	public function tenant(): array {
		return array(
			'id'              => 'b9c1f0e2-4d7a-4c31-9f6e-7a5d2c8b1a44',
			'displayName'     => 'Romy NZ Limited (mock tenant)',
			'tenantType'      => 'AAD',
			'countryLetterCode' => 'NZ',
			'verifiedDomains' => array(
				array(
					'name'      => 'romynz.com',
					'isDefault' => true,
					'type'      => 'Managed',
				),
			),
		);
	}

	/**
	 * How many users / devices the mock fleet contains.
	 *
	 * @return array{users:int,devices:int,userless:int}
	 */
	public function counts(): array {
		$userless = 0;
		foreach ( $this->devices() as $device ) {
			if ( '' === (string) $device['userId'] ) {
				++$userless;
			}
		}

		return array(
			'users'    => count( $this->users() ),
			'devices'  => count( $this->devices() ),
			'userless' => $userless,
		);
	}

	/* -----------------------------------------------------------------
	 * Fixtures reshaped into Graph objects
	 * --------------------------------------------------------------- */

	/**
	 * Graph /users objects built from the shared people fixture.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function users(): array {
		if ( null !== $this->users ) {
			return $this->users;
		}

		$people = \VulnHub\Core\Mock::people();

		// Managers are referenced by UPN in the fixture; Graph expands them as
		// objects, so we need a UPN => id lookup first.
		$by_upn = array();
		foreach ( $people as $person ) {
			$by_upn[ strtolower( (string) $person['userPrincipalName'] ) ] = $person;
		}

		$users = array();
		foreach ( $people as $person ) {
			$manager     = null;
			$manager_upn = strtolower( (string) ( $person['manager']['userPrincipalName'] ?? '' ) );
			if ( '' !== $manager_upn && isset( $by_upn[ $manager_upn ] ) ) {
				$manager = array(
					'@odata.type'       => '#microsoft.graph.user',
					'id'                => (string) $by_upn[ $manager_upn ]['id'],
					'displayName'       => (string) $by_upn[ $manager_upn ]['displayName'],
					'userPrincipalName' => $manager_upn,
				);
			}

			$users[] = array(
				'id'                => (string) $person['id'],
				'userPrincipalName' => (string) $person['userPrincipalName'],
				'displayName'       => (string) $person['displayName'],
				'givenName'         => (string) $person['givenName'],
				'surname'           => (string) $person['surname'],
				'mail'              => (string) $person['mail'],
				'jobTitle'          => (string) $person['jobTitle'],
				'department'        => (string) $person['department'],
				'officeLocation'    => (string) $person['officeLocation'],
				'city'              => (string) $person['city'],
				'state'             => (string) $person['state'],
				'country'           => (string) $person['country'],
				'companyName'       => (string) $person['companyName'],
				'employeeId'        => (string) $person['employeeId'],
				'usageLocation'     => (string) $person['usageLocation'],
				'accountEnabled'    => (bool) $person['accountEnabled'],
				'userType'          => 'Member',
				'manager'           => $manager,
			);
		}

		$this->users = $users;
		return $users;
	}

	/**
	 * Graph /deviceManagement/managedDevices objects.
	 *
	 * Only fixture records with a non-empty intune_id are Intune-managed;
	 * servers and network gear deliberately are not, and must not appear here.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function devices(): array {
		if ( null !== $this->devices ) {
			return $this->devices;
		}

		$people = array();
		foreach ( \VulnHub\Core\Mock::people() as $person ) {
			$people[ strtolower( (string) $person['userPrincipalName'] ) ] = $person;
		}

		$managed = array();
		foreach ( \VulnHub\Core\Mock::devices() as $device ) {
			if ( '' === (string) $device['intune_id'] ) {
				continue;
			}
			$managed[] = $device;
		}

		// Deliberately userless machines: a shared meeting-room laptop, a
		// front-desk kiosk and a spare loan phone. Real fleets always have a
		// handful, and they are exactly what the unresolved-workstation screen
		// is meant to surface.
		$total    = count( $managed );
		$userless = array();
		foreach ( array( 5, 17, max( 0, $total - 1 ) ) as $position ) {
			if ( $position < $total ) {
				$userless[ $position ] = true;
			}
		}

		$devices = array();
		foreach ( $managed as $index => $device ) {
			$owner_upn = strtolower( (string) $device['owner_upn'] );
			$person    = $people[ $owner_upn ] ?? null;
			$shared    = isset( $userless[ $index ] );

			$os = (string) $device['operating_system'];
			if ( 'iOS' === $os && str_contains( (string) $device['model'], 'iPad' ) ) {
				$os = 'iPadOS';
			}

			$devices[] = array(
				'id'                      => (string) $device['intune_id'],
				'userId'                  => $shared ? '' : (string) ( $person['id'] ?? '' ),
				'userPrincipalName'       => $shared ? '' : (string) ( $person['userPrincipalName'] ?? '' ),
				'userDisplayName'         => $shared ? '' : (string) ( $person['displayName'] ?? '' ),
				'deviceName'              => (string) $device['hostname'],
				'managedDeviceName'       => strtolower( (string) $device['hostname'] ) . '_' . strtolower( $os ),
				'managedDeviceOwnerType'  => 'company',
				'deviceCategoryDisplayName' => $shared ? 'Shared device' : ucfirst( (string) $device['asset_type'] ),
				'enrolledDateTime'        => $this->iso( (string) $device['first_seen'] ),
				'lastSyncDateTime'        => $this->iso( (string) $device['last_seen'] ),
				'operatingSystem'         => $os,
				'osVersion'               => (string) $device['os_version'],
				'complianceState'         => (string) $device['compliance_state'],
				'deviceEnrollmentType'    => $shared ? 'windowsBulkAzureDomainJoin' : (string) $device['enrollment_type'],
				'deviceRegistrationState' => 'registered',
				'managementAgent'         => 'mdm',
				'azureADRegistered'       => true,
				'azureADDeviceId'         => (string) $device['azure_ad_device_id'],
				'serialNumber'            => (string) $device['serial'],
				'model'                   => (string) $device['model'],
				'manufacturer'            => (string) $device['manufacturer'],
				'wiFiMacAddress'          => str_replace( ':', '', (string) $device['mac'] ),
				'ethernetMacAddress'      => '',
				'isEncrypted'             => true,
				'isSupervised'            => 'mobile' === (string) $device['asset_type'],
				'jailBroken'              => 'False',
			);
		}

		$this->devices = $devices;
		return $devices;
	}

	/**
	 * Deterministic group memberships, keyed by (lowercased) user id.
	 *
	 * @return array<string,array<int,array<string,mixed>>>
	 */
	private function memberships(): array {
		if ( null !== $this->memberships ) {
			return $this->memberships;
		}

		$map = array();
		foreach ( \VulnHub\Core\Mock::people() as $person ) {
			$department = (string) $person['department'];
			$office     = (string) $person['officeLocation'];

			$groups = array(
				array(
					'@odata.type' => '#microsoft.graph.group',
					'id'          => $this->guid( 'grp-all-staff' ),
					'displayName' => 'All Staff',
				),
				array(
					'@odata.type' => '#microsoft.graph.group',
					'id'          => $this->guid( 'grp-team-' . $department ),
					'displayName' => 'TEAM-' . $department,
				),
				array(
					'@odata.type' => '#microsoft.graph.group',
					'id'          => $this->guid( 'grp-site-' . $office ),
					'displayName' => 'SITE-' . $office,
				),
			);

			if ( ! empty( $person['isManager'] ) ) {
				$groups[] = array(
					'@odata.type' => '#microsoft.graph.group',
					'id'          => $this->guid( 'grp-managers' ),
					'displayName' => 'People Leaders',
				);
			}

			$map[ strtolower( (string) $person['id'] ) ] = $groups;
		}

		$this->memberships = $map;
		return $map;
	}

	/* -----------------------------------------------------------------
	 * Paging helpers
	 * --------------------------------------------------------------- */

	/**
	 * Slice a collection into a Graph page, with a realistic nextLink.
	 *
	 * @param array<int,array<string,mixed>> $rows    Full collection.
	 * @param string                         $url     URL being answered.
	 * @param string                         $context OData context fragment.
	 * @return array<string,mixed>
	 */
	private function page( array $rows, string $url, string $context ): array {
		$offset = $this->offset_from( $url );
		$slice  = array_slice( $rows, $offset, $this->page_size );

		$payload = array(
			'@odata.context' => $this->base_url . '/$metadata#' . $context,
			'value'          => array_values( $slice ),
		);

		$next = $offset + $this->page_size;
		if ( $next < count( $rows ) ) {
			$payload['@odata.nextLink'] = $this->next_link( $url, $next );
		}

		return $payload;
	}

	/**
	 * Read our own skiptoken back out of a URL.
	 *
	 * @param string $url URL.
	 * @return int Row offset.
	 */
	private function offset_from( string $url ): int {
		if ( ! preg_match( '/[?&]\$skiptoken=([^&]+)/', $url, $matches ) ) {
			return 0;
		}
		$raw = base64_decode( strtr( rawurldecode( $matches[1] ), '-_~', '+/=' ), true );
		if ( ! is_string( $raw ) || ! preg_match( '/^mockpage:(\d+)$/', $raw, $found ) ) {
			return 0;
		}
		return (int) $found[1];
	}

	/**
	 * Build the next page URL, preserving every other query argument exactly
	 * the way Graph does.
	 *
	 * @param string $url    Current URL.
	 * @param int    $offset Next row offset.
	 * @return string
	 */
	private function next_link( string $url, int $offset ): string {
		$clean = (string) preg_replace( '/([?&])\$skiptoken=[^&]*(&|$)/', '$1', $url );
		$clean = rtrim( $clean, '?&' );
		$token = strtr( base64_encode( 'mockpage:' . $offset ), '+/=', '-_~' );

		return $clean . ( str_contains( $clean, '?' ) ? '&' : '?' ) . '$skiptoken=' . $token;
	}

	/**
	 * Strip the API version segment from a path.
	 *
	 * @param string $path URL path.
	 * @return string
	 */
	private function strip_version( string $path ): string {
		$path = ltrim( $path, '/' );
		foreach ( array( 'v1.0/', 'beta/' ) as $version ) {
			if ( str_starts_with( $path, $version ) ) {
				return substr( $path, strlen( $version ) );
			}
		}
		return $path;
	}

	/**
	 * Deterministic GUID from a seed string.
	 *
	 * @param string $seed Seed.
	 * @return string
	 */
	private function guid( string $seed ): string {
		$hash = md5( $seed );
		return sprintf(
			'%s-%s-4%s-b%s-%s',
			substr( $hash, 0, 8 ),
			substr( $hash, 8, 4 ),
			substr( $hash, 13, 3 ),
			substr( $hash, 17, 3 ),
			substr( $hash, 20, 12 )
		);
	}

	/**
	 * MySQL datetime to ISO 8601 UTC, the way Graph renders timestamps.
	 *
	 * @param string $mysql MySQL datetime.
	 * @return string
	 */
	private function iso( string $mysql ): string {
		$timestamp = strtotime( $mysql . ' UTC' );
		return false === $timestamp ? '' : gmdate( 'Y-m-d\TH:i:s\Z', $timestamp );
	}
}

