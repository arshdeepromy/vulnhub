<?php
/**
 * A minimal, pure-PHP S3 client: SigV4 signing plus exactly the operations a
 * backup job needs.
 *
 * No AWS SDK dependency — that is hundreds of files and a Composer
 * dependency for what amounts to seven REST calls. Every request goes
 * through VulnHub\Core\Http, which passes a raw string body and custom
 * headers through to wp_remote_request() untouched (its only opinion is an
 * `Accept: application/json` header and a best-effort json_decode on the
 * response, both harmless against S3's XML).
 *
 * Reference: docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html,
 * .../mpuoverview.html (multipart), .../API_PutBucketLifecycleConfiguration.html.
 *
 * @package VulnHub\Backup
 */

declare( strict_types = 1 );

use VulnHub\Core\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Signed S3 REST calls.
 */
final class VulnHub_Backup_S3 {

	/**
	 * AWS's own best-practice cutoff: use multipart upload at or above this
	 * size rather than a single PutObject.
	 */
	public const MULTIPART_THRESHOLD = 104857600; // 100 MB.

	/**
	 * Part size for a multipart upload. Comfortably above the 5 MB minimum
	 * AWS enforces on every part but the last, and safe under the container's
	 * 512 MB memory_limit (one part, plus request overhead, held in memory
	 * at a time).
	 */
	public const PART_SIZE = 33554432; // 32 MB.

	private string $access_key;
	private string $secret_key;
	private string $region;
	private string $bucket;
	private Http $http;

	public function __construct( string $access_key, string $secret_key, string $region, string $bucket ) {
		$this->access_key = $access_key;
		$this->secret_key = $secret_key;
		$this->region     = '' !== $region ? $region : 'us-east-1';
		$this->bucket     = $bucket;
		$this->http       = new Http( 'VulnHub-Backup/1.0' );
	}

	public function configured(): bool {
		return '' !== $this->access_key && '' !== $this->secret_key && '' !== $this->bucket;
	}

	private function host(): string {
		return $this->bucket . '.s3.' . $this->region . '.amazonaws.com';
	}

	private function endpoint( string $key = '', array $query = array() ): string {
		$url = 'https://' . $this->host() . '/' . self::uri_encode_path( $key );

		if ( $query ) {
			$url .= '?' . self::canonical_query_string( $query, false );
		}

		return $url;
	}

	/* =================================================================
	 * SigV4
	 * ============================================================== */

	/**
	 * URI-encode one path segment per RFC 3986 the way SigV4 requires:
	 * unreserved characters left alone, everything else percent-encoded,
	 * '/' preserved as a segment separator.
	 *
	 * @param string $path Raw object key (may contain '/').
	 * @return string
	 */
	private static function uri_encode_path( string $path ): string {
		$segments = explode( '/', $path );

		return implode( '/', array_map( static fn( string $s ): string => self::uri_encode( $s ), $segments ) );
	}

	/**
	 * The canonical URI for a SigV4 canonical request: the URI-encoded
	 * object key, prefixed with '/', or exactly '/' for bucket-level
	 * operations (empty key). Must match the path S3 sees in the actual
	 * request line (see endpoint()) or every signature fails.
	 *
	 * @param string $key Object key ('' for bucket-level operations).
	 * @return string
	 */
	private static function canonical_uri( string $key ): string {
		return '' !== $key ? '/' . self::uri_encode_path( $key ) : '/';
	}

	/**
	 * URI-encode a single value per SigV4's rules (RFC 3986 unreserved set
	 * plus '-', '_', '.', '~'; everything else, including '/', percent-encoded).
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private static function uri_encode( string $value ): string {
		$encoded = rawurlencode( $value );
		// rawurlencode already matches RFC 3986 for everything relevant here.
		return $encoded;
	}

	/**
	 * Build a canonical query string: keys sorted, each key and value
	 * SigV4-encoded, joined with '&'.
	 *
	 * @param array<string,string> $query        Query parameters.
	 * @param bool                 $for_signing  Sorted+encoded either way; kept
	 *                                            as a separate parameter name
	 *                                            for readability at call sites.
	 * @return string
	 */
	private static function canonical_query_string( array $query, bool $for_signing = true ): string {
		unset( $for_signing );

		ksort( $query );

		$parts = array();

		foreach ( $query as $k => $v ) {
			$parts[] = self::uri_encode( (string) $k ) . '=' . self::uri_encode( (string) $v );
		}

		return implode( '&', $parts );
	}

	/**
	 * Sign a request and return the full header set to send, including
	 * Authorization, x-amz-date, x-amz-content-sha256 and Host.
	 *
	 * @param string                $method       HTTP method.
	 * @param string                $key          Object key ('' for
	 *                                            bucket-level operations).
	 * @param array<string,string>  $query        Query string parameters.
	 * @param array<string,string>  $extra_headers Additional headers to sign
	 *                                             (e.g. Content-Type).
	 * @param string                $payload      Raw request body, for the
	 *                                            payload hash.
	 * @return array<string,string> Headers to send with the request.
	 */
	private function sign( string $method, string $key, array $query, array $extra_headers, string $payload ): array {
		$now        = new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) );
		$amz_date   = $now->format( 'Ymd\THis\Z' );
		$short_date = $now->format( 'Ymd' );
		$host       = $this->host();
		$payload_hash = hash( 'sha256', $payload );

		$headers = array_merge(
			array(
				'host'                 => $host,
				'x-amz-date'           => $amz_date,
				'x-amz-content-sha256' => $payload_hash,
			),
			array_change_key_case( $extra_headers, CASE_LOWER )
		);

		ksort( $headers );

		$signed_headers   = implode( ';', array_keys( $headers ) );
		$canonical_headers = '';

		foreach ( $headers as $k => $v ) {
			$canonical_headers .= $k . ':' . trim( (string) $v ) . "\n";
		}

		$canonical_request = implode(
			"\n",
			array(
				strtoupper( $method ),
				self::canonical_uri( $key ),
				self::canonical_query_string( $query ),
				$canonical_headers,
				$signed_headers,
				$payload_hash,
			)
		);

		$credential_scope = $short_date . '/' . $this->region . '/s3/aws4_request';

		$string_to_sign = implode(
			"\n",
			array(
				'AWS4-HMAC-SHA256',
				$amz_date,
				$credential_scope,
				hash( 'sha256', $canonical_request ),
			)
		);

		$k_date     = hash_hmac( 'sha256', $short_date, 'AWS4' . $this->secret_key, true );
		$k_region   = hash_hmac( 'sha256', $this->region, $k_date, true );
		$k_service  = hash_hmac( 'sha256', 's3', $k_region, true );
		$k_signing  = hash_hmac( 'sha256', 'aws4_request', $k_service, true );
		$signature  = hash_hmac( 'sha256', $string_to_sign, $k_signing );

		$authorization = sprintf(
			'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
			$this->access_key,
			$credential_scope,
			$signed_headers,
			$signature
		);

		$out = $extra_headers;

		$out['Host']                 = $host;
		$out['X-Amz-Date']           = $amz_date;
		$out['X-Amz-Content-Sha256'] = $payload_hash;
		$out['Authorization']        = $authorization;

		return $out;
	}

	/**
	 * Issue one signed request.
	 *
	 * @param string                $method  HTTP method.
	 * @param string                $key     Object key ('' for bucket-level).
	 * @param array<string,string>  $query   Query string parameters.
	 * @param array<string,string>  $headers Extra headers (Content-Type etc).
	 * @param string                $body    Raw request body.
	 * @return array{ok:bool,status:int,body:string,headers:array<string,mixed>,error:string}
	 */
	private function call( string $method, string $key, array $query, array $headers, string $body ): array {
		$signed = $this->sign( $method, $key, $query, $headers, $body );
		$url    = $this->endpoint( $key, $query );

		$response = $this->http->request(
			$method,
			$url,
			array(
				'headers' => $signed,
				'body'    => $body,
				'json'    => false,
				'timeout' => 120,
			)
		);

		$status = $response->status;
		$raw    = $response->body;

		if ( 0 === $status ) {
			return array(
				'ok'      => false,
				'status'  => 0,
				'body'    => '',
				'headers' => array(),
				'error'   => $response->error_message(),
			);
		}

		// Normalised to lowercase keys so callers (e.g. reading 'etag' after
		// an UploadPart) never have to guess the casing the transport used.
		$headers = array_change_key_case( (array) $response->headers, CASE_LOWER );

		if ( $status >= 200 && $status < 300 ) {
			return array(
				'ok'      => true,
				'status'  => $status,
				'body'    => $raw,
				'headers' => $headers,
				'error'   => '',
			);
		}

		return array(
			'ok'      => false,
			'status'  => $status,
			'body'    => $raw,
			'headers' => $headers,
			'error'   => self::xml_error( $raw ),
		);
	}

	/**
	 * Pull a human-readable message out of an S3 XML error body.
	 *
	 * @param string $xml Raw XML body.
	 * @return string
	 */
	private static function xml_error( string $xml ): string {
		if ( '' === trim( $xml ) ) {
			return '';
		}

		$prev = libxml_use_internal_errors( true );
		$doc  = simplexml_load_string( $xml );
		libxml_use_internal_errors( $prev );

		if ( false === $doc ) {
			return substr( $xml, 0, 300 );
		}

		$code    = (string) ( $doc->Code ?? '' );
		$message = (string) ( $doc->Message ?? '' );

		return trim( $code . ': ' . $message, ': ' );
	}

	/* =================================================================
	 * Object operations
	 * ============================================================== */

	/**
	 * PutObject — for anything under MULTIPART_THRESHOLD.
	 *
	 * @param string $key          Object key.
	 * @param string $body         Raw object bytes.
	 * @param string $content_type MIME type.
	 * @return array{ok:bool,error:string}
	 */
	public function put_object( string $key, string $body, string $content_type = 'application/octet-stream' ): array {
		$result = $this->call( 'PUT', $key, array(), array( 'Content-Type' => $content_type ), $body );

		return array( 'ok' => $result['ok'], 'error' => $result['error'] );
	}

	/**
	 * CreateMultipartUpload.
	 *
	 * @param string $key          Object key.
	 * @param string $content_type MIME type.
	 * @return array{ok:bool,uploadId:string,error:string}
	 */
	public function create_multipart_upload( string $key, string $content_type = 'application/octet-stream' ): array {
		$result = $this->call( 'POST', $key, array( 'uploads' => '' ), array( 'Content-Type' => $content_type ), '' );

		if ( ! $result['ok'] ) {
			return array( 'ok' => false, 'uploadId' => '', 'error' => $result['error'] );
		}

		$prev = libxml_use_internal_errors( true );
		$doc  = simplexml_load_string( $result['body'] );
		libxml_use_internal_errors( $prev );

		$upload_id = $doc ? (string) $doc->UploadId : '';

		return array(
			'ok'       => '' !== $upload_id,
			'uploadId' => $upload_id,
			'error'    => '' === $upload_id ? __( 'S3 did not return an upload id.', 'vulnhub' ) : '',
		);
	}

	/**
	 * UploadPart. The ETag S3 returns for this part must be recorded (in the
	 * job's counters) and later fed back in the same order to
	 * complete_multipart_upload() — it is not merely a checksum here, it is
	 * the identifier S3 uses to assemble the final object.
	 *
	 * @param string $key         Object key.
	 * @param string $upload_id   Multipart upload id.
	 * @param int    $part_number 1-10000.
	 * @param string $body        This part's raw bytes.
	 * @return array{ok:bool,etag:string,error:string}
	 */
	public function upload_part( string $key, string $upload_id, int $part_number, string $body ): array {
		$result = $this->call(
			'PUT',
			$key,
			array(
				'partNumber' => (string) $part_number,
				'uploadId'   => $upload_id,
			),
			array(),
			$body
		);

		if ( ! $result['ok'] ) {
			return array( 'ok' => false, 'etag' => '', 'error' => $result['error'] );
		}

		$etag = trim( (string) ( $result['headers']['etag'] ?? '' ), '"' );

		if ( '' === $etag ) {
			return array( 'ok' => false, 'etag' => '', 'error' => __( 'S3 did not return an ETag for that part.', 'vulnhub' ) );
		}

		return array( 'ok' => true, 'etag' => $etag, 'error' => '' );
	}

	/**
	 * CompleteMultipartUpload.
	 *
	 * @param string                              $key       Object key.
	 * @param string                              $upload_id Multipart upload id.
	 * @param array<int,array{partNumber:int,etag:string}> $parts Ordered parts.
	 * @return array{ok:bool,error:string}
	 */
	public function complete_multipart_upload( string $key, string $upload_id, array $parts ): array {
		$xml = '<CompleteMultipartUpload>';

		foreach ( $parts as $part ) {
			$xml .= '<Part><PartNumber>' . (int) $part['partNumber'] . '</PartNumber><ETag>"' . esc_html( (string) $part['etag'] ) . '"</ETag></Part>';
		}

		$xml .= '</CompleteMultipartUpload>';

		$result = $this->call(
			'POST',
			$key,
			array( 'uploadId' => $upload_id ),
			array( 'Content-Type' => 'application/xml' ),
			$xml
		);

		return array( 'ok' => $result['ok'], 'error' => $result['error'] );
	}

	/**
	 * AbortMultipartUpload — called when a job fails or is cancelled mid-upload
	 * so S3 stops billing for the orphaned parts immediately rather than
	 * waiting on the lifecycle rule.
	 *
	 * @param string $key       Object key.
	 * @param string $upload_id Multipart upload id.
	 * @return array{ok:bool,error:string}
	 */
	public function abort_multipart_upload( string $key, string $upload_id ): array {
		$result = $this->call( 'DELETE', $key, array( 'uploadId' => $upload_id ), array(), '' );

		return array( 'ok' => $result['ok'], 'error' => $result['error'] );
	}

	/**
	 * ListObjectsV2, one page.
	 *
	 * @param string $prefix Key prefix.
	 * @param string $token  Continuation token from a previous page.
	 * @return array{ok:bool,keys:array<int,array{key:string,lastModified:string}>,nextToken:string,error:string}
	 */
	public function list_objects_v2( string $prefix, string $token = '' ): array {
		$query = array(
			'list-type' => '2',
			'prefix'    => $prefix,
			'max-keys'  => '1000',
		);

		if ( '' !== $token ) {
			$query['continuation-token'] = $token;
		}

		$result = $this->call( 'GET', '', $query, array(), '' );

		if ( ! $result['ok'] ) {
			return array( 'ok' => false, 'keys' => array(), 'nextToken' => '', 'error' => $result['error'] );
		}

		$prev = libxml_use_internal_errors( true );
		$doc  = simplexml_load_string( $result['body'] );
		libxml_use_internal_errors( $prev );

		if ( false === $doc ) {
			return array( 'ok' => false, 'keys' => array(), 'nextToken' => '', 'error' => __( 'Could not parse the S3 listing response.', 'vulnhub' ) );
		}

		$keys = array();

		foreach ( $doc->Contents ?? array() as $entry ) {
			$keys[] = array(
				'key'          => (string) $entry->Key,
				'lastModified' => (string) $entry->LastModified,
			);
		}

		$truncated  = 'true' === (string) ( $doc->IsTruncated ?? 'false' );
		$next_token = $truncated ? (string) ( $doc->NextContinuationToken ?? '' ) : '';

		return array( 'ok' => true, 'keys' => $keys, 'nextToken' => $next_token, 'error' => '' );
	}

	/**
	 * Every object under a prefix, across as many pages as it takes.
	 *
	 * @param string $prefix Key prefix.
	 * @return array<int,array{key:string,lastModified:string}>
	 */
	public function list_all( string $prefix ): array {
		$keys  = array();
		$token = '';

		do {
			$page = $this->list_objects_v2( $prefix, $token );

			if ( ! $page['ok'] ) {
				break;
			}

			$keys  = array_merge( $keys, $page['keys'] );
			$token = $page['nextToken'];
		} while ( '' !== $token );

		return $keys;
	}

	/**
	 * DeleteObjects — batches of up to 1000 keys per the API's own limit.
	 *
	 * @param array<int,string> $keys Object keys to delete.
	 * @return array{ok:bool,deleted:int,error:string}
	 */
	public function delete_objects( array $keys ): array {
		if ( ! $keys ) {
			return array( 'ok' => true, 'deleted' => 0, 'error' => '' );
		}

		$deleted = 0;
		$error   = '';

		foreach ( array_chunk( $keys, 1000 ) as $batch ) {
			$xml = '<Delete><Quiet>true</Quiet>';

			foreach ( $batch as $key ) {
				$xml .= '<Object><Key>' . esc_html( $key ) . '</Key></Object>';
			}

			$xml .= '</Delete>';

			$body_hash = base64_encode( hash( 'md5', $xml, true ) );

			$result = $this->call(
				'POST',
				'',
				array( 'delete' => '' ),
				array(
					'Content-Type' => 'application/xml',
					'Content-MD5'  => $body_hash,
				),
				$xml
			);

			if ( ! $result['ok'] ) {
				$error = $result['error'];
				continue;
			}

			$deleted += count( $batch );
		}

		return array( 'ok' => '' === $error, 'deleted' => $deleted, 'error' => $error );
	}

	/* =================================================================
	 * Lifecycle hygiene: abort orphaned multipart uploads automatically.
	 * Per AWS's own guidance: "we recommend that you configure a lifecycle
	 * rule to delete incomplete multipart uploads... to minimize storage
	 * costs." GET-merge-PUT, never a blind overwrite, since PUT replaces
	 * the bucket's entire lifecycle configuration.
	 * ============================================================== */

	private const LIFECYCLE_RULE_ID = 'vulnhub-backup-abort-incomplete-mpu';

	/**
	 * Ensure an AbortIncompleteMultipartUpload rule exists for our prefix.
	 * Safe to call repeatedly; a no-op once the rule is present.
	 *
	 * @param string $prefix Key prefix this plugin writes under.
	 * @param int    $days   Days after initiation to abort an incomplete upload.
	 * @return array{ok:bool,error:string}
	 */
	public function ensure_lifecycle_rule( string $prefix, int $days = 3 ): array {
		$get = $this->call( 'GET', '', array( 'lifecycle' => '' ), array(), '' );

		$rules = array();

		if ( $get['ok'] ) {
			$prev = libxml_use_internal_errors( true );
			$doc  = simplexml_load_string( $get['body'] );
			libxml_use_internal_errors( $prev );

			if ( false !== $doc ) {
				foreach ( $doc->Rule ?? array() as $rule ) {
					$id = (string) ( $rule->ID ?? '' );

					if ( self::LIFECYCLE_RULE_ID === $id ) {
						// Already present; nothing to merge or send.
						return array( 'ok' => true, 'error' => '' );
					}

					$rules[] = $rule->asXML();
				}
			}
		} elseif ( 404 !== $get['status'] && 0 !== $get['status'] ) {
			// A real error other than "no lifecycle configuration yet".
			return array( 'ok' => false, 'error' => $get['error'] );
		}

		$xml = '<LifecycleConfiguration>';

		foreach ( $rules as $rule_xml ) {
			$xml .= (string) $rule_xml;
		}

		$xml .= '<Rule>'
			. '<ID>' . self::LIFECYCLE_RULE_ID . '</ID>'
			. '<Filter><Prefix>' . esc_html( $prefix ) . '</Prefix></Filter>'
			. '<Status>Enabled</Status>'
			. '<AbortIncompleteMultipartUpload><DaysAfterInitiation>' . max( 1, $days ) . '</DaysAfterInitiation></AbortIncompleteMultipartUpload>'
			. '</Rule>'
			. '</LifecycleConfiguration>';

		$body_hash = base64_encode( hash( 'md5', $xml, true ) );

		$put = $this->call(
			'PUT',
			'',
			array( 'lifecycle' => '' ),
			array(
				'Content-Type' => 'application/xml',
				'Content-MD5'  => $body_hash,
			),
			$xml
		);

		return array( 'ok' => $put['ok'], 'error' => $put['error'] );
	}
}

