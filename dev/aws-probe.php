<?php
/**
 * Ask one question: is Amazon Inspector already computing network
 * reachability for this account, and does it cover the assets we hold?
 *
 *     docker compose cp dev/aws-probe.php wpcli:/tmp/probe.php
 *     docker compose exec -T \
 *       -e AWS_ACCESS_KEY_ID=... \
 *       -e AWS_SECRET_ACCESS_KEY=... \
 *       -e AWS_REGIONS=ap-southeast-2,us-east-1 \
 *       wpcli wp eval-file /tmp/probe.php
 *
 * Read-only throughout. It calls sts:GetCallerIdentity,
 * inspector2:BatchGetAccountStatus and inspector2:ListFindings, and writes
 * nothing -- to the AWS account or to our database.
 *
 * The point is to settle the build decision before building. If Inspector is
 * on, it has already worked out what the internet can reach, and reading its
 * answer is far less code than deriving reachability from security groups,
 * route tables, NACLs and gateways ourselves. If it is off, that second path
 * is the one to take, and knowing so now saves writing the wrong one.
 *
 * Credentials come from the environment rather than a stored setting: nothing
 * is configured yet, and a probe should not be the thing that creates the
 * first piece of persistent state.
 *
 * @package VulnHub
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "Run this through wp-cli - see the header for the docker compose cp/exec pair.\n" );
}

$key    = (string) getenv( 'AWS_ACCESS_KEY_ID' );
$secret = (string) getenv( 'AWS_SECRET_ACCESS_KEY' );
$token  = (string) getenv( 'AWS_SESSION_TOKEN' );

if ( '' === $key || '' === $secret ) {
	exit(
		"AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set.\n\n"
		. "The IAM user needs only read access. The AWS managed policy\n"
		. "SecurityAudit covers everything this probe calls, or inline:\n\n"
		. "  sts:GetCallerIdentity\n"
		. "  inspector2:BatchGetAccountStatus\n"
		. "  inspector2:ListFindings\n\n"
	);
}

$regions = array_filter( array_map( 'trim', explode( ',', (string) getenv( 'AWS_REGIONS' ) ) ) );

if ( ! $regions ) {
	// Where our own AWS assets say they live, rather than a guess.
	global $wpdb;

	$regions = array_filter(
		array_map(
			'strval',
			(array) $wpdb->get_col(
				'SELECT DISTINCT cloud_region FROM ' . vh_table( 'assets' ) . " WHERE cloud_provider = 'aws' AND cloud_region <> ''" // phpcs:ignore
			)
		)
	);

	printf( "No AWS_REGIONS given; using the regions our assets report: %s\n\n", implode( ', ', $regions ) ?: '(none)' );
}

if ( ! $regions ) {
	exit( "No regions to check. Set AWS_REGIONS.\n" );
}

$client = new VulnHub_AWS_Client( $key, $secret, $token );

/* ------------------------------------------------------ who are we, first. */

echo "=== credentials ===\n";

$who = $client->caller_identity();

if ( ! $who['ok'] ) {
	printf( "  FAILED: %s\n\n", $who['error'] );
	exit( "Stopping: without a working identity nothing below can be trusted.\n" );
}

printf( "  account : %s\n", $who['account'] );
printf( "  identity: %s\n\n", $who['arn'] );

/* ------------------------------------------- is Inspector on, and for what. */

$inspector = new VulnHub_AWS_Inspector( $client );
$enabled   = array();

echo "=== Amazon Inspector status ===\n";

foreach ( $regions as $region ) {
	$st = $inspector->status( $region );

	if ( ! $st['ok'] ) {
		printf( "  %-16s ERROR  %s\n", $region, $st['error'] );
		continue;
	}

	if ( ! $st['accounts'] ) {
		printf( "  %-16s no account status returned\n", $region );
		continue;
	}

	foreach ( $st['accounts'] as $acct ) {
		printf(
			"  %-16s overall=%-10s ec2=%-10s ecr=%-10s lambda=%s\n",
			$region,
			$acct['overall'],
			$acct['ec2'],
			$acct['ecr'],
			$acct['lambda']
		);

		if ( 'ENABLED' === $acct['ec2'] ) {
			$enabled[] = $region;
		}
	}
}

echo "\n";

if ( ! $enabled ) {
	echo "=== verdict ===\n";
	echo "  Inspector EC2 scanning is not enabled in any region checked.\n";
	echo "  There is no reachability data to read, so the connector should\n";
	echo "  derive exposure itself from EC2 + ELB describe calls (tier 1).\n";
	exit( 0 );
}

/* ---------------------------------------- what does its reachability say. */

echo "=== NETWORK_REACHABILITY findings ===\n";

$shaped = array();

foreach ( array_unique( $enabled ) as $region ) {
	$res = $inspector->reachability( $region, 500 );

	if ( ! $res['ok'] && ! $res['findings'] ) {
		printf( "  %-16s ERROR  %s\n", $region, $res['error'] );
		continue;
	}

	printf( "  %-16s %d finding(s)\n", $region, count( $res['findings'] ) );

	foreach ( $res['findings'] as $f ) {
		$shaped[] = VulnHub_AWS_Inspector::shape( $f );
	}
}

if ( ! $shaped ) {
	echo "\n=== verdict ===\n";
	echo "  Inspector is enabled but returned no reachability findings. That\n";
	echo "  means either nothing is reachable, or EC2 scanning has not yet\n";
	echo "  completed a cycle. Re-run in a few hours before concluding; if it\n";
	echo "  stays empty, build tier 1.\n";
	exit( 0 );
}

echo "\n  sample:\n";

foreach ( array_slice( $shaped, 0, 8 ) as $s ) {
	printf(
		"    %-21s %s %d-%d  %-8s %s\n",
		$s['instance_id'],
		$s['protocol'],
		$s['port_from'],
		$s['port_to'],
		$s['severity'],
		substr( $s['path'], 0, 50 )
	);
}

/* --------------------------------- does it cover the assets we already hold. */

global $wpdb;

$ours = array_map(
	'strval',
	(array) $wpdb->get_col(
		'SELECT aws_instance_id FROM ' . vh_table( 'assets' ) . " WHERE aws_instance_id <> ''" // phpcs:ignore
	)
);

$ours_set = array_flip( $ours );
$theirs   = array_unique( array_filter( array_column( $shaped, 'instance_id' ) ) );

$matched = 0;

foreach ( $theirs as $id ) {
	if ( isset( $ours_set[ $id ] ) ) {
		++$matched;
	}
}

echo "\n=== coverage against our inventory ===\n";
printf( "  assets we hold with an instance id : %d\n", count( $ours ) );
printf( "  instances Inspector reports on     : %d\n", count( $theirs ) );
printf( "  matched to one of ours             : %d\n", $matched );
printf( "  Inspector knows, we do not         : %d\n", count( $theirs ) - $matched );

echo "\n=== verdict ===\n";

if ( $matched > 0 ) {
	printf(
		"  Inspector is already computing reachability and %d of its instances\n"
		. "  match assets we hold. Tier 2 is the cheaper build: pull these\n"
		. "  findings on the connector schedule and feed the port ranges\n"
		. "  straight into the exposure rule.\n",
		$matched
	);
} else {
	echo "  Inspector has reachability data but none of it matches an asset we\n";
	echo "  hold by instance id. Check whether it is scanning a different\n";
	echo "  account before choosing a tier.\n";
}
