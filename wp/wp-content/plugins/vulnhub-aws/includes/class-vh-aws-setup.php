<?php
/**
 * Turning "connect an AWS account" into something a person can finish.
 *
 * The hard part of a cloud connector is never the API -- it is the twenty
 * minutes somebody spends in the IAM console building a policy by hand,
 * getting one action wrong, and reading an AccessDenied that names none of
 * them. So the policy ships as a CloudFormation template: they create a stack,
 * copy two outputs back, and press Test.
 *
 * The template is served from this app rather than linked from S3 on purpose.
 * CloudFormation's one-click quick-create URL needs a template its own backend
 * can fetch, which means a public bucket -- and this install sits behind a
 * tunnel with no public address. Pretending otherwise would produce a button
 * that fails for exactly the people most careful about exposure. Download,
 * upload, done: two more clicks, and it works on a private install.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Guided setup: the template, and the links around it.
 */
final class VulnHub_AWS_Setup {

	/** Stack name we suggest, so support conversations have a shared noun. */
	public const STACK = 'VulnHubReadOnlyAccess';

	/**
	 * The least privilege that answers "can the internet reach this, and on
	 * what port".
	 *
	 * Every action is a read. There is no describe-one variant of most of
	 * these, so the resource is `*`: an ec2:DescribeInstances that could only
	 * read some instances would report an estate with holes in it, which is
	 * worse than not asking.
	 *
	 * @return string[]
	 */
	public static function actions(): array {
		return array(
			// Who am I -- allowed for every principal, used to fail fast.
			'sts:GetCallerIdentity',

			// The reachability chain. All five links, or the answer is a guess.
			'ec2:DescribeInstances',
			'ec2:DescribeNetworkInterfaces',
			'ec2:DescribeSecurityGroups',
			'ec2:DescribeSubnets',
			'ec2:DescribeVpcs',
			'ec2:DescribeRouteTables',
			'ec2:DescribeNetworkAcls',
			'ec2:DescribeInternetGateways',
			'ec2:DescribeAddresses',
			'ec2:DescribeRegions',

			// An instance with no public IP is still reachable behind an
			// internet-facing load balancer, and that path is invisible
			// without these.
			'elasticloadbalancing:DescribeLoadBalancers',
			'elasticloadbalancing:DescribeListeners',
			'elasticloadbalancing:DescribeTargetGroups',
			'elasticloadbalancing:DescribeTargetHealth',

			// Optional: if Inspector is on it has already done this work.
			'inspector2:BatchGetAccountStatus',
			'inspector2:ListFindings',
		);
	}

	/**
	 * The CloudFormation template, as YAML.
	 *
	 * Creates an IAM user holding only the reads above, plus an access key,
	 * and returns both halves as stack outputs.
	 *
	 * A user rather than a role because this app runs on-premises in Docker.
	 * There is no instance profile and no AWS principal of our own to write
	 * into a trust policy, so there is nothing for a cross-account role to
	 * trust -- the pattern Tenable and Wiz use is not available to a
	 * self-hosted install, and offering it would be theatre.
	 *
	 * The secret appears in the stack outputs, which is how every
	 * CloudFormation-issued credential works. It is called out in the template
	 * description so nobody learns it by surprise, and deleting the stack
	 * revokes the key.
	 */
	public static function template(): string {
		$actions = '';

		foreach ( self::actions() as $action ) {
			$actions .= "                  - {$action}\n";
		}

		return <<<YAML
AWSTemplateFormatVersion: '2010-09-09'

Description: >-
  Read-only access for VulnHub, to work out which instances the internet can
  reach and on which ports. Every permission granted is a Describe or a Get;
  nothing here can change, start, stop or delete anything.

  NOTE: the access key secret is returned as a stack output, which is how any
  CloudFormation-issued credential works. Treat the Outputs tab as sensitive,
  and delete this stack to revoke the key.

Resources:

  VulnHubReadOnlyUser:
    Type: AWS::IAM::User
    Properties:
      UserName: vulnhub-readonly
      Policies:
        - PolicyName: VulnHubNetworkExposureRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
{$actions}                Resource: '*'

  VulnHubReadOnlyKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref VulnHubReadOnlyUser

Outputs:

  AccountId:
    Description: Paste into the AWS account ID field in VulnHub.
    Value: !Ref AWS::AccountId

  AccessKeyId:
    Description: Paste into the Access key ID field in VulnHub.
    Value: !Ref VulnHubReadOnlyKey

  SecretAccessKey:
    Description: Paste into the Secret access key field in VulnHub. Shown once.
    Value: !GetAtt VulnHubReadOnlyKey.SecretAccessKey
YAML;
	}

	/**
	 * Where the browser downloads the template from.
	 *
	 * The REST nonce is not optional here. A cookie alone does not
	 * authenticate a REST request -- WordPress refuses to resolve the current
	 * user without `_wpnonce`, so `current_user_can()` is false and the route
	 * answers 401. A plain link would have looked perfectly correct in the
	 * markup and handed every user a permission error on click.
	 */
	public static function template_url(): string {
		return add_query_arg(
			'_wpnonce',
			wp_create_nonce( 'wp_rest' ),
			rest_url( 'vulnhub-aws/v1/cloudformation-template' )
		);
	}

	/**
	 * The CloudFormation console, on the create-stack step, in one region.
	 *
	 * Deep-linked to the upload step rather than the stack list, because the
	 * difference between the two is about six clicks and a wrong turn into
	 * StackSets.
	 */
	public static function console_url( string $region ): string {
		$region = '' !== $region ? $region : 'us-east-1';

		return sprintf(
			'https://%1$s.console.aws.amazon.com/cloudformation/home?region=%1$s#/stacks/create/template',
			rawurlencode( $region )
		);
	}

	/** Where to find the outputs once the stack exists. */
	public static function outputs_url( string $region ): string {
		$region = '' !== $region ? $region : 'us-east-1';

		return sprintf(
			'https://%1$s.console.aws.amazon.com/cloudformation/home?region=%1$s#/stacks',
			rawurlencode( $region )
		);
	}

	/**
	 * The regions worth offering, taken from the estate rather than from a
	 * list of every region AWS has.
	 *
	 * @return string[]
	 */
	public static function suggested_regions(): array {
		global $wpdb;

		$rows = (array) $wpdb->get_col( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'SELECT DISTINCT cloud_region FROM ' . vh_table( 'assets' ) // phpcs:ignore
			. " WHERE cloud_provider = 'aws' AND cloud_region <> '' ORDER BY cloud_region"
		);

		return array_values( array_filter( array_map( 'strval', $rows ) ) );
	}

	/**
	 * The setup steps, rendered into the first field's help text.
	 *
	 * It lives here rather than in the connector so the wording and the
	 * template cannot drift apart.
	 */
	public static function instructions( string $region ): string {
		$steps = sprintf(
			'<ol class="vh-aws-steps">
				<li>%1$s <a href="%2$s" download="vulnhub-aws-readonly.yaml"><strong>%3$s</strong></a></li>
				<li>%4$s <a href="%5$s" target="_blank" rel="noopener noreferrer"><strong>%6$s</strong></a> %7$s</li>
				<li>%8$s</li>
			</ol>',
			esc_html__( 'Download the read-only CloudFormation template:', 'vulnhub' ),
			esc_url( self::template_url() ),
			esc_html__( 'vulnhub-aws-readonly.yaml', 'vulnhub' ),
			esc_html__( 'Open', 'vulnhub' ),
			esc_url( self::console_url( $region ) ),
			esc_html__( 'CloudFormation → Create stack', 'vulnhub' ),
			esc_html__( 'in your AWS account, upload the file, and name the stack anything you like.', 'vulnhub' ),
			esc_html__( 'When it finishes, open the stack’s Outputs tab and copy the three values into the fields below. Then press Test connection.', 'vulnhub' )
		);

		return $steps
			. '<p>' . esc_html__( 'The template grants only Describe and Get permissions — it cannot change, start, stop or delete anything. Deleting the stack revokes the key.', 'vulnhub' ) . '</p>';
	}
}
