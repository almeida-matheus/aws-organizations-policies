var __index = {"config":{"lang":["en"],"separator":"[\\s\\-]+","pipeline":["stopWordFilter"]},"docs":[{"location":"index.html","title":"AWS Organizations Policies","text":""},{"location":"index.html#scp-service-control-policies","title":"SCP - Service Control Policies","text":""},{"location":"index.html#about","title":"About","text":"<p>Service Control Policies (SCPs) are authorization policies to help you to centrally manage the security of AWS accounts within an organization.</p> <p>SCP provide central control over the maximum permissions available to IAM users and IAM roles in an organization. They help enforce security boundaries and ensure compliance by restricting access to specific services or actions.</p>"},{"location":"index.html#examples","title":"Examples","text":"<ul> <li>Prevent disabling of security services</li> <li>Prevent member accounts from leaving the organizations</li> <li>Deny sharing of resources outside the organization</li> <li>Require IMDSv2 enabled to launch EC2 instances</li> <li>Block root user access</li> <li> <p>Deny contact information changes</p> </li> <li> <p>Deny access to unused regions</p> </li> <li> <p>Prevent region enable and disable actions</p> </li> <li>Deny critical IAM actions</li> <li>Restrict update of critical IAM roles</li> <li>Protect default security settings across services</li> </ul>"},{"location":"index.html#tips","title":"Tips","text":"<ul> <li>Create multiple Organizational Units (OUs) instead of attaching all SCPs to the root of your organization. This approach allows for more granular restrictions and increases the number of SCPs you can attach, due to quota limits.</li> <li>Each Organizational Unit (OU) can have up to 5 SCPs attached and maximum policy size limitations of 5120 characters. To avoid hitting this limit, consider combining multiple policies into a single SCP where possible.</li> <li>Refine your SCPs and restrict access to only the necessary AWS services using least privilege concept. Keep in mind that Root user accounts are affected by SCPs.</li> <li>The default SCP <code>FullAWSAccess</code> is automatically created and attached to every entity in your organization (root, OU and AWS accounts), which allows all principals to perform any actions. Use this as a base and then apply additional SCP to restrict access as needed.</li> <li>Always test your SCPs in a non-production environment to understand their impact before applying them broadly.</li> <li>Policies do not affect users or roles in the management account, so it is recommended not to run workloads in that account and leave it exclusively for managing accounts.</li> <li>Unlike IAM policies, SCPs count whitespace towards the character limit. Be mindful of this when writing policies to ensure they stay within the size constraints.</li> </ul>"},{"location":"index.html#quotas","title":"Quotas","text":"Value Quota Maximum number of policies attached to root, OU or account 5 Maximum size of a policy document 5120 characters"},{"location":"index.html#rcp-resource-control-policies","title":"RCP - Resource Control Policies","text":""},{"location":"index.html#about_1","title":"About","text":"<p>Resource Control Policies (RCPs) are authorization policies to help you to centrally manage the security of AWS accounts within an organization.</p> <p>RCP provide central control over the maximum permissions available permissions for resources in an organization. They help maintain resource-level security and ensure compliance by restricting what actions can be performed on specific resources.</p>"},{"location":"index.html#examples_1","title":"Examples","text":"<ul> <li>Prevent cross-service confused deputy problem</li> <li>Restrict access to only HTTPS connections to your resources</li> <li>Enforce consistent Amazon S3 bucket policy controls</li> </ul>"},{"location":"index.html#tips_1","title":"Tips","text":"<ul> <li>Create multiple Organizational Units (OUs) instead of attaching all RCPs to the root of your organization. This approach allows for more granular restrictions and increases the number of RCPs you can attach, due to quota limits.</li> <li>Each Organizational Unit (OU) can have up to 5 RCPs attached and maximum policy size limitations of 5120 characters. To avoid hitting this limit, consider combining multiple policies into a single RCP where possible.</li> <li>The default RCP <code>FRCPullAWSAccess</code> is automatically created and attached to every entity in your organization (root, OU and AWS accounts), which allows all principals to perform any actions. Use this as a base and then apply additional RCP to restrict access as needed.</li> <li>RCP does not support all AWS services, currently only works with specific AWS services: S3, STS, KMS, SQS and Secrets Manager.</li> <li>RCP does not affect service-linked roles and cannot manage permissions for resources shared across accounts using AWS RAM.</li> <li>Policies do not affect resources in the management account, so it is recommended not to run workloads in that account and leave it exclusively for managing accounts.</li> <li>Always test your RCPs in a non-production environment to understand their impact before applying them broadly.</li> </ul>"},{"location":"index.html#quotas_1","title":"Quotas","text":"Value Quota Maximum number of policies attached to root, OU or account 5 Maximum size of a policy document 5120 characters"},{"location":"aws-rcp-examples.html","title":"AWS RCP Examples","text":""},{"location":"aws-rcp-examples.html#prevent-cross-service-confused-deputy-problem","title":"Prevent cross-service confused deputy problem","text":"<p>Some AWS services use their service principals to interact with resources in other AWS services. When an unintended actor tries to leverage an AWS service principal's trust to access resources they shouldn't, this is known as the cross-service confused deputy problem.</p> <p>The following policy ensures that AWS service principals can only access your resources on behalf of requests originating from your organization. This policy applies the control only on requests that have <code>aws:SourceAccount</code> present so that service integrations that do not require the use of <code>aws:SourceAccount</code> aren't impacted. If the <code>aws:SourceAccount</code> is present in the request context, the <code>Null</code> condition will evaluate to <code>true</code>, causing the <code>aws:SourceOrgID</code> key to be enforced.</p> <pre><code>{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {            \n            \"Sid\": \"EnforceConfusedDeputyProtection\",\n            \"Effect\": \"Deny\",\n            \"Principal\": \"*\",\n            \"Action\": [\n                \"s3:*\",\n                \"sqs:*\",\n                \"kms:*\",\n                \"secretsmanager:*\",\n                \"sts:*\"\n            ],\n            \"Resource\": \"*\",\n            \"Condition\": {\n                \"StringNotEqualsIfExists\": {\n                    \"aws:SourceOrgID\": \"o-1234567890\",\n                    \"aws:SourceAccount\": [\n                        \"third-party-account-a\",\n                        \"third-party-account-b\"\n                    ]\n                },  \n                \"Bool\": {\n                    \"aws:PrincipalIsAWSService\": \"true\"\n                }\n            }\n        }\n    ]\n}\n</code></pre> <p>Reference: AWS Official Documentation</p>"},{"location":"aws-rcp-examples.html#restrict-access-to-only-https-connections-to-your-resources","title":"Restrict access to only HTTPS connections to your resources","text":"<p>The following policy requires that all access to your resources must occur over encrypted connections using HTTPS (TLS). Enforcing this helps mitigate the risk of attackers intercepting or altering network traffic.</p> <pre><code>{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"EnforceSecureTransport\",\n            \"Effect\": \"Deny\",\n            \"Principal\": \"*\",\n            \"Action\": [\n                \"sts:*\",\n                \"s3:*\",\n                \"sqs:*\",\n                \"secretsmanager:*\",\n                \"kms:*\"\n            ],\n            \"Resource\": \"*\",\n            \"Condition\": {\n                \"BoolIfExists\": {\n                    \"aws:SecureTransport\": \"false\"\n                }\n            }\n        }\n    ]\n}\n</code></pre> <p>Reference: AWS Official Documentation</p>"},{"location":"aws-rcp-examples.html#enforce-consistent-amazon-s3-bucket-policy-controls","title":"Enforce consistent Amazon S3 bucket policy controls","text":"<p>The following policy contains multiple statements to enforce consistent access controls for Amazon S3 buckets in your organization.</p> <ul> <li>Statement <code>EnforceS3TlsVersion</code>: Require a minimum TLS version of 1.2 for access to S3 buckets.</li> <li>Statement <code>EnforceKMSEncryption</code>: Require objects to be server-side encrypted with KMS keys.</li> </ul> <pre><code>{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"EnforceS3TlsVersion\",\n            \"Effect\": \"Deny\",\n            \"Principal\": \"*\",\n            \"Action\": \"s3:*\",\n            \"Resource\": \"*\",\n            \"Condition\": {                \n                \"NumericLessThan\": {\n                    \"s3:TlsVersion\": [\n                        \"1.2\"\n                    ]\n                }\n            }\n        },\n        {\n            \"Sid\": \"EnforceKMSEncryption\",\n            \"Effect\": \"Deny\",\n            \"Principal\": \"*\",\n            \"Action\": \"s3:PutObject\",\n            \"Resource\": \"*\",\n            \"Condition\": {\n                \"Null\": {\n                    \"s3:x-amz-server-side-encryption-aws-kms-key-id\": \"true\"\n                }\n            }\n        }\n    ]\n}\n</code></pre> <p>Reference: AWS Official Documentation</p>"},{"location":"aws-scp-examples.html","title":"AWS SPC Examples","text":""},{"location":"aws-scp-examples.html#prevent-disabling-of-security-services","title":"Prevent disabling of security services","text":"<p>Once you have established a security baseline for your AWS account, it is crucial to ensure that the configuration remains secure and cannot be altered by unauthorized users.</p> <ul> <li>Statement <code>DenyCloudtrail</code>: Deny any actions that could disrupt CloudTrail logs to ensure audit trails are preserved.</li> <li>Statement <code>DenyConfig</code>: Deny any actions that could disrupt AWS Config.</li> <li>Statement <code>DenyGuardDutyDeny</code>: any actions that could disrupt GuardDuty.</li> <li>Statement <code>DenySecurityHub</code>: Deny any actions that could disrupt Security Hub.</li> <li>Statement <code>DenyAccessAnalyzer</code>: Deny any actions that could disrupt Access Analyzer.</li> <li>Statement <code>DenyMacie</code>: Deny any actions that could disrupt Macie.</li> <li>Statement <code>DenyEventBridge</code>: Deny any actions that could disrupt EventBridge rules that generate important alerts.</li> </ul> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"DenyCloudtrail\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"cloudtrail:DeleteTrail\",\n        \"cloudtrail:PutEventSelectors\",\n        \"cloudtrail:StopLogging\",\n        \"cloudtrail:UpdateTrail\",\n        \"cloudtrail:CreateTrail\"\n      ],\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"DenyConfig\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"config:DeleteAggregationAuthorization\",\n        \"config:DeleteConfigurationRecorder\",\n        \"config:DeleteDeliveryChannel\",\n        \"config:DeleteRetentionConfiguration\",\n        \"config:PutConfigurationRecorder\",\n        \"config:PutDeliveryChannel\",\n        \"config:PutRetentionConfiguration\",\n        \"config:StopConfigurationRecorder\",\n        \"config:PutConfigRule\",\n        \"config:DeleteConfigRule\",\n        \"config:DeleteEvaluationResults\",\n        \"config:DeleteConfigurationAggregator\",\n        \"config:PutConfigurationAggregator\"\n      ],\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"DenyGuardDuty\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"guardduty:AcceptInvitation\",\n        \"guardduty:ArchiveFindings\",\n        \"guardduty:CreateDetector\",\n        \"guardduty:CreateFilter\",\n        \"guardduty:CreateIPSet\",\n        \"guardduty:CreateMembers\",\n        \"guardduty:CreatePublishingDestination\",\n        \"guardduty:CreateSampleFindings\",\n        \"guardduty:CreateThreatIntelSet\",\n        \"guardduty:DeclineInvitations\",\n        \"guardduty:DeleteDetector\",\n        \"guardduty:DeleteFilter\",\n        \"guardduty:DeleteInvitations\",\n        \"guardduty:DeleteIPSet\",\n        \"guardduty:DeleteMembers\",\n        \"guardduty:DeletePublishingDestination\",\n        \"guardduty:DeleteThreatIntelSet\",\n        \"guardduty:DisassociateFromMasterAccount\",\n        \"guardduty:DisassociateMembers\",\n        \"guardduty:InviteMembers\",\n        \"guardduty:StartMonitoringMembers\",\n        \"guardduty:StopMonitoringMembers\",\n        \"guardduty:TagResource\",\n        \"guardduty:UnarchiveFindings\",\n        \"guardduty:UntagResource\",\n        \"guardduty:UpdateDetector\",\n        \"guardduty:UpdateFilter\",\n        \"guardduty:UpdateFindingsFeedback\",\n        \"guardduty:UpdateIPSet\",\n        \"guardduty:UpdatePublishingDestination\",\n        \"guardduty:UpdateThreatIntelSet\"\n      ],\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"DenySecurityHub\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"securityhub:DeleteInvitations\",\n        \"securityhub:DisableSecurityHub\",\n        \"securityhub:DisassociateFromMasterAccount\",\n        \"securityhub:DeleteMembers\",\n        \"securityhub:DisassociateMembers\"\n      ],\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"DenyAccessAnalyzer\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"access-analyzer:DeleteAnalyzer\"\n      ],\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"DenyMacie\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"macie2:DisassociateFromMasterAccount\",\n        \"macie2:DisableOrganizationAdminAccount\",\n        \"macie2:DisableMacie\",\n        \"macie2:DeleteMember\"\n      ],\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"DenyEventBridge\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"events:DeleteRule\",\n        \"events:DisableRule\",\n        \"events:RemoveTargets\"\n      ],\n      \"Resource\": \"arn:aws:events:*:*:rule/default/IMPORTANT-RULE\"\n    }\n  ]\n}\n</code></pre>"},{"location":"aws-scp-examples.html#prevent-member-accounts-from-leaving-the-organizations","title":"Prevent member accounts from leaving the organizations","text":"<p>The following policy blocks member accounts leave your organization where they would no longer be restricted by your SCP.</p> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"DenyLeaveOrganization\",\n      \"Effect\": \"Deny\",\n      \"Action\": \"organizations:LeaveOrganization\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n</code></pre>"},{"location":"aws-scp-examples.html#deny-sharing-of-resources-outside-the-organization","title":"Deny sharing of resources outside the organization","text":"<p>The following example SCP prevents users from sharing resources that are not part of the organization with AWS Resource Access Manager (RAM).</p> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"ram:CreateResourceShare\",\n        \"ram:UpdateResourceShare\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"Bool\": {\n          \"ram:RequestedAllowsExternalPrincipals\": \"true\"\n        }\n      }\n    },\n    {\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"ram:AcceptResourceShareInvitation\",\n        \"ram:AssociateResourceShare\",\n        \"ram:CreateResourceShare\",\n        \"ram:DeleteResourceShare\",\n        \"ram:DisassociateResourceShare\",\n        \"ram:RejectResourceShareInvitation\",\n        \"ram:TagResource\",\n        \"ram:UntagResource\",\n        \"ram:UpdateResourceShare\",\n        \"ram:EnableSharingWithAwsOrganization\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringNotEquals\": {\n          \"aws:PrincipalOrgID\": \"o-1234567890\"\n        }\n      }\n    }\n  ]\n}\n</code></pre>"},{"location":"aws-scp-examples.html#require-imdsv2-enabled-to-launch-ec2-instances","title":"Require IMDSv2 enabled to launch EC2 instances","text":"<p>The following policy restricts all users from launching EC2 instances without IMDSv2 but allows specific IAM identities to modify instance metadata options.</p> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Deny\",\n      \"Action\": \"ec2:RunInstances\",\n      \"Resource\": \"arn:aws:ec2:*:*:instance/*\",\n      \"Condition\": {\n        \"StringNotEquals\": {\n          \"ec2:MetadataHttpTokens\": \"required\"\n        }\n      }\n    },\n    {\n      \"Effect\": \"Deny\",\n      \"Action\": \"ec2:RunInstances\",\n      \"Resource\": \"arn:aws:ec2:*:*:instance/*\",\n      \"Condition\": {\n        \"NumericGreaterThan\": {\n          \"ec2:MetadataHttpPutResponseHopLimit\": \"3\"\n        }\n      }\n    },\n    {\n      \"Effect\": \"Deny\",\n      \"Action\": \"*\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"NumericLessThan\": {\n          \"ec2:RoleDelivery\": \"2.0\"\n        }\n      }\n    },\n    {\n      \"Effect\": \"Deny\",\n      \"Action\": \"ec2:ModifyInstanceMetadataOptions\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringNotLike\": {\n          \"aws:PrincipalARN\": [\n            \"arn:aws:iam::{ACCOUNT_ID}:{RESOURCE_TYPE}/{RESOURCE_NAME}\"\n          ]\n        }\n      }\n    }\n  ]\n}\n</code></pre>"},{"location":"aws-scp-examples.html#block-root-user-access","title":"Block root user access","text":"<p>The root user has privileged access by default, this policy blocks access for this user in the AWS account.</p> <p>Benefits:</p> <ul> <li>The difficulty of understanding what person was involved in an action if they authenticate with the root user.</li> <li>It mitigates the concerns on AWS around password recovery such account take-over risk that can happen with Root users.</li> <li>There isn\u2019t a need to set up a multi-factor device for the user.</li> </ul> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\n    \"Sid\": \"DenyRootUser\",\n    \"Effect\": \"Deny\",\n    \"Action\": \"*\",\n    \"Resource\": \"*\",\n    \"Condition\": {\n      \"StringLike\": {\n        \"aws:PrincipalArn\": \"arn:aws:iam::*:root\"\n      }\n    }\n  }\n}\n</code></pre>"},{"location":"aws-scp-examples.html#deny-contact-information-changes","title":"Deny contact information changes","text":"<p>The following policy prevents the risk of account takeover by preventing contact information from being changed by any user.</p> <p>One way to resolve access issues to your AWS account and receive critical security alerts is through contact information.</p> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"DenyChangingContactInfo\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"account:PutAlternateContact\",\n        \"account:PuContactInformation\"\n      ],\n      \"Resource\": [\n        \"*\"\n      ]\n    }\n  ]\n}\n</code></pre>"},{"location":"aws-scp-examples.html#deny-access-to-unused-regions","title":"Deny access to unused regions","text":"<p>This policy denies access to any operations outside of the specified regions. This way you ensure that no resources will be provisioned in another region and you won't need to worry about applying security controls.</p> <p>In this exemples lets supposed that my organizations have workloads only in the <code>us-west-1</code> and <code>sa-east-1</code> regions, so this policy uses the Deny effect to deny access to all requests for operations that don't target one of the two approved regions. </p> <p>The <code>NotAction</code> element enables you to list services whose operations (or individual operations) are exempted from this restriction. Because global services have endpoints that are physically hosted by the <code>us-east-1</code> region , they must be exempted in this way. With an SCP structured this way, requests made to global services in the <code>us-east-1</code> region are allowed if the requested service is included in the <code>NotAction</code> element. Any other requests to services in the <code>us-east-1</code> region are denied by this example policy.</p> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"DenyAllUnapprovedRegions\",\n      \"Effect\": \"Deny\",\n      \"NotAction\": [\n        \"a4b:*\",\n        \"acm:*\",\n        \"aws-marketplace-management:*\",\n        \"aws-marketplace:*\",\n        \"aws-portal:*\",\n        \"budgets:*\",\n        \"ce:*\",\n        \"chime:*\",\n        \"cloudfront:*\",\n        \"config:*\",\n        \"cur:*\",\n        \"directconnect:*\",\n        \"ec2:DescribeRegions\",\n        \"ec2:DescribeTransitGateways\",\n        \"ec2:DescribeVpnGateways\",\n        \"fms:*\",\n        \"globalaccelerator:*\",\n        \"health:*\",\n        \"iam:*\",\n        \"importexport:*\",\n        \"kms:*\",\n        \"mobileanalytics:*\",\n        \"networkmanager:*\",\n        \"organizations:*\",\n        \"pricing:*\",\n        \"route53:*\",\n        \"route53domains:*\",\n        \"route53-recovery-cluster:*\",\n        \"route53-recovery-control-config:*\",\n        \"route53-recovery-readiness:*\",\n        \"s3:GetAccountPublic*\",\n        \"s3:ListAllMyBuckets\",\n        \"s3:ListMultiRegionAccessPoints\",\n        \"s3:PutAccountPublic*\",\n        \"shield:*\",\n        \"sts:*\",\n        \"support:*\",\n        \"trustedadvisor:*\",\n        \"waf-regional:*\",\n        \"waf:*\",\n        \"wafv2:*\",\n        \"wellarchitected:*\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringNotEquals\": {\n          \"aws:RequestedRegion\": [\n            \"us-west-1\",\n            \"sa-east-1\"\n          ]\n        },\n        \"ArnNotLike\": {\n          \"aws:PrincipalARN\": [\n            \"arn:aws:iam::*:role/Role1AllowedToBypassThisSCP\",\n            \"arn:aws:iam::*:role/Role2AllowedToBypassThisSCP\"\n          ]\n        }\n      }\n    }\n  ]\n}\n</code></pre> <p>Reference: AWS Official Documentation</p>"},{"location":"aws-scp-examples.html#prevent-region-enable-and-disable-actions","title":"Prevent region enable and disable actions","text":"<p>This policy prevents unauthorized or accidental changes to the region settings, which could impact the availability and configuration of services across the account. The policy ensures that only specific, highly privileged roles can enable or disable AWS regions.</p> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"PreventAccountRegionUpdate\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"account:EnableRegion\",\n        \"account:DisableRegion\"\n      ],\n      \"Resource\": [\n        \"*\"\n      ],\n      \"Condition\": {\n        \"StringNotLike\": {\n          \"aws:PrincipalArn\": [\n            \"arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess*\",\n            \"arn:aws:iam::*:role/OrganizationAccountAccessRole\"\n          ]\n        }\n      }\n    }\n  ]\n}\n</code></pre>"},{"location":"aws-scp-examples.html#deny-critical-iam-actions","title":"Deny critical IAM actions","text":"<p>The following policy blocks access key creation for the root user and restricts access to other critical IAM actions.</p> <ul> <li>Statement <code>DenyCreateRootUserAccessKey</code>: Deny creation of access keys for the root user.</li> <li>Statement <code>DenyCreateAccessKey</code>: Deny creation of any access keys except security roles.</li> <li>Statement <code>DenyPasswordPolicyUpdate</code>: Deny update IAM password policy except security roles.</li> </ul> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    { \n      \"Sid\": \"DenyCreateRootUserAccessKey\",\n      \"Effect\": \"Deny\",\n      \"Action\": \"iam:CreateAccessKey\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringLike\": {\n          \"aws:PrincipalArn\": [\n            \"arn:aws:iam::*:root\"\n          ]\n        }\n      }\n    },\n    {\n      \"Sid\": \"DenyCreateAccessKey\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"iam:CreateUser\",\n        \"iam:CreateAccessKey\"\n      ],\n      \"Resource\": [\n        \"*\"\n      ],\n      \"Condition\": {\n        \"StringNotEquals\": {\n          \"aws:PrincipalARN\": [\n            \"arn:aws:iam::*:role/AUDIT-ROLE-NAME\"\n          ]\n        }\n      }\n    },\n    {\n      \"Sid\": \"DenyPasswordPolicyUpdate\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"iam:DeleteAccountPasswordPolicy\",\n        \"iam:UpdateAccountPasswordPolicy\"\n      ],\n      \"Resource\": [\n        \"*\"\n      ],\n      \"Condition\": {\n        \"StringNotEquals\": {\n          \"aws:PrincipalARN\": [\n            \"arn:aws:iam::*:role/AUDIT-ROLE-NAME\"\n          ]\n        }\n      }\n    }\n  ]\n}\n</code></pre>"},{"location":"aws-scp-examples.html#restrict-update-of-critical-iam-roles","title":"Restrict update of critical IAM roles","text":"<p>This policy restricts IAM users and roles from making changes to the specified IAM role that can be used to deny modifications of an incident response or other security auditing role.</p> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"DenyCriticalRoleModification\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"iam:AttachRolePolicy\",\n        \"iam:DeleteRole\",\n        \"iam:DeleteRolePermissionsBoundary\",\n        \"iam:DeleteRolePolicy\",\n        \"iam:DetachRolePolicy\",\n        \"iam:PutRolePermissionsBoundary\",\n        \"iam:PutRolePolicy\",\n        \"iam:UpdateAssumeRolePolicy\",\n        \"iam:UpdateRole\",\n        \"iam:UpdateRoleDescription\"\n      ],\n      \"Resource\": [\n        \"arn:aws:iam::*:role/AUDIT-ROLE-NAME\",\n        \"arn:aws:iam::*:role/OrganizationAccountAccessRole\",\n        \"arn:aws:iam::*:role/stacksets-exec-*\",\n        \"arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO*\"\n      ]\n    }\n  ]\n}\n</code></pre>"},{"location":"aws-scp-examples.html#protect-default-security-settings-across-services","title":"Protect default security settings across services","text":"<p>The following policy prevent some important security settings services from being disable. None of these features are enabled by default and should be enabled as part of your initial account baseline.</p> <ul> <li>Statement <code>ProtectS3PublicAccess</code>: Prevent disabling block of S3 buckets from being made public.</li> <li>Statement <code>ProtectEBSEncryption</code>: Prevent disabling of default Amazon EBS encryption.</li> </ul> <pre><code>{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"ProtectS3PublicAccess\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"s3:PutAccountPublicAccessBlock\"\n      ],\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"ProtectEBSEncryption\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"ec2:DisableEbsEncryptionByDefault\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}\n</code></pre>"}]}