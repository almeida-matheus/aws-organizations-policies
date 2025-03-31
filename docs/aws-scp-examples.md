# AWS SPC Examples

##  Deny contact information changes
> Category: Account

The following policy prevents the risk of account takeover by preventing contact information from being changed by any user.

One way to resolve access issues to your AWS account and receive critical security alerts is through contact information.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "DenyChangingContactInfo",
      "Effect": "Deny",
      "Action": [
        "account:PutAlternateContact",
        "account:PuContactInformation"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
```

##  Prevent region enable and disable actions
> Category: Account

This policy prevents unauthorized or accidental changes to the region settings, which could impact the availability and configuration of services across the account. The policy ensures that only specific, highly privileged roles can enable or disable AWS regions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PreventAccountRegionUpdate",
      "Effect": "Deny",
      "Action": [
        "account:EnableRegion",
        "account:DisableRegion"
      ],
      "Resource": [
        "*"
      ],
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin"
          ]
        }
      }
    }
  ]
}
```

## Prevent accounts from leaving the organizations
> Category: Account

The following policy blocks member accounts leave your organization where they would no longer be restricted by your SCP.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeaveOrganization",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    }
  ]
}
```

##  Deny access to unused regions
> Category: Account

> Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html#example-scp-deny-region)

This policy restricts access to operations outside the specified AWS regions. By enforcing this restriction, you ensure that resources are not provisioned in unauthorized regions, reducing the need for additional security controls.

In this example, let's assume that our organization operates workloads only in the `us-west-1` and `sa-east-1` regions. The policy applies the Deny effect to block all requests for operations targeting any other region that are not targeted at one of the two approved regions.

The `NotAction` element enables you to list services whose operations (or individual operations) are exempted from this restriction. Because global services have endpoints that are physically hosted by the `us-east-1` region , they must be exempted in this way. With an SCP structured this way, requests made to global services in the `us-east-1` region are allowed if the requested service is included in the `NotAction` element. Any other requests to services in the `us-east-1` region are denied by this example policy.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllUnapprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "a4b:*",
        "acm:*",
        "aws-marketplace-management:*",
        "aws-marketplace:*",
        "aws-portal:*",
        "budgets:*",
        "ce:*",
        "chime:*",
        "cloudfront:*",
        "config:*",
        "cur:*",
        "directconnect:*",
        "ec2:DescribeRegions",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeVpnGateways",
        "fms:*",
        "globalaccelerator:*",
        "health:*",
        "iam:*",
        "importexport:*",
        "kms:*",
        "mobileanalytics:*",
        "networkmanager:*",
        "organizations:*",
        "pricing:*",
        "route53:*",
        "route53domains:*",
        "route53-recovery-cluster:*",
        "route53-recovery-control-config:*",
        "route53-recovery-readiness:*",
        "s3:GetAccountPublic*",
        "s3:ListAllMyBuckets",
        "s3:ListMultiRegionAccessPoints",
        "s3:PutAccountPublic*",
        "shield:*",
        "sts:*",
        "support:*",
        "trustedadvisor:*",
        "waf-regional:*",
        "waf:*",
        "wafv2:*",
        "wellarchitected:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-west-1",
            "sa-east-1"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalARN": [
            "arn:aws:iam::*:role/Role1AllowedToBypassThisSCP",
            "arn:aws:iam::*:role/Role2AllowedToBypassThisSCP"
          ]
        }
      }
    }
  ]
}
```

##  Deny sharing of resources outside the organization
> Category: Account

The following example SCP prevents users from sharing resources that are not part of the organization (`o-1234567890`) with AWS Resource Access Manager (RAM).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ram:CreateResourceShare",
        "ram:UpdateResourceShare"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "ram:RequestedAllowsExternalPrincipals": "true"
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": [
        "ram:AcceptResourceShareInvitation",
        "ram:AssociateResourceShare",
        "ram:CreateResourceShare",
        "ram:DeleteResourceShare",
        "ram:DisassociateResourceShare",
        "ram:RejectResourceShareInvitation",
        "ram:TagResource",
        "ram:UntagResource",
        "ram:UpdateResourceShare",
        "ram:EnableSharingWithAwsOrganization"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-1234567890"
        }
      }
    }
  ]
}
```

## Prevent disabling of security services

> Category: Security

Once you have established a security baseline for your AWS account, it is crucial to ensure that the configuration remains secure and cannot be altered by unauthorized users.

- Statement `DenyCloudtrail`: Prevents disabling or modifying CloudTrail to ensure audit trails remain intact.
- Statement `DenyConfig`: Prevents disabling or altering AWS Config to maintain configuration recording, compliance tracking and rules.
- Statement `DenyGuardDuty`: Prevents disabling GuardDuty or modifying its configuration, ensuring continuous threat detection remains active.
- Statement `DenySecurityHub`: Prevents changes that could disable Security Hub, ensuring centralized security findings remain accessible.
- Statement `DenyAccessAnalyzer`: Prevents disabling Access Analyzer, ensuring uninterrupted access analysis and monitoring.
- Statement `DenyMacie`: Prevents disabling Macie to ensure sensitive data discovery and monitoring remain active.
- Statement `DenyEventBridge`: Ensures EventBridge rules that generate critical security alerts cannot be modified or deleted.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudtrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
        "cloudtrail:CreateTrail"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyConfig",
      "Effect": "Deny",
      "Action": [
        "config:DeleteAggregationAuthorization",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:DeleteRetentionConfiguration",
        "config:PutConfigurationRecorder",
        "config:PutDeliveryChannel",
        "config:PutRetentionConfiguration",
        "config:StopConfigurationRecorder",
        "config:PutConfigRule",
        "config:DeleteConfigRule",
        "config:DeleteEvaluationResults",
        "config:DeleteConfigurationAggregator",
        "config:PutConfigurationAggregator"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyGuardDuty",
      "Effect": "Deny",
      "Action": [
        "guardduty:AcceptInvitation",
        "guardduty:ArchiveFindings",
        "guardduty:CreateDetector",
        "guardduty:CreateFilter",
        "guardduty:CreateIPSet",
        "guardduty:CreateMembers",
        "guardduty:CreatePublishingDestination",
        "guardduty:CreateSampleFindings",
        "guardduty:CreateThreatIntelSet",
        "guardduty:DeclineInvitations",
        "guardduty:DeleteDetector",
        "guardduty:DeleteFilter",
        "guardduty:DeleteInvitations",
        "guardduty:DeleteIPSet",
        "guardduty:DeleteMembers",
        "guardduty:DeletePublishingDestination",
        "guardduty:DeleteThreatIntelSet",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "guardduty:InviteMembers",
        "guardduty:StartMonitoringMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:TagResource",
        "guardduty:UnarchiveFindings",
        "guardduty:UntagResource",
        "guardduty:UpdateDetector",
        "guardduty:UpdateFilter",
        "guardduty:UpdateFindingsFeedback",
        "guardduty:UpdateIPSet",
        "guardduty:UpdatePublishingDestination",
        "guardduty:UpdateThreatIntelSet"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenySecurityHub",
      "Effect": "Deny",
      "Action": [
        "securityhub:DeleteInvitations",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromMasterAccount",
        "securityhub:DeleteMembers",
        "securityhub:DisassociateMembers"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyAccessAnalyzer",
      "Effect": "Deny",
      "Action": [
        "access-analyzer:DeleteAnalyzer"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyMacie",
      "Effect": "Deny",
      "Action": [
        "macie2:DisassociateFromMasterAccount",
        "macie2:DisableOrganizationAdminAccount",
        "macie2:DisableMacie",
        "macie2:DeleteMember"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyEventBridge",
      "Effect": "Deny",
      "Action": [
        "events:DeleteRule",
        "events:DisableRule",
        "events:RemoveTargets"
      ],
      "Resource": "arn:aws:events:*:*:rule/default/important-rule"
    }
  ]
}
```

## Deny creating public secrets
> Category: Security

> Reference: [Rami's Wiki](https://rami.wiki/scps/)

This policy ensures that all secrets stored in AWS Secrets Manager cannot be publicly exposed, preventing unintended exposure of credentials and other sensitive data. This is possible because AWS provides a setting called Block Public Policy, which prevents policies from being made public.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "secretsmanager:PutResourcePolicy",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "secretsmanager:BlockPublicPolicy": "false"
        }
      }
    }
  ]
}

```

## Block root user access
> Category: IAM

The root user has privileged access by default, this policy blocks access for this user in the AWS account.

Benefits:

- The difficulty of understanding what person was involved in an action if they authenticate with the root user.
- It mitigates the concerns on AWS around password recovery such account take-over risk that can happen with Root users.
- There isn’t a need to set up a multi-factor device for the user.

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Sid": "DenyRootUser",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringLike": {
        "aws:PrincipalArn": "arn:aws:iam::*:root"
      }
    }
  }
}
```

##  Deny critical IAM actions
> Category: IAM

The following policy blocks access key creation for the root user and restricts access to other critical IAM actions.

* Statement `DenyCreateRootUserAccessKey`: Deny creation of access keys for the root user.
* Statement `DenyCreateAccessKey`: Deny creation of any access keys except admin role.
* Statement `DenyPasswordPolicyUpdate`: Deny update IAM password policy except admin role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCreateRootUserAccessKey",
      "Effect": "Deny",
      "Action": "iam:CreateAccessKey",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:root"
          ]
        }
      }
    },
    {
      "Sid": "DenyCreateAccessKey",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:CreateAccessKey"
      ],
      "Resource": [
        "*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalARN": [
            "arn:aws:iam::*:role/admin"
          ]
        }
      }
    },
    {
      "Sid": "DenyPasswordPolicyUpdate",
      "Effect": "Deny",
      "Action": [
        "iam:DeleteAccountPasswordPolicy",
        "iam:UpdateAccountPasswordPolicy"
      ],
      "Resource": [
        "*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalARN": [
            "arn:aws:iam::*:role/admin"
          ]
        }
      }
    }
  ]
}
```

##  Restrict update of critical IAM roles
> Category: IAM

This policy restricts IAM users and roles from making changes to specified critical IAM roles with an exception for a admin role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCriticalRoleModification",
      "Effect": "Deny",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:DeleteRole",
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeleteRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:UpdateRole",
        "iam:UpdateRoleDescription"
      ],
      "Resource": [
        "arn:aws:iam::*:role/audit",
        "arn:aws:iam::*:role/OrganizationAccountAccessRole",
        "arn:aws:iam::*:role/stacksets-exec-*",
        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO*"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN":"arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```


##  Protect S3 default security public access block settings
> Category: Storage

AWS S3 Public Access Block settings help organizations enforce security policies by restricting public access to S3 buckets across an AWS account. If these settings are modified or disabled, S3 buckets could unintentionally become publicly accessible, leading to data leaks and security vulnerabilities.

Note: This feature is not enabled by default and should be enabled as part of your initial account baseline.

This policy prevents unauthorized modifications to the S3 account level public access block settings, ensuring that security controls remain enforced.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectS3PublicAccess",
      "Effect": "Deny",
      "Action": [
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

## Preventing unauthorized AWS Backup modifications
> Category: Storage

> Reference: [Asecure Cloud](https://asecure.cloud/a/scp_backup/)

AWS Backup provides a centralized solution for managing backups across AWS services. However, accidental deletion or modification of backup configurations can lead to data loss and compliance violations.

This policy prevents unauthorized or even accidental modifications to AWS Backup settings, ensuring that backup plans, vaults, and recovery points remain intact and protected.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "backup:DeleteBackupPlan",
        "backup:DeleteBackupSelection",
        "backup:DeleteBackupVault",
        "backup:DeleteBackupVaultAccessPolicy",
        "backup:DeleteBackupVaultNotifications",
        "backup:DeleteRecoveryPoint",
        "backup:PutBackupVaultAccessPolicy",
        "backup:PutBackupVaultNotifications",
        "backup:UpdateBackupPlan",
        "backup:UpdateRecoveryPointLifecycle",
        "backup:UpdateRegionSettings"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
```

##  Require IMDSv2 enabled to launch EC2 instances
> Category: Computing

> Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_ec2.html#example-ec2-2)

The following policy restricts all users from launching EC2 instances without IMDSv2 but allows specific IAM role `admin` from AWS account `111111111111` to modify instance metadata options.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "NumericGreaterThan": {
          "ec2:MetadataHttpPutResponseHopLimit": "3"
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": {
          "ec2:RoleDelivery": "2.0"
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": "ec2:ModifyInstanceMetadataOptions",
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalARN": [
            "arn:aws:iam::111111111111:role/admin"
          ]
        }
      }
    }
  ]
}
```

##  Protect default security settings EBS encryption
> Category: Computing

Amazon Elastic Block Store (EBS) encryption helps organizations protect their data at rest by encrypting volumes using AWS Key Management Service (KMS). AWS allows administrators to enable EBS encryption by default, ensuring that all newly created volumes are encrypted automatically.

This feature is not enabled by default and should be enabled as part of your initial account baseline. However, if this setting is disabled, new EBS volumes could be created without encryption, leading to potential security and compliance risks.

This policy ensures that the default encryption setting cannot be turned off.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectEBSEncryption",
      "Effect": "Deny",
      "Action": [
        "ec2:DisableEbsEncryptionByDefault"
      ],
      "Resource": "*"
    }
  ]
}
```

## Prevent computing log deletion
> Category: Computing

Logs are crucial for security monitoring, compliance, and troubleshooting in AWS environments. However, unauthorized deletion of logs can be a significant security risk, as it may allow attackers to cover their tracks or disrupt incident investigations.

This following policy is designed to prevent the deletion of VPC Flow Logs and CloudWatch Logs.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyVPCFlowLogs",
      "Effect": "Deny",
      "Action": [
        "ec2:DeleteFlowLogs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyCWLogs",
      "Effect": "Deny",
      "Action": [
        "logs:DeleteLogGroup",
        "logs:DeleteLogStream"
      ],
      "Resource": "*"
    }
  ]
}
```

## Enforce secure AWS lambda function URL authentication
> Category: Computing

> Reference: [Asecure Cloud](https://asecure.cloud/a/scp_lambda_open_url/)

AWS Lambda Function URLs allow developers to expose Lambda functions as HTTP endpoints. However, misconfigured authentication settings can lead to publicly accessible Lambda functions, increasing the risk of unauthorized access and data exposure.

This policy enforces security best practices by blocking the creation or update of Lambda Function URLs that not required authentication unless they are secured using AWS IAM authentication.


```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "lambda:CreateFunctionUrlConfig",
        "lambda:UpdateFunctionUrlConfig"
      ],
      "Resource": "arn:aws:lambda:*:*:function/*",
      "Effect": "Deny",
      "Condition": {
        "StringNotEquals": {
            "lambda:FunctionUrlAuthType": "AWS_IAM"
        }
      }
    }
  ]
}
```

## Restrict billing modifications
> Category: Billing

> Reference: [Asecure Cloud](https://asecure.cloud/a/scp_account_billing/)

AWS billing and account settings contain sensitive financial and administrative information. Unauthorized modifications to billing, payment methods, or account settings can lead to financial risks, service disruptions, or compliance issues.

This policy prevents unauthorized identities from modifying AWS billing and account settings, ensuring that only designated FinOps role have permission to make such changes.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "aws-portal:ModifyAccount",
        "aws-portal:ModifyBilling",
        "aws-portal:ModifyPaymentMethods"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/finops"
          ]
        }
      }
    }
  ]
}
```

## Prevent modifications to specific cloudformation stacks
> Category: Computing

> Reference: [Asecure Cloud](https://asecure.cloud/a/scp_cloudformation/)

AWS CloudFormation simplifies infrastructure management by enabling Infrastructure as Code (IaC). However, unauthorized modifications to critical CloudFormation stacks can lead to configuration drift, security risks, or service disruptions.

This AWS Service Control Policy (SCP) enforces strict access control on a specific CloudFormation stack, ensuring that only admin role can create, update, or delete it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCF",
      "Effect": "Deny",
      "Action": [
        "cloudformation:CreateChangeSet",
        "cloudformation:CreateStack",
        "cloudformation:CreateStackInstances",
        "cloudformation:CreateStackSet",
        "cloudformation:DeleteChangeSet",
        "cloudformation:DeleteStack",
        "cloudformation:DeleteStackInstances",
        "cloudformation:DeleteStackSet",
        "cloudformation:DetectStackDrift",
        "cloudformation:DetectStackResourceDrift",
        "cloudformation:DetectStackSetDrift",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:SetStackPolicy",
        "cloudformation:StopStackSetOperation",
        "cloudformation:UpdateStack",
        "cloudformation:UpdateStackInstances",
        "cloudformation:UpdateStackSet",
        "cloudformation:UpdateTerminationProtection"
      ],
      "Resource": [
        "arn:aws:cloudformation:*:*:stack/important-cf-stack"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

## Restrict network modifications to authorized roles for specific squad

> Category: Network

This policy is designed to restrict modifications to critical networking components, including Amazon Route 53 (DNS services) and Amazon VPC (Virtual Private Cloud). Only IAM network role is allowed to make changes, ensuring that unauthorized users cannot disrupt DNS configurations, network routing, or security settings.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRoute53",
      "Effect": "Deny",
      "Action": [
        "route53:Change*",
        "route53:Create*",
        "route53:Delete*",
        "route53:Disassociate*",
        "route53domains:DisableDomainAutoRenew",
        "route53domains:EnableDomainAutoRenew",
        "route53domains:RegisterDomain",
        "route53resolver:Create*",
        "route53resolver:Delete*",
        "route53resolver:Disassociate*",
        "route53resolver:Update*"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:role/network"
        }
      }
    },
    {
      "Sid": "DenyVPC",
      "Effect": "Deny",
      "Action": [
        "ec2:AuthorizeSecurity*",
        "ec2:RevokeSecurity*",
        "ec2:AllocateAddress",
        "ec2:AssociateAddress",
        "ec2:CreateDefault*",
        "ec2:CreateInternetGateway",
        "ec2:CreateNetworkAclEntry",
        "ec2:CreateVpc*",
        "ec2:DeleteNetworkAclEntry",
        "ec2:DeleteRoute",
        "ec2:DeleteSubnet",
        "ec2:DeleteVpc*",
        "ec2:Disassociate*",
        "ec2:ModifyVpcAttribute",
        "ec2:ProvisionByoipCidr"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:role/network"
        }
      }
    }
  ]
}
```