# AWS SPC Examples

## Prevent disabling of security services

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

## Prevent member accounts from leaving the organizations

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

## Deny sharing of resources outside the organization

The following example SCP prevents users from sharing resources that are not part of the organization with AWS Resource Access Manager (RAM).

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

## Require IMDSv2 enabled to launch EC2 instances

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
Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_ec2.html#example-ec2-2)

## Block root user access

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

## Deny contact information changes

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

## Deny access to unused regions

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

Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html#example-scp-deny-region)

## Prevent region enable and disable actions

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

## Deny critical IAM actions

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

## Restrict update of critical IAM roles

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

## Protect default security settings across services

The following policy prevent some important security settings services from being disable. None of these features are enabled by default and should be enabled as part of your initial account baseline.

- Statement `ProtectS3PublicAccess`: Prevent disabling block of S3 buckets from being made public.
- Statement `ProtectEBSEncryption`: Prevent disabling of default Amazon EBS encryption.

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
    },
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
