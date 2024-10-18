# AWS SPC Examples - Security

## Protect security services

Once you have configured an AWS account to meet a security baseline, you will want to ensure your configuration cannot be modified by anyone.

- Deny any actions that could deletes of CloudTrail logs to ensure audit trails are preserved.
- Deny any actions that could disrupt AWS Config to maintain consistent settings.
- Deny any actions that could disrupt GuardDuty.
- Deny any actions that could disrupt Security Hub.
- Deny any actions that could disrupt Access Analyzer.
- Deny any actions that could disrupt Macie.
- Deny any actions that could disrupt EventBridge rules that generate important alerts.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PreventCloudTrailModification",
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
      "Sid": "PreventConfigModification",
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
      "Sid": "PreventGuardDutyModification",
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
      "Sid": "PreventSecurityHubModification",
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
      "Sid": "PreventAccessAnalyzerModification",
      "Effect": "Deny",
      "Action": [
        "access-analyzer:DeleteAnalyzer"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PreventMacieModification",
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
      "Sid": "PreventEventBridgeModification",
      "Effect": "Deny",
      "Action": [
        "events:DeleteRule",
        "events:DisableRule",
        "events:RemoveTargets"
      ],
      "Resource": "arn:aws:events:*:*:rule/default/IMPORTANT-RULE"
    }
  ]
}
```

## Require EC2 IMDSv2

The following policy restricts all users from launching EC2 instances without IMDSv2 but allows specific IAM identities to modify instance metadata options.

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
            "arn:aws:iam::{ACCOUNT_ID}:{RESOURCE_TYPE}/{RESOURCE_NAME}"
          ]
        }
      }
    }
  ]
}
```

## Deny ability to leave Organization

The following policy avoid having the accounts simply leave your organization where they would no longer be restricted by your SCP.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    }
  ]
}
```

## Deny sharing of resources outside of the organization using AWS RAM

The following policy avoid having the accounts simply leave your organization where they would no longer be restricted by your SCP.
The following example SCP prevents users from creating resource shares that allow sharing with IAM users and roles that aren't part of the organization.

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

## Prevent account takeover risk

The following policy avoid account takeover.

You should have the contact information for your accounts set to approved phone numbers and other values.

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

## Restrict AWS region access

Deny access to AWS services in regions that are not approved for use.

[Oficial AWS example](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html#example-scp-deny-region).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllOutsideEU",
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
            "eu-central-1",
            "eu-west-1"
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

## Deny account region modification

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PreventAccountRegionChanges",
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
            "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess*",
            "arn:aws:iam::*:role/OrganizationAccountAccessRole"
          ]
        }
      }
    }
  ]
}
```

## Prevent critical IAM actions

* Deny creation of access keys for the root user
* Deny creation of any access keys except security team
* Deny update IAM password policy except security team

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
            "arn:aws:iam::*:role/AUDIT-ROLE-NAME"
          ]
        }
      }
    },
    {
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
            "arn:aws:iam::*:role/AUDIT-ROLE-NAME"
          ]
        }
      }
    }
  ]
}
```


## Deny ability to modify an important IAM role

This policy restricts IAM users and roles from making changes to the specified IAM role that can be used to deny modifications of an incident response or other security auditing role.

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
        "arn:aws:iam::*:role/AUDIT-ROLE-NAME",
        "arn:aws:iam::*:role/OrganizationAccountAccessRole",
        "arn:aws:iam::*:role/stacksets-exec-*",
        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO*"
      ]
    }
  ]
}
```

## Deny root user access

To disallowing account access with root user credentials due to the difficulty of understanding what person was involved in an action if they authenticate with the root users because it has privelege access by default.

- Advantages:
    - It mitigates the concerns on AWS around password recovery such account take-over risk that can happen with Root users
    - There isn’t a need to set up a multi-factor device for the user

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

## Protect default security settings

The following policy restricts all users from disabling the default Amazon EBS Encryption.

The following SCP protects some important security settings from being turned off. None of these features are enabled by default and should be enabled as part of your initial account baseline. These features are

* Prevent disabling of default Amazon EBS encryption
* Access Analyzer: A service for identifying when resources are made public or granted access to untrusted accounts.
* Default EBS encryption: This encrypts the virtual hard-drives of your EC2s by default.
* S3 Block Public Access: Denies S3 buckets from being made public.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:DisableEbsEncryptionByDefault",
        "access-analyzer:DeleteAnalyzer",
        "ec2:DisableEbsEncryptionByDefault",
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

## Prevent public resource via policy

* Prevent changes to bucket logging for your Amazon S3 buckets.
* Prevent changes to bucket policy for your Amazon S3 buckets
* Prevent uploading unencrypted objects to S3 buckets.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketLogging",
        "s3:PutBucketPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PreventUnencryptedObject",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    }
  ]
}
```