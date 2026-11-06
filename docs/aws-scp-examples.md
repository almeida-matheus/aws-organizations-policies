# SCP Examples

All examples follow a deny list strategy: `FullAWSAccess` stays attached and each policy only adds `Deny` statements.

Before using them:

- Replace the placeholders: `o-xxxxxxxxxx` (organization ID), `111111111111` (account ID), `222222222222` (trusted third-party account), `203.0.113.0/24` (corporate CIDR), `vpc-0123456789abcdef0` (your VPC) and the role names `admin`, `security`, `network`, `finops` and `iac-deploy`.
- Each example is a separate policy for readability. With 10 SCPs per entity (`FullAWSAccess` takes one), merge statements from several examples into one policy.
- `arn:aws:iam::*:role/admin` matches a role named `admin` in **any** account of the organization. If the exception role lives in a single account, use its account ID instead of `*`.
- Exceptions by role name are only safe if nobody else can create or change a role with that name. Attach [Protect critical IAM roles](#protect-critical-iam-roles) with every exception role in it before relying on any other policy here.
- To exempt an IAM Identity Center permission set, match the generated role: `arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_AdministratorAccess_*`.
- If you use AWS Control Tower, add `arn:aws:iam::*:role/AWSControlTowerExecution` to the exceptions of policies that touch CloudTrail, Config, IAM roles or Regions. Otherwise account enrollment and baseline updates fail.
- SCPs don't apply to the management account or to service-linked roles.
- Attach to a test OU first and watch CloudTrail for `AccessDenied` before moving the policy up the hierarchy.

---

## Account

### Deny account contact changes and closure

Contact information is how AWS reaches you about security events and how account recovery works. Changing it is a common step in account takeover. The same policy blocks closing the account from inside it.

The management account can still update member account contacts through the Account Management API, since SCPs don't apply there.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAccountSettingsChanges",
      "Effect": "Deny",
      "Action": [
        "account:CloseAccount",
        "account:DeleteAlternateContact",
        "account:PutAlternateContact",
        "account:PutContactInformation"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

### Deny enabling or disabling Regions

Opt-in Regions should only be turned on by the platform team. An enabled but unmonitored Region is a good place to hide resources.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRegionOptInChanges",
      "Effect": "Deny",
      "Action": [
        "account:EnableRegion",
        "account:DisableRegion"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

### Deny leaving the organization

An account that leaves the organization is no longer subject to its SCPs, RCPs or consolidated billing. This is one of the first SCPs AWS recommends attaching.

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

### Deny access to unapproved Regions

> Reference: [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples/blob/main/Region-controls/Deny-access-to-AWS-based-on-the-requested-AWS-region.json)

Denies every request outside `us-east-1` and `sa-east-1`. Global services are listed in `NotAction` because their endpoints live in `us-east-1` and would otherwise break when `us-east-1` isn't in the approved list.

Notes:

- Include the home Region of IAM Identity Center and AWS Control Tower in the approved list.
- If you use Control Tower, its Region deny control does the same thing and is maintained by AWS.
- New global services show up over time. If something breaks with `AccessDenied` on `us-east-1`, check whether its prefix needs to go into `NotAction`.
- Amazon Bedrock [cross-Region inference](https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html) sends requests to other Regions in the same geography, which a plain Region deny blocks. `DenyBedrockOutsideApprovedRegions` handles that: Bedrock calls to other Regions are only allowed through `us.*` inference profiles; use the prefix of your geography. [Global profiles](https://docs.aws.amazon.com/bedrock/latest/userguide/global-cross-region-inference.html) (`global.*`) stay blocked, because they can send data to any commercial Region. To allow them, add `arn:aws:bedrock:*:*:inference-profile/global.*` to `bedrock:InferenceProfileArn`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnapprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "a4b:*",
        "acm:*",
        "aws-marketplace-management:*",
        "aws-marketplace:*",
        "aws-portal:*",
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
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
            "us-east-1",
            "sa-east-1"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    },
    {
      "Sid": "DenyBedrockOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "sa-east-1"
          ]
        },
        "ArnNotLike": {
          "bedrock:InferenceProfileArn": "arn:aws:bedrock:*:*:inference-profile/us.*",
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

---

## IAM

### Deny root user access

> Reference: [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples/blob/main/Privileged-access-controls/Prevent-root-credentials-management-in-member-accounts-in-AWS-Organizations.json)

Blocks every action taken with root credentials in member accounts. Root sessions are hard to attribute to a person and the root password reset flow is a takeover path.

Sessions opened through [centralized root access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user-access-management) (`sts:AssumeRoot`, from the management account or a delegated admin) carry the `aws:AssumedRoot` key and are not blocked. That keeps root-only tasks possible, such as removing an S3 bucket policy that locks everyone out.

With centralized root access enabled you can also delete the root credentials of member accounts. Keep this SCP anyway for accounts that still have them.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootUser",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        },
        "Null": {
          "aws:AssumedRoot": "true"
        }
      }
    }
  ]
}
```

### Deny IAM users and long-term credentials

Access keys and console passwords for IAM users are the most common source of leaked AWS credentials. Use IAM Identity Center for people and roles for workloads, and block the creation of long-term credentials.

`iam:CreateServiceSpecificCredential` covers CodeCommit, Keyspaces and long-term Amazon Bedrock API keys. Reactivating an old access key (`UpdateAccessKey`) and uploading SSH keys or signing certificates are blocked too.

The SES console creates an IAM user with an access key when you generate SMTP credentials, so that needs the `admin` role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLongTermCredentials",
      "Effect": "Deny",
      "Action": [
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:CreateServiceSpecificCredential",
        "iam:CreateUser",
        "iam:DeleteAccountPasswordPolicy",
        "iam:ResetServiceSpecificCredential",
        "iam:UpdateAccessKey",
        "iam:UpdateAccountPasswordPolicy",
        "iam:UpdateLoginProfile",
        "iam:UploadSigningCertificate",
        "iam:UploadSSHPublicKey"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

### Deny identity provider changes

A new identity source is a back door: whoever controls it can get into the account without touching IAM users or roles. This covers the three ways to add one:

- SAML and OIDC providers in IAM
- IAM Roles Anywhere trust anchors (any certificate signed by the anchor's CA can get credentials)
- IAM Identity Center account instances (`sso:CreateInstance`), a separate Identity Center that lives inside a member account and outside the central one

Cognito identity pools also hand out AWS credentials. Unauthenticated access is covered by the [Cognito RCP](aws-rcp-examples.md#deny-unauthenticated-cognito-identity-pool-access); if no team builds apps with identity pools, add `cognito-identity:CreateIdentityPool` here as well.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIdentityProviderChanges",
      "Effect": "Deny",
      "Action": [
        "iam:AddClientIDToOpenIDConnectProvider",
        "iam:CreateOpenIDConnectProvider",
        "iam:CreateSAMLProvider",
        "iam:DeleteOpenIDConnectProvider",
        "iam:DeleteSAMLProvider",
        "iam:RemoveClientIDFromOpenIDConnectProvider",
        "iam:UpdateOpenIDConnectProviderThumbprint",
        "iam:UpdateSAMLProvider",
        "rolesanywhere:CreateTrustAnchor",
        "rolesanywhere:EnableTrustAnchor",
        "rolesanywhere:UpdateTrustAnchor",
        "sso:CreateInstance"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

### Protect critical IAM roles

This is the policy that makes every exception in this project safe. The other SCPs and RCPs exempt roles by name (`admin`, `security`, `network`, `finops`, `iac-deploy`), and a name is all it takes: anyone who can create a role called `network` and attach a policy to it gets past the network SCP. So every exception role, plus the roles the platform depends on (cross-account access, StackSets, Control Tower, Identity Center, AWS Backup), is locked here. Only `admin` and the StackSets execution role, which deploys the baseline, can create or change them. If you add an exception role to any policy, add it here too.

- `DenyCriticalRoleChanges`: creating, deleting, editing the trust policy or changing the permissions of these roles.
- `DenyPassingCriticalRoles`: passing one of these roles to an EC2 instance or a Lambda function you control is as good as assuming it. `iac-deploy` and the AWS Backup role are left out because pipelines and backup plans legitimately pass them to CloudFormation and AWS Backup.
- `ProtectPlatformPolicies`: locking a role isn't enough if its permissions come from a customer managed policy anyone can edit, since a new policy version changes what the role can do. This covers policies under the `/platform/` path, so create the platform's policies with it (`aws iam create-policy --path /platform/ ...`).

Accounts created through Organizations or Control Tower get `OrganizationAccountAccessRole` or `AWSControlTowerExecution` from the service itself, which this policy doesn't affect. To enroll an existing account in Control Tower, create `AWSControlTowerExecution` with the `admin` role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCriticalRoleChanges",
      "Effect": "Deny",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeleteRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:PutRolePolicy",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:UpdateRole",
        "iam:UpdateRoleDescription"
      ],
      "Resource": [
        "arn:aws:iam::*:role/admin",
        "arn:aws:iam::*:role/security",
        "arn:aws:iam::*:role/network",
        "arn:aws:iam::*:role/finops",
        "arn:aws:iam::*:role/iac-deploy",
        "arn:aws:iam::*:role/OrganizationAccountAccessRole",
        "arn:aws:iam::*:role/AWSControlTowerExecution",
        "arn:aws:iam::*:role/stacksets-exec-*",
        "arn:aws:iam::*:role/service-role/AWSBackupDefaultServiceRole",
        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/stacksets-exec-*"
          ]
        }
      }
    },
    {
      "Sid": "DenyPassingCriticalRoles",
      "Effect": "Deny",
      "Action": "iam:PassRole",
      "Resource": [
        "arn:aws:iam::*:role/admin",
        "arn:aws:iam::*:role/security",
        "arn:aws:iam::*:role/network",
        "arn:aws:iam::*:role/finops",
        "arn:aws:iam::*:role/OrganizationAccountAccessRole",
        "arn:aws:iam::*:role/AWSControlTowerExecution"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    },
    {
      "Sid": "ProtectPlatformPolicies",
      "Effect": "Deny",
      "Action": [
        "iam:CreatePolicyVersion",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:TagPolicy",
        "iam:UntagPolicy"
      ],
      "Resource": "arn:aws:iam::*:policy/platform/*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/stacksets-exec-*"
          ]
        }
      }
    }
  ]
}
```

### Require a permissions boundary on roles

Lets application teams create their own roles without being able to create one more powerful than allowed. Every role they create or change must have the `workload-boundary` policy as its [permissions boundary](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html).

- `RequireBoundary`: creating, deleting or changing a role (its policies or its trust policy) is denied unless that role has the boundary. `iam:PermissionsBoundary` refers to the boundary of the target role, so this also stops teams from touching roles that don't have one, such as the platform roles. `UpdateAssumeRolePolicy` is the important one: without it, a team could edit the trust policy of a platform role and assume it.
- `DenyBoundaryRemoval`: the boundary can't be removed.
- `ProtectBoundaryPolicy`: the boundary policy itself can't be edited.

Create `workload-boundary` in every account before attaching. The StackSets execution role is exempted so the baseline can deploy the boundary and the platform roles. If another pipeline creates platform roles without a boundary, add its role to the exceptions. `iam:CreatePolicy` is denied for the boundary's name too, so nobody can create a permissive `workload-boundary` in a new account before the baseline gets there.

This only covers roles. It depends on two other policies: [Deny IAM users](#deny-iam-users-and-long-term-credentials), since users and groups have no boundary here, and [Protect critical IAM roles](#protect-critical-iam-roles), which stops teams from passing powerful roles to services and from editing the `/platform/` policies those roles use. Customer managed policies attached to platform roles outside `/platform/` can still be edited.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireBoundary",
      "Effect": "Deny",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "iam:PermissionsBoundary": "arn:aws:iam::*:policy/workload-boundary",
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/stacksets-exec-*"
          ]
        }
      }
    },
    {
      "Sid": "DenyBoundaryRemoval",
      "Effect": "Deny",
      "Action": "iam:DeleteRolePermissionsBoundary",
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/stacksets-exec-*"
          ]
        }
      }
    },
    {
      "Sid": "ProtectBoundaryPolicy",
      "Effect": "Deny",
      "Action": [
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:SetDefaultPolicyVersion"
      ],
      "Resource": "arn:aws:iam::*:policy/workload-boundary",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/stacksets-exec-*"
          ]
        }
      }
    }
  ]
}
```

### Control outbound identity federation

> Reference: [IAM outbound identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_policies.html)

With [outbound identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound.html), AWS principals call `sts:GetWebIdentityToken` to get a signed JWT and use it to authenticate to other clouds and SaaS. It removes stored API keys, but it also means any role with that permission can authenticate to services outside AWS.

- `DenyEnablingOutboundFederation`: only the `admin` role can turn the feature on in an account.
- `RestrictTokenAudience`: tokens can only be issued for the listed audiences. Replace them with your external services.
- `LimitTokenLifetime`: tokens are valid for at most 5 minutes.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEnablingOutboundFederation",
      "Effect": "Deny",
      "Action": "iam:EnableOutboundWebIdentityFederation",
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    },
    {
      "Sid": "RestrictTokenAudience",
      "Effect": "Deny",
      "Action": "sts:GetWebIdentityToken",
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringNotLike": {
          "sts:IdentityTokenAudience": [
            "https://api.example.com",
            "api://AzureADTokenExchange"
          ]
        }
      }
    },
    {
      "Sid": "LimitTokenLifetime",
      "Effect": "Deny",
      "Action": "sts:GetWebIdentityToken",
      "Resource": "*",
      "Condition": {
        "NumericGreaterThan": {
          "sts:DurationSeconds": "300"
        }
      }
    }
  ]
}
```

### Deny Identity Store changes when users come from an IdP

> Reference: [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples/blob/main/Deny-changes-to-security-services/Deny-IdentityStore-mutations-for-SCIM-provisioned-directories.json)

When IAM Identity Center gets its users and groups from Okta, Entra ID or Google through SCIM, the IdP is the only source of truth. Nobody should create a user or add someone to a group directly in Identity Center. That's what an attacker with access to the Identity Center admin account would do to slip into a privileged group while staying invisible in the IdP. Permission sets and account assignments (`sso:*`) are not covered here, since teams often manage them with IaC from the same account; lock those down with your own exception role if they don't.

SCIM provisioning uses its own token, not IAM, so it keeps working. Attach this to the account that is the delegated administrator for Identity Center. SCPs don't apply to the management account, so if Identity Center is administered from there, move it to a delegated admin first.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIdentityStoreChanges",
      "Effect": "Deny",
      "Action": [
        "identitystore:Create*",
        "identitystore:Delete*",
        "identitystore:Update*"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

---

## Security services

### Deny disabling security services

Keeps detection and audit tooling running after the baseline is in place. Only the `security` role, used by the security team and its automation, can change these services.

| Sid | Protects |
| :--- | :--- |
| `DenyCloudTrail` | Trails and CloudTrail Lake event data stores |
| `DenyConfig` | Recorder, delivery channel, rules, conformance packs, aggregators, remediation |
| `DenyGuardDuty` | Detector and member detectors, organization settings, filters (auto-archive), trusted IP lists, membership |
| `DenySecurityHub` | Hub, standards, controls, central configuration policies, automation rules (a rule can suppress every finding), membership |
| `DenyAccessAnalyzer` | Analyzers and archive rules that hide findings |
| `DenyMacie` | Macie session and membership |
| `DenyInspector` | Inspector scanning, configuration, suppression filters and membership |
| `DenyEventBridge` | Rules that route security alerts and their targets (replace `security-alerts-*`) |

If you use an organization trail and Control Tower, part of this is already enforced, but the SCP also covers trails and settings created outside them. [Security Hub, GuardDuty and Inspector policies](index.md#other-policy-types) in Organizations turn these services on in every account; this SCP keeps anyone from weakening them afterwards.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteEventDataStore",
        "cloudtrail:DeleteTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:StopEventDataStoreIngestion",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateEventDataStore",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/security"
        }
      }
    },
    {
      "Sid": "DenyConfig",
      "Effect": "Deny",
      "Action": [
        "config:DeleteAggregationAuthorization",
        "config:DeleteConfigRule",
        "config:DeleteConfigurationAggregator",
        "config:DeleteConfigurationRecorder",
        "config:DeleteConformancePack",
        "config:DeleteDeliveryChannel",
        "config:DeleteEvaluationResults",
        "config:DeleteOrganizationConfigRule",
        "config:DeleteRemediationConfiguration",
        "config:DeleteRetentionConfiguration",
        "config:DeleteServiceLinkedConfigurationRecorder",
        "config:DisassociateResourceTypes",
        "config:PutConfigRule",
        "config:PutConfigurationAggregator",
        "config:PutConfigurationRecorder",
        "config:PutDeliveryChannel",
        "config:PutOrganizationConfigRule",
        "config:PutRemediationConfigurations",
        "config:PutRetentionConfiguration",
        "config:StopConfigurationRecorder"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/security"
        }
      }
    },
    {
      "Sid": "DenyGuardDuty",
      "Effect": "Deny",
      "Action": [
        "guardduty:AcceptAdministratorInvitation",
        "guardduty:ArchiveFindings",
        "guardduty:CreateFilter",
        "guardduty:CreateIPSet",
        "guardduty:CreatePublishingDestination",
        "guardduty:DeclineInvitations",
        "guardduty:DeleteDetector",
        "guardduty:DeleteFilter",
        "guardduty:DeleteIPSet",
        "guardduty:DeleteMembers",
        "guardduty:DeletePublishingDestination",
        "guardduty:DeleteThreatIntelSet",
        "guardduty:DisassociateFromAdministratorAccount",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:UpdateDetector",
        "guardduty:UpdateFilter",
        "guardduty:UpdateIPSet",
        "guardduty:UpdateMalwareScanSettings",
        "guardduty:UpdateMemberDetectors",
        "guardduty:UpdateOrganizationConfiguration",
        "guardduty:UpdatePublishingDestination",
        "guardduty:UpdateThreatIntelSet"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/security"
        }
      }
    },
    {
      "Sid": "DenySecurityHub",
      "Effect": "Deny",
      "Action": [
        "securityhub:BatchDeleteAutomationRules",
        "securityhub:BatchDisableStandards",
        "securityhub:BatchUpdateAutomationRules",
        "securityhub:BatchUpdateStandardsControlAssociations",
        "securityhub:CreateAutomationRule",
        "securityhub:DeleteConfigurationPolicy",
        "securityhub:DeleteInvitations",
        "securityhub:DeleteMembers",
        "securityhub:DisableImportFindingsForProduct",
        "securityhub:DisableSecurityHub",
        "securityhub:DisableSecurityHubV2",
        "securityhub:DisassociateFromAdministratorAccount",
        "securityhub:DisassociateFromMasterAccount",
        "securityhub:DisassociateMembers",
        "securityhub:UpdateConfigurationPolicy",
        "securityhub:UpdateOrganizationConfiguration",
        "securityhub:UpdateSecurityHubConfiguration",
        "securityhub:UpdateStandardsControl"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/security"
        }
      }
    },
    {
      "Sid": "DenyAccessAnalyzer",
      "Effect": "Deny",
      "Action": [
        "access-analyzer:ApplyArchiveRule",
        "access-analyzer:CreateArchiveRule",
        "access-analyzer:DeleteAnalyzer",
        "access-analyzer:DeleteArchiveRule",
        "access-analyzer:UpdateArchiveRule",
        "access-analyzer:UpdateFindings"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/security"
        }
      }
    },
    {
      "Sid": "DenyMacie",
      "Effect": "Deny",
      "Action": [
        "macie2:DeleteMember",
        "macie2:DisableMacie",
        "macie2:DisableOrganizationAdminAccount",
        "macie2:DisassociateFromAdministratorAccount",
        "macie2:DisassociateMember",
        "macie2:UpdateMacieSession",
        "macie2:UpdateMemberSession"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/security"
        }
      }
    },
    {
      "Sid": "DenyInspector",
      "Effect": "Deny",
      "Action": [
        "inspector2:CreateFilter",
        "inspector2:Disable",
        "inspector2:DisableDelegatedAdminAccount",
        "inspector2:DisassociateMember",
        "inspector2:UpdateConfiguration",
        "inspector2:UpdateOrganizationConfiguration"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/security"
        }
      }
    },
    {
      "Sid": "DenyEventBridge",
      "Effect": "Deny",
      "Action": [
        "events:DeleteRule",
        "events:DisableRule",
        "events:PutRule",
        "events:PutTargets",
        "events:RemoveTargets"
      ],
      "Resource": "arn:aws:events:*:*:rule/security-alerts-*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/security"
        }
      }
    }
  ]
}
```

---

## Data protection

### Enforce the resource perimeter

> Reference: [AWS data perimeter examples](https://github.com/aws-samples/data-perimeter-policy-examples/blob/main/service_control_policies/resource_perimeter_scp.json)

The [identity perimeter RCP](aws-rcp-examples.md#enforce-the-identity-perimeter) keeps outsiders away from your data. This is the other direction: your principals can only use S3, SQS, KMS, Secrets Manager and DynamoDB resources that belong to your organization or to `222222222222`. Credentials stolen from inside can't copy data to a bucket the attacker owns.

- Tag a role `dp:exclude:resource = true` to exempt it. Protect that tag so only the platform team can set it.
- Some AWS features read from AWS-owned buckets with your credentials, for example SSM Agent and Patch Manager downloads. Attach to a test OU first and look for `AccessDenied` on buckets you don't own in CloudTrail.
- The official example also covers AWS-owned resources in other services (ECR images for EKS add-ons, SSM documents, Lambda layers). Use it if you want `Action: "*"`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceResourcePerimeter",
      "Effect": "Deny",
      "Action": [
        "dynamodb:*",
        "kms:*",
        "s3:*",
        "secretsmanager:*",
        "sqs:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:ResourceOrgID": "o-xxxxxxxxxx",
          "aws:ResourceAccount": [
            "222222222222"
          ],
          "aws:PrincipalTag/dp:exclude:resource": "true"
        }
      }
    }
  ]
}
```

### Protect data perimeter tags

The data perimeter policies use tags as switches: `dp:exclude:*` takes a role or resource out of a perimeter and `dp:include:network` puts a role in. If anyone can set them, anyone can opt out. This denies adding or removing any `dp:*` tag on roles and on the resources the RCPs cover, including tags passed when the resource is created, except for `admin` and the StackSets baseline. The [Protect security tags](aws-rcp-examples.md#protect-security-tags) RCP blocks the same tags as session tags, which would otherwise override the role's own.

S3 has a gap: `s3:PutBucketTagging`, the API most tools use, doesn't support `aws:TagKeys`, so a bucket can still be tagged. That alone doesn't expose it, because sharing a bucket also takes a bucket policy change, which [Protect S3 bucket security settings](aws-rcp-examples.md#protect-s3-bucket-security-settings) limits to `admin` and `iac-deploy`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPerimeterTagChanges",
      "Effect": "Deny",
      "Action": [
        "dynamodb:CreateTable",
        "dynamodb:TagResource",
        "dynamodb:UntagResource",
        "ecr:CreateRepository",
        "ecr:TagResource",
        "ecr:UntagResource",
        "iam:CreateRole",
        "iam:TagRole",
        "iam:UntagRole",
        "kms:CreateKey",
        "kms:TagResource",
        "kms:UntagResource",
        "logs:CreateLogGroup",
        "logs:TagLogGroup",
        "logs:TagResource",
        "logs:UntagLogGroup",
        "logs:UntagResource",
        "s3:CreateBucket",
        "s3:TagResource",
        "s3:UntagResource",
        "secretsmanager:CreateSecret",
        "secretsmanager:TagResource",
        "secretsmanager:UntagResource",
        "sqs:CreateQueue",
        "sqs:TagQueue",
        "sqs:UntagQueue"
      ],
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringLike": {
          "aws:TagKeys": "dp:*"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/stacksets-exec-*"
          ]
        }
      }
    }
  ]
}
```

### Deny public secrets

> Reference: [Rami McCarthy - SCPs](https://rami.wiki/scps/)

Secrets Manager only checks whether a resource policy makes a secret public when `BlockPublicPolicy=true` is sent with `PutResourcePolicy`, and by default it isn't. This SCP makes the check mandatory, so no one can attach a resource policy that exposes a secret publicly.

`BoolIfExists` matters here: requests that don't send the parameter at all are denied too, which is the default in the CLI and SDKs. Scripts and templates have to set it to `true`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicSecretPolicy",
      "Effect": "Deny",
      "Action": "secretsmanager:PutResourcePolicy",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "secretsmanager:BlockPublicPolicy": "false"
        }
      }
    }
  ]
}
```

### Protect S3 account-level Block Public Access

Prevents changes to the account-level S3 Block Public Access settings. Turn them on in every account as part of the baseline before attaching this policy.

[Amazon S3 policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_s3.html) in AWS Organizations now enforce Block Public Access centrally and block account-level overrides. If you use them, this SCP is redundant.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyS3AccountPublicAccessChanges",
      "Effect": "Deny",
      "Action": "s3:PutAccountPublicAccessBlock",
      "Resource": "*"
    }
  ]
}
```

### Require S3 buckets in the account regional namespace

> Reference: [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples/blob/main/Service-specific-controls/Amazon-S3/enforce-s3-bucket-namespace.json)

Since March 2026, S3 supports [account regional namespaces](https://docs.aws.amazon.com/AmazonS3/latest/userguide/gpbucketnamespaces.html) for general purpose buckets (names end in `-<account-id>-<region>-an`). Only your account can create buckets in that namespace, which ends bucket squatting: an attacker can no longer pre-register a bucket name your code or templates expect.

This policy denies creating new buckets in the global namespace. Existing buckets are not affected.

Anything that creates buckets with your credentials and a global name stops working until it supports the new namespace: IaC modules with fixed bucket names, `cdk bootstrap`, and console flows that create buckets for you (CloudFormation templates, Athena results, SageMaker defaults). Start with the accounts where teams create few buckets, or exempt the `iac-deploy` role while modules are updated.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireAccountRegionalBucketNamespace",
      "Effect": "Deny",
      "Action": "s3:CreateBucket",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "s3:x-amz-bucket-namespace": "account-regional"
        }
      }
    }
  ]
}
```

### Deny external resource sharing with RAM

> Reference: [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples/blob/main/Sensitive-data-protection/Deny-RAM-from-sharing-resources-to-external-accounts.json)

- `DenyExternalSharesOnCreate`: `allowExternalPrincipals` [defaults to true](https://docs.aws.amazon.com/ram/latest/APIReference/API_CreateResourceShare.html), so creating a share is denied unless the request sets it to `false`.
- `DenyExternalSharesOnUpdate`: turning on external principals for an existing share.
- `DenyAddingToExternalShares`: adding principals or resources to a share that already allows external principals.
- `DenyShareInvitations`: blocks accepting share invitations. With RAM sharing enabled for the organization, shares between your own accounts don't use invitations, so this only blocks shares coming from outside.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExternalSharesOnCreate",
      "Effect": "Deny",
      "Action": "ram:CreateResourceShare",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "ram:RequestedAllowsExternalPrincipals": "true"
        }
      }
    },
    {
      "Sid": "DenyExternalSharesOnUpdate",
      "Effect": "Deny",
      "Action": "ram:UpdateResourceShare",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "ram:RequestedAllowsExternalPrincipals": "true"
        }
      }
    },
    {
      "Sid": "DenyAddingToExternalShares",
      "Effect": "Deny",
      "Action": "ram:AssociateResourceShare",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "ram:AllowsExternalPrincipals": "true"
        }
      }
    },
    {
      "Sid": "DenyShareInvitations",
      "Effect": "Deny",
      "Action": "ram:AcceptResourceShareInvitation",
      "Resource": "*"
    }
  ]
}
```

### Protect AWS Backup

> Reference: [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples/blob/main/Sensitive-data-protection/Deny-AWS-Backup-deletion-and-changes-to-configuration.json)

Deleting backups is a standard step in ransomware playbooks. This blocks deletion and changes to plans, vaults and recovery points for everyone except the `admin` role.

For stronger protection use [Backup Vault Lock](https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html) in compliance mode (not even root can delete) and [logically air-gapped vaults](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyBackupChanges",
      "Effect": "Deny",
      "Action": [
        "backup:DeleteBackupPlan",
        "backup:DeleteBackupSelection",
        "backup:DeleteBackupVault",
        "backup:DeleteBackupVaultAccessPolicy",
        "backup:DeleteBackupVaultLockConfiguration",
        "backup:DeleteBackupVaultNotifications",
        "backup:DeleteRecoveryPoint",
        "backup:PutBackupVaultAccessPolicy",
        "backup:PutBackupVaultNotifications",
        "backup:UpdateBackupPlan",
        "backup:UpdateRecoveryPointLifecycle",
        "backup:UpdateRegionSettings"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

### Require encryption on new RDS instances

Since February 2026, [new Aurora clusters are encrypted by default](https://aws.amazon.com/about-aws/whats-new/2026/02/amazon-aurora-server-side-encryption-at-rest). RDS instances (MySQL, PostgreSQL, MariaDB, Oracle, SQL Server, Db2) are not: without `StorageEncrypted=true` the instance is created unencrypted, and encryption can't be turned on later without a snapshot copy and restore.

Aurora, DocumentDB and Neptune instances are excluded because they inherit encryption from the cluster. Requests that omit `StorageEncrypted` are denied too, so templates have to set it. Read replicas and restores inherit encryption from the source and aren't covered: an unencrypted snapshot still restores unencrypted.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireRdsEncryption",
      "Effect": "Deny",
      "Action": [
        "rds:CreateDBInstance",
        "rds:RestoreDBInstanceFromS3"
      ],
      "Resource": "arn:aws:rds:*:*:db:*",
      "Condition": {
        "BoolIfExists": {
          "rds:StorageEncrypted": "false"
        },
        "StringNotLike": {
          "rds:DatabaseEngine": [
            "aurora*",
            "docdb",
            "neptune"
          ]
        }
      }
    }
  ]
}
```

### Deny publishing to Amazon ECR Public

Amazon ECR Public repositories are readable by anyone on the internet. An internal image pushed there by mistake leaks code, dependencies and sometimes credentials baked into layers. Pulling public images is not affected.

If you publish open source images, do it from a dedicated account and keep that account in an OU without this policy.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEcrPublicPublishing",
      "Effect": "Deny",
      "Action": [
        "ecr-public:CompleteLayerUpload",
        "ecr-public:CreateRepository",
        "ecr-public:InitiateLayerUpload",
        "ecr-public:PutImage",
        "ecr-public:PutRegistryCatalogData",
        "ecr-public:PutRepositoryCatalogData",
        "ecr-public:SetRepositoryPolicy",
        "ecr-public:UploadLayerPart"
      ],
      "Resource": "*"
    }
  ]
}
```

### Deny sharing snapshots and AMIs with other accounts

Block public access stops snapshots and AMIs from being made public, but sharing them with one specific account is still allowed. That's one of the simplest ways to take a whole disk or database out of an account: share it with an account you control, copy it there, done. The resource perimeter doesn't help, because the snapshot still belongs to you.

- `DenySnapshotAndImageSharing`: the sharing actions for EBS snapshots, AMIs, and RDS, Aurora and Redshift snapshots are denied entirely. Conditions can't reliably tell sharing apart from other changes here: for AMIs, the EC2 condition keys [can't see the launch permission being added](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-for-amazon-ec2.html#attribute-key). The side effect is that changing an AMI's description also needs an exception role.
- `DenyImageExport`: exporting an instance or AMI to an S3 bucket is another way to copy a whole disk out.

AWS Backup uses these same actions for cross-account copies, through its service role (see `EC2ModifyPermissions` in [AWSBackupServiceRolePolicyForBackup](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSBackupServiceRolePolicyForBackup.html)), so the default Backup role is exempted. Cross-account copies only work inside the organization, so this doesn't open a way out. If you use a custom Backup role, Data Lifecycle Manager or an image pipeline that shares golden AMIs, add their roles too, and lock them in [Protect critical IAM roles](#protect-critical-iam-roles).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySnapshotAndImageSharing",
      "Effect": "Deny",
      "Action": [
        "ec2:ModifyImageAttribute",
        "ec2:ModifySnapshotAttribute",
        "rds:ModifyDBClusterSnapshotAttribute",
        "rds:ModifyDBSnapshotAttribute",
        "redshift:AuthorizeSnapshotAccess"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/service-role/AWSBackupDefaultServiceRole"
          ]
        }
      }
    },
    {
      "Sid": "DenyImageExport",
      "Effect": "Deny",
      "Action": [
        "ec2:CreateInstanceExportTask",
        "ec2:CreateStoreImageTask",
        "ec2:ExportImage"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

### Deny KMS keys with external key material

A known ransomware technique with KMS: create a key with imported key material, re-encrypt data with it, then delete the material. AWS can't recover the key, so only the attacker, who kept a copy, can decrypt. An external key store does the same with a key outside AWS.

Most organizations never need either. This denies creating keys with external material or in an external key store, importing material, and managing custom key stores, except for the `admin` role. It also denies creating a key with the lockout safety check bypassed, which can leave a key nobody can manage. That one has to be in an SCP: `CreateKey` has no resource yet, so RCPs don't apply to it. Using a key from another account for the same trick is blocked by the [resource perimeter](#enforce-the-resource-perimeter).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExternalKeyOrigin",
      "Effect": "Deny",
      "Action": "kms:CreateKey",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:KeyOrigin": [
            "EXTERNAL",
            "EXTERNAL_KEY_STORE"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    },
    {
      "Sid": "DenyKeyMaterialImport",
      "Effect": "Deny",
      "Action": [
        "kms:ConnectCustomKeyStore",
        "kms:CreateCustomKeyStore",
        "kms:DeleteCustomKeyStore",
        "kms:ImportKeyMaterial",
        "kms:UpdateCustomKeyStore"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    },
    {
      "Sid": "DenyLockoutSafetyBypass",
      "Effect": "Deny",
      "Action": "kms:CreateKey",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "kms:BypassPolicyLockoutSafetyCheck": "true"
        }
      }
    }
  ]
}
```

---

## Compute

### Require IMDSv2 on EC2 instances

> Reference: [AWS Organizations docs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_ec2.html)

- `RequireImdsV2`: instances must be launched with `HttpTokens=required`.
- `LimitImdsHopLimit`: hop limit of at most 3 (containers on the instance need 2).
- `DenyImdsV1Credentials`: requests signed with credentials obtained through IMDSv1 are denied.
- `DenyMetadataOptionChanges`: only the `admin` role in account `111111111111` can change metadata options on running instances or the account defaults.

The [EC2 declarative policy](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_declarative_syntax.html) can also enforce IMDSv2 as the account default without relying on API-level denies.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireImdsV2",
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
      "Sid": "LimitImdsHopLimit",
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
      "Sid": "DenyImdsV1Credentials",
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
      "Sid": "DenyMetadataOptionChanges",
      "Effect": "Deny",
      "Action": [
        "ec2:ModifyInstanceMetadataDefaults",
        "ec2:ModifyInstanceMetadataOptions"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::111111111111:role/admin"
        }
      }
    }
  ]
}
```

### Protect EC2 and SSM account-level settings

These account settings are usually turned on once in the baseline and should never be turned off:

- EBS encryption by default, and its default KMS key (pointing it to a key the attacker controls, or one about to be deleted, is a known ransomware trick)
- Block public access for AMIs and EBS snapshots
- EC2 serial console access (kept disabled)
- Public sharing of SSM documents (kept blocked)

Turn on the settings before attaching the policy. Only the `admin` role can change the EC2 settings afterwards. The [EC2 declarative policy](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_declarative_syntax.html) enforces most of these directly in the service and is preferred where you can use it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEc2SecuritySettingChanges",
      "Effect": "Deny",
      "Action": [
        "ec2:DisableEbsEncryptionByDefault",
        "ec2:DisableImageBlockPublicAccess",
        "ec2:DisableSnapshotBlockPublicAccess",
        "ec2:EnableSerialConsoleAccess",
        "ec2:ModifyEbsDefaultKmsKeyId"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    },
    {
      "Sid": "DenySsmDocumentPublicSharing",
      "Effect": "Deny",
      "Action": [
        "ssm:ResetServiceSetting",
        "ssm:UpdateServiceSetting"
      ],
      "Resource": "arn:aws:ssm:*:*:servicesetting/ssm/documents/console/public-sharing-permission"
    }
  ]
}
```

### Require IAM auth on Lambda function URLs

> Reference: [Asecure Cloud](https://asecure.cloud/a/scp_lambda_open_url/)

A function URL with `AuthType=NONE` is a public HTTPS endpoint. This denies creating or updating function URLs without IAM auth, and adding resource policy statements that open an existing URL to the public.

The condition matches on `NONE` instead of "not `AWS_IAM`" so regular `lambda:AddPermission` calls, which don't carry this key, are not affected. Function URLs that already use `NONE` are not changed, so find them before attaching (`aws lambda list-function-url-configs`).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicFunctionUrls",
      "Effect": "Deny",
      "Action": [
        "lambda:AddPermission",
        "lambda:CreateFunctionUrlConfig",
        "lambda:UpdateFunctionUrlConfig"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "lambda:FunctionUrlAuthType": "NONE"
        }
      }
    }
  ]
}
```

### Require Session Manager instead of SSH keys

SSH key pairs are long-term credentials that live on laptops and never expire. EC2 Instance Connect is worse in one way: anyone with `ec2-instance-connect:SendSSHPublicKey` can push a key to any instance and log in as any OS user, which makes it a common path for lateral movement. Session Manager gives the same shell with IAM authentication, no open port 22 and every session logged.

This denies creating or importing key pairs and pushing keys with Instance Connect, including to the serial console. Key pairs that already exist keep working, so clean them up separately. SSH through an EC2 Instance Connect Endpoint also needs a key, so it stops working as well. Windows instances launched without a key pair can't have their Administrator password retrieved with `GetPasswordData`; use Session Manager or Fleet Manager for them.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySshKeys",
      "Effect": "Deny",
      "Action": [
        "ec2-instance-connect:SendSerialConsoleSSHPublicKey",
        "ec2-instance-connect:SendSSHPublicKey",
        "ec2:CreateKeyPair",
        "ec2:ImportKeyPair"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

---

## Logging

### Deny log deletion

Deleting logs is how an attacker covers their tracks. This protects VPC Flow Logs and CloudWatch Logs, including the subscription filters and account-level policies that forward logs to a SIEM. Changing a retention or a subscription filter is blocked as well: a one-day retention has the same effect as deleting, and rewriting a filter quietly sends the logs somewhere else.

Infrastructure as code usually needs to delete log groups and set their retention, so the `iac-deploy` role is exempted. With AWS CDK, deployments run as the bootstrap role `cdk-*-cfn-exec-role-*`. If you add it, also add it to [Protect critical IAM roles](#protect-critical-iam-roles), and keep in mind that anyone who can pass it to CloudFormation gets the exception. The CDK `logRetention` property sets retention from a Lambda function with its own role, which gets denied; define the log group explicitly so CloudFormation sets the retention instead. For a stricter version, scope `Resource` to the log groups that matter (for example `arn:aws:logs:*:*:log-group:/security/*`) and remove the exceptions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLogDeletion",
      "Effect": "Deny",
      "Action": [
        "ec2:DeleteFlowLogs",
        "logs:DeleteAccountPolicy",
        "logs:DeleteLogGroup",
        "logs:DeleteLogStream",
        "logs:DeleteSubscriptionFilter",
        "logs:PutRetentionPolicy",
        "logs:PutSubscriptionFilter"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/iac-deploy"
          ]
        }
      }
    }
  ]
}
```

---

## Network

### Restrict network changes to the network team

Only the `network` role can change VPC topology, routing, internet exposure, hybrid connectivity and DNS. This covers what is typically owned by a central network team:

- `DenyVpcChanges`: VPCs, subnets, route tables, NACLs, internet/NAT gateways, peering, Transit Gateway attachments, VPN, VPC Block Public Access and Global Accelerator.
- `DenyDnsChanges`: Route 53 hosted zones, records, Resolver and domain registration.

DHCP options and VPC endpoints are included: DHCP options can point a VPC's DNS anywhere, and gateway endpoints write routes. If application teams create their own interface endpoints, remove `ec2:CreateVpcEndpoint` and `ec2:ModifyVpcEndpoint`. Security groups are left out on purpose: application teams usually manage their own. If you allow application teams to manage DNS records, remove `route53:ChangeResourceRecordSets` (matched by `route53:Change*`).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyVpcChanges",
      "Effect": "Deny",
      "Action": [
        "ec2:AcceptTransitGatewayPeeringAttachment",
        "ec2:AcceptVpcPeeringConnection",
        "ec2:AssociateDhcpOptions",
        "ec2:AssociateRouteTable",
        "ec2:AttachInternetGateway",
        "ec2:CreateCustomerGateway",
        "ec2:CreateDefaultSubnet",
        "ec2:CreateDefaultVpc",
        "ec2:CreateDhcpOptions",
        "ec2:CreateEgressOnlyInternetGateway",
        "ec2:CreateInternetGateway",
        "ec2:CreateNatGateway",
        "ec2:CreateNetworkAcl",
        "ec2:CreateNetworkAclEntry",
        "ec2:CreateRoute",
        "ec2:CreateRouteTable",
        "ec2:CreateSubnet",
        "ec2:CreateTransitGatewayVpcAttachment",
        "ec2:CreateVpc",
        "ec2:CreateVpcBlockPublicAccessExclusion",
        "ec2:CreateVpcEndpoint",
        "ec2:CreateVpcPeeringConnection",
        "ec2:CreateVpnConnection",
        "ec2:CreateVpnGateway",
        "ec2:DeleteNatGateway",
        "ec2:DeleteNetworkAcl",
        "ec2:DeleteNetworkAclEntry",
        "ec2:DeleteRoute",
        "ec2:DeleteRouteTable",
        "ec2:DeleteSubnet",
        "ec2:DeleteVpc",
        "ec2:DetachInternetGateway",
        "ec2:DisassociateRouteTable",
        "ec2:ModifySubnetAttribute",
        "ec2:ModifyVpcAttribute",
        "ec2:ModifyVpcBlockPublicAccessOptions",
        "ec2:ModifyVpcEndpoint",
        "ec2:ReplaceNetworkAclAssociation",
        "ec2:ReplaceNetworkAclEntry",
        "ec2:ReplaceRoute",
        "ec2:ReplaceRouteTableAssociation",
        "globalaccelerator:Add*",
        "globalaccelerator:Create*",
        "globalaccelerator:Update*"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/network"
        }
      }
    },
    {
      "Sid": "DenyDnsChanges",
      "Effect": "Deny",
      "Action": [
        "route53:Change*",
        "route53:Create*",
        "route53:Delete*",
        "route53:Disassociate*",
        "route53domains:DisableDomainAutoRenew",
        "route53domains:EnableDomainAutoRenew",
        "route53domains:RegisterDomain",
        "route53domains:TransferDomain*",
        "route53domains:UpdateDomainNameservers",
        "route53resolver:Associate*",
        "route53resolver:Create*",
        "route53resolver:Delete*",
        "route53resolver:Disassociate*",
        "route53resolver:Update*"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/network"
        }
      }
    }
  ]
}
```

### Deny public RDS instances and EKS endpoints

Databases and Kubernetes API servers reachable from the internet are a frequent finding in breach reports. This denies creating RDS instances with `PubliclyAccessible=true` and EKS clusters with a public API endpoint.

- When `PubliclyAccessible` is omitted, RDS decides based on the subnets, so the statement also denies requests that don't set it. Templates have to set it to `false`. DocumentDB and Neptune also use the RDS API but can't be public and don't take the parameter, so they are excluded by engine. AWS Backup restores through its service role without setting the parameter, so that role is exempted.
- `Resource` is limited to DB instances. `CreateDBInstance` also authorizes parameter, option and subnet groups, which don't carry these keys, so a `*` resource could deny every request.
- EKS creates a public endpoint when `endpointPublicAccess` is omitted, so `CreateCluster` uses `BoolIfExists` for the same reason. `UpdateClusterConfig` uses `Bool` so updates that don't touch the endpoint keep working. If you use public endpoints restricted to a few CIDRs, this policy is not for you.
- `rds:ModifyDBInstance` doesn't support `rds:PubliclyAccessible`, so an existing instance can still be made public. Use the Config rule `rds-instance-public-access-check` to catch that.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicRdsInstances",
      "Effect": "Deny",
      "Action": [
        "rds:CreateDBInstance",
        "rds:CreateDBInstanceReadReplica",
        "rds:RestoreDBInstanceFromDBSnapshot",
        "rds:RestoreDBInstanceFromS3",
        "rds:RestoreDBInstanceToPointInTime"
      ],
      "Resource": "arn:aws:rds:*:*:db:*",
      "Condition": {
        "BoolIfExists": {
          "rds:PubliclyAccessible": "true"
        },
        "StringNotLike": {
          "rds:DatabaseEngine": [
            "docdb",
            "neptune"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/service-role/AWSBackupDefaultServiceRole"
        }
      }
    },
    {
      "Sid": "DenyPublicEksEndpointOnCreate",
      "Effect": "Deny",
      "Action": "eks:CreateCluster",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "eks:endpointPublicAccess": "true"
        }
      }
    },
    {
      "Sid": "DenyPublicEksEndpointOnUpdate",
      "Effect": "Deny",
      "Action": "eks:UpdateClusterConfig",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "eks:endpointPublicAccess": "true"
        }
      }
    }
  ]
}
```

### Restrict Identity Center sessions to expected networks

> Reference: [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples/blob/main/Protect-cloud-platform-resource/Deny-use-of-IAM-Identity-Center-credentials-from-unexpected-networks.json)

Phishing kits and infostealers no longer go after passwords. They take the session after MFA, and an Identity Center session works from anywhere until it expires. This denies requests made with Identity Center roles unless they come from the corporate CIDR or through VPC endpoints in your VPCs, so a stolen session is useless outside your network.

- Calls that AWS services make on your behalf (`aws:ViaAWSService`) are not affected.
- As in the AWS example, data plane actions such as `rds-db:connect`, EFS client access and OpenSearch requests are left out in `NotAction`. Access to those is already limited by the network of the database or file system.
- Only Identity Center roles are matched, so workloads and pipelines are not affected. Remote users need the VPN, so plan for it before attaching.
- Include your IPv6 ranges if the network has IPv6. Many AWS endpoints are dual-stack, and the request may reach AWS over IPv6.
- `aws:SourceVpc` is only present when the request goes through a VPC endpoint. Requests from a VPC that leave through a NAT gateway (jump hosts, WorkSpaces) show the NAT's public IP, so add those Elastic IPs to `aws:SourceIp`.
- AWS CloudShell sends requests from AWS's own addresses, so it stops working unless you run it in a VPC environment that reaches AWS through VPC endpoints or a NAT listed above.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceNetworkPerimeterOnIdentityCenterSessions",
      "Effect": "Deny",
      "NotAction": [
        "dax:BatchGetItem",
        "dax:BatchWriteItem",
        "dax:ConditionCheckItem",
        "dax:DeleteItem",
        "dax:GetItem",
        "dax:PutItem",
        "dax:Query",
        "dax:Scan",
        "dax:UpdateItem",
        "elasticfilesystem:Client*",
        "es:ES*",
        "kafka-cluster:*",
        "neptune-db:*",
        "rds-db:connect"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:ViaAWSService": "false"
        },
        "NotIpAddressIfExists": {
          "aws:SourceIp": "203.0.113.0/24"
        },
        "StringNotEqualsIfExists": {
          "aws:SourceVpc": "vpc-0123456789abcdef0"
        },
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*"
        }
      }
    }
  ]
}
```

---

## Messaging

### Restrict Amazon SES setup

After crypto mining, the most common use of leaked AWS keys is sending spam and phishing through Amazon SES. Attackers verify their own domain or address, request production access and start sending, and your account's reputation pays for it.

This denies verifying new identities, requesting production access and turning sending back on after AWS pauses it, except for the `admin` role. Accounts that already send email keep working, since sending itself is not blocked. In accounts that never send email, deny `ses:*` instead.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySesSetup",
      "Effect": "Deny",
      "Action": [
        "ses:CreateEmailIdentity",
        "ses:PutAccountDetails",
        "ses:PutAccountSendingAttributes",
        "ses:UpdateAccountSendingEnabled",
        "ses:VerifyDomainDkim",
        "ses:VerifyDomainIdentity",
        "ses:VerifyEmailAddress",
        "ses:VerifyEmailIdentity"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

---

## Cost and billing

### Restrict billing changes

> Reference: [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples/blob/main/Privileged-access-controls/Deny-billing-modification-action.json)

Only the `finops` role can change billing preferences, payment methods, tax settings and invoice delivery.

The old `aws-portal:Modify*` actions were retired in 2023 and no longer control access. Use the fine-grained `billing`, `payments`, `tax` and `invoicing` actions below.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyBillingChanges",
      "Effect": "Deny",
      "Action": [
        "billing:PutContractInformation",
        "billing:UpdateBillingPreferences",
        "billing:UpdateIAMAccessPreference",
        "invoicing:PutInvoiceEmailDeliveryPreferences",
        "payments:DeletePaymentInstrument",
        "payments:UpdatePaymentPreferences",
        "tax:BatchPutTaxRegistration",
        "tax:DeleteTaxRegistration",
        "tax:PutTaxInheritance"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/finops"
        }
      }
    }
  ]
}
```

### Deny long-term commitments

Reserved Instances, Savings Plans and Shield Advanced are 1 to 3 year commitments that can't be cancelled. Capacity Blocks, Bedrock provisioned throughput and SageMaker training plans are shorter, but they are paid upfront or by the hour whether you use them or not, and GPU capacity is expensive. Purchases should go through FinOps, not whoever has `AdministratorAccess` in a workload account.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCommitmentPurchases",
      "Effect": "Deny",
      "Action": [
        "bedrock:CreateProvisionedModelThroughput",
        "dynamodb:PurchaseReservedCapacityOfferings",
        "ec2:AcceptReservedInstancesExchangeQuote",
        "ec2:PurchaseCapacityBlock",
        "ec2:PurchaseCapacityBlockExtension",
        "ec2:PurchaseHostReservation",
        "ec2:PurchaseReservedInstancesOffering",
        "elasticache:PurchaseReservedCacheNodesOffering",
        "es:PurchaseReservedInstanceOffering",
        "memorydb:PurchaseReservedNodesOffering",
        "rds:PurchaseReservedDBInstancesOffering",
        "redshift:PurchaseReservedNodeOffering",
        "sagemaker:CreateTrainingPlan",
        "sagemaker:ExtendTrainingPlan",
        "savingsplans:CreateSavingsPlan",
        "shield:CreateSubscription"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/finops"
        }
      }
    }
  ]
}
```

### Restrict expensive instance types

The first thing done with leaked AWS keys is usually crypto mining on the largest GPU instances the account can launch, in every Region. This denies GPU, accelerator and FPGA families, bare metal and very large sizes on EC2 and SageMaker, except for the `admin` role.

- `StartInstances` is included so a stopped instance can't be changed to a blocked type and started.
- Adjust the list to what your teams actually use. A data science OU, for example, can get a version without `g*`.
- EC2 Auto Scaling and other services that launch instances with a service-linked role are not covered, since SCPs don't apply to service-linked roles. The Config rule `desired-instance-type` catches those instances after launch.
- Miners also use services you may not watch, such as Lightsail, Batch and ECS. If no team uses Lightsail, deny `lightsail:*` as well.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExpensiveEc2Types",
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances",
        "ec2:StartInstances"
      ],
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringLike": {
          "ec2:InstanceType": [
            "dl*",
            "f*",
            "g*",
            "inf*",
            "p*",
            "trn*",
            "u*-*",
            "vt*",
            "*.metal*",
            "*.24xlarge",
            "*.32xlarge",
            "*.48xlarge",
            "*.96xlarge"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    },
    {
      "Sid": "DenyExpensiveSageMakerTypes",
      "Effect": "Deny",
      "Action": [
        "sagemaker:CreateApp",
        "sagemaker:CreateCluster",
        "sagemaker:CreateDomain",
        "sagemaker:CreateEndpointConfig",
        "sagemaker:CreateHyperParameterTuningJob",
        "sagemaker:CreateNotebookInstance",
        "sagemaker:CreateProcessingJob",
        "sagemaker:CreateSpace",
        "sagemaker:CreateTrainingJob",
        "sagemaker:CreateTransformJob",
        "sagemaker:UpdateCluster",
        "sagemaker:UpdateDomain",
        "sagemaker:UpdateNotebookInstance"
      ],
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringLike": {
          "sagemaker:InstanceTypes": [
            "ml.g*",
            "ml.inf*",
            "ml.p*",
            "ml.trn*",
            "ml.*.24xlarge",
            "ml.*.32xlarge",
            "ml.*.48xlarge"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

### Require a cost allocation tag on creation

Denies creating EC2 instances, EBS volumes and RDS databases without a `CostCenter` tag in the request. Use [tag policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_tag-policies.html) to control which values are allowed.

The EC2 statements are split on purpose: `RunInstances` also authorizes the volume resource, so a combined statement would force tags on the instance's volumes as well.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireTagOnInstances",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "Null": {
          "aws:RequestTag/CostCenter": "true"
        }
      }
    },
    {
      "Sid": "RequireTagOnVolumes",
      "Effect": "Deny",
      "Action": "ec2:CreateVolume",
      "Resource": "arn:aws:ec2:*:*:volume/*",
      "Condition": {
        "Null": {
          "aws:RequestTag/CostCenter": "true"
        }
      }
    },
    {
      "Sid": "RequireTagOnDatabases",
      "Effect": "Deny",
      "Action": [
        "rds:CreateDBCluster",
        "rds:CreateDBInstance"
      ],
      "Resource": [
        "arn:aws:rds:*:*:cluster:*",
        "arn:aws:rds:*:*:db:*"
      ],
      "Condition": {
        "Null": {
          "aws:RequestTag/CostCenter": "true"
        }
      }
    }
  ]
}
```

---

## Governance

### Protect specific CloudFormation stacks

> Reference: [Asecure Cloud](https://asecure.cloud/a/scp_cloudformation/)

Only the `admin` role, the `iac-deploy` pipeline and StackSets can update or delete the baseline stacks. Name them `baseline-*`; StackSets names its stack instances `StackSet-<stackset-name>-<id>`, so a stack set called `baseline-...` is covered by the second ARN. Stack ARNs end with a generated ID (`stack/<name>/<id>`), so the resource needs the trailing `/*`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyBaselineStackChanges",
      "Effect": "Deny",
      "Action": [
        "cloudformation:CancelUpdateStack",
        "cloudformation:ContinueUpdateRollback",
        "cloudformation:CreateChangeSet",
        "cloudformation:DeleteChangeSet",
        "cloudformation:DeleteStack",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:RollbackStack",
        "cloudformation:SetStackPolicy",
        "cloudformation:UpdateStack",
        "cloudformation:UpdateTerminationProtection"
      ],
      "Resource": [
        "arn:aws:cloudformation:*:*:stack/baseline-*/*",
        "arn:aws:cloudformation:*:*:stack/StackSet-baseline-*/*"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/iac-deploy",
            "arn:aws:iam::*:role/stacksets-exec-*"
          ]
        }
      }
    }
  ]
}
```

---

## AI

### Restrict Amazon Bedrock to approved models

Uses `NotResource`, available now that SCPs support the full IAM policy language, to deny invoking any model outside the approved list. The example allows Anthropic and Amazon models, both directly and through cross-Region inference profiles.

- `DenyUnapprovedModels`: covers `InvokeModel` (also used by the Converse API) and batch inference jobs. If you use provisioned throughput, imported models, application inference profiles or Bedrock projects, add their ARNs to `NotResource`.
- `DenyBedrockApiKeys`: blocks calls authenticated with Bedrock API keys (bearer tokens), so access always goes through IAM roles.
- `DenyBedrockMantle`: Bedrock also has an OpenAI-compatible endpoint with its own IAM prefix, `bedrock-mantle`. The model check above doesn't apply to it, so it's denied entirely. If you use it, replace this statement with a condition on `bedrock-mantle:Model`.

To filter prompts and responses as well, use an [Amazon Bedrock policy](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_bedrock.html) to apply a guardrail to every model call in the organization.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnapprovedModels",
      "Effect": "Deny",
      "Action": [
        "bedrock:CreateModelInvocationJob",
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "NotResource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.*",
        "arn:aws:bedrock:*::foundation-model/amazon.*",
        "arn:aws:bedrock:*:*:inference-profile/*anthropic.*",
        "arn:aws:bedrock:*:*:inference-profile/*amazon.*",
        "arn:aws:bedrock:*:*:model-invocation-job/*"
      ]
    },
    {
      "Sid": "DenyBedrockApiKeys",
      "Effect": "Deny",
      "Action": "bedrock:CallWithBearerToken",
      "Resource": "*"
    },
    {
      "Sid": "DenyBedrockMantle",
      "Effect": "Deny",
      "Action": "bedrock-mantle:*",
      "Resource": "*"
    }
  ]
}
```

### Limit what AI agents and chat apps can do

> Reference: [aws:ViaAWSMCPService](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-viaawsmcpservice), [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples/blob/main/Service-specific-controls/Amazon-Q-Developer/Deny-actions-invoked-through-Amazon-Q-Developer-in-chat-applications-configurations.json)

When an agent uses the AWS-managed MCP Server, the server calls AWS with the user's credentials and the request carries `aws:ViaAWSMCPService = true`. This lets the same person keep full access in the console and CLI while the agent working for them can't run the actions listed below: deleting core infrastructure, any IAM change, assuming other roles, running commands on instances and reading secrets or parameters. It's a denylist, so anything not on it is still allowed; extend it with what matters in your accounts.

Chat apps have the same problem. With Amazon Q Developer in Slack or Teams, anyone in the channel can run commands with the channel's role, and a compromised chat account becomes AWS access. Those requests carry `aws:ChatbotSourceArn`, and `DenyPrivilegedActionsViaChat` keeps IAM changes, credentials, role assumption, secrets and Organizations out of reach from chat.

This only covers the AWS-managed MCP Server and Amazon Q Developer in chat apps. Local MCP servers and agents that run the AWS CLI call AWS directly and look like any other request. For those, give the agent its own role with limited permissions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDestructiveActionsViaMcp",
      "Effect": "Deny",
      "Action": [
        "cloudformation:DeleteStack",
        "dynamodb:DeleteTable",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeleteVpc",
        "ec2:TerminateInstances",
        "eks:DeleteCluster",
        "iam:Add*",
        "iam:Attach*",
        "iam:Create*",
        "iam:Delete*",
        "iam:Detach*",
        "iam:PassRole",
        "iam:Put*",
        "iam:Remove*",
        "iam:Set*",
        "iam:Tag*",
        "iam:Untag*",
        "iam:Update*",
        "iam:Upload*",
        "kms:DisableKey",
        "kms:ScheduleKeyDeletion",
        "lambda:DeleteFunction",
        "lambda:UpdateFunctionCode",
        "logs:DeleteLogGroup",
        "organizations:*",
        "rds:DeleteDBCluster",
        "rds:DeleteDBInstance",
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:PutBucketPolicy",
        "secretsmanager:DeleteSecret",
        "ssm:SendCommand",
        "ssm:StartSession",
        "sts:AssumeRole"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:ViaAWSMCPService": "true"
        }
      }
    },
    {
      "Sid": "DenySecretReadsViaMcp",
      "Effect": "Deny",
      "Action": [
        "secretsmanager:BatchGetSecretValue",
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:ViaAWSMCPService": "true"
        }
      }
    },
    {
      "Sid": "DenyPrivilegedActionsViaChat",
      "Effect": "Deny",
      "Action": [
        "iam:AddUserToGroup",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:CreatePolicyVersion",
        "iam:CreateRole",
        "iam:CreateServiceSpecificCredential",
        "iam:CreateUser",
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeleteRolePolicy",
        "iam:DeleteUserPermissionsBoundary",
        "iam:DeleteUserPolicy",
        "iam:DetachRolePolicy",
        "iam:DetachUserPolicy",
        "iam:PassRole",
        "iam:PutGroupPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:ResetServiceSpecificCredential",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAccessKey",
        "iam:UpdateAssumeRolePolicy",
        "organizations:*",
        "secretsmanager:GetSecretValue",
        "sts:AssumeRole"
      ],
      "Resource": "*",
      "Condition": {
        "ArnLike": {
          "aws:ChatbotSourceArn": "arn:aws:chatbot::*:*"
        }
      }
    }
  ]
}
```
