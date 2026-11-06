# RCP Examples

Every RCP statement must be a `Deny` with `"Principal": "*"`. `RCPFullAWSAccess` stays attached and counts toward the limit of 5 RCPs per entity.

Before using them:

- Replace the placeholders: `o-xxxxxxxxxx` (organization ID), `222222222222` (trusted third-party account), `my-github-org`, `203.0.113.0/24` (corporate CIDR) and role names such as `admin` and `iac-deploy`.
- Each example is a separate policy for readability. With only 4 free RCP slots per entity, merge statements from several examples into one policy.
- RCPs only apply to [supported services](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services). An action from an unsupported service in an RCP has no effect.
- RCPs don't apply to resources in the management account, to calls made by service-linked roles, or to AWS managed KMS keys.
- Unlike SCPs, RCPs are evaluated for principals **outside** your organization too. An exception like `arn:aws:iam::*:role/admin` also matches a role named `admin` in someone else's account. Pair those policies with the [identity perimeter](#enforce-the-identity-perimeter), or use account IDs instead of `*`.
- Review [IAM Access Analyzer external access findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings-view.html) before attaching data perimeter policies. They show which resources are already shared outside the organization.

---

## Data perimeter

### Enforce the identity perimeter

> Reference: [AWS data perimeter examples](https://github.com/aws-samples/data-perimeter-policy-examples/blob/main/resource_control_policies/identity_perimeter_rcp.json)

Only principals from your organization (or from the trusted account `222222222222`) can access your resources or assume your roles, even if a bucket policy, key policy or role trust policy says otherwise. This is the RCP that stops a misconfigured resource policy from becoming a data leak.

- AWS service principals are not affected (`aws:PrincipalIsAWSService`). They are handled by the [confused deputy](#enforce-confused-deputy-protection) policy.
- `sts:AssumeRoleWithWebIdentity` and `sts:AssumeRoleWithSAML` are left out because federated users don't belong to an organization. Use the [OIDC](#restrict-oidc-federation-to-trusted-providers) policy for those.
- Tag a resource with `dp:exclude:identity = true` to exempt it, for example a bucket that intentionally shares data with a partner. Protect that tag with an SCP so only the platform team can set it.
- ELB access logs in older Regions are delivered by an AWS-owned account. If you use them, add that account to `aws:PrincipalAccount`.
- Anonymous requests have no principal account, so they are denied too. Public objects, S3 static websites and CloudFront with a legacy origin access identity (OAI) stop working. Move CloudFront to origin access control (OAC), which uses a service principal, and tag buckets that must stay public with `dp:exclude:identity`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceOrgIdentities",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "aoss:*",
        "cognito-idp:*",
        "dynamodb:*",
        "ecr:*",
        "kms:*",
        "logs:*",
        "s3:*",
        "secretsmanager:*",
        "sqs:*",
        "sts:AssumeRole",
        "sts:DecodeAuthorizationMessage",
        "sts:GetAccessKeyInfo",
        "sts:GetFederationToken",
        "sts:GetServiceBearerToken",
        "sts:GetSessionToken",
        "sts:SetContext"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": "o-xxxxxxxxxx",
          "aws:PrincipalAccount": [
            "222222222222"
          ],
          "aws:ResourceTag/dp:exclude:identity": "true"
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
  ]
}
```

### Enforce confused deputy protection

> Reference: [AWS RCP examples](https://github.com/aws-samples/resource-control-policy-examples/blob/main/Restrict-resource-access-patterns/Enforce-controls-on-AWS-services-that-use-service-principals-to-access-your-resources.json)

When an AWS service accesses your resources with its service principal (for example CloudTrail writing to a bucket or SNS sending to a queue), someone else's resource could trick the service into acting on yours. That is the [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).

This policy only lets service principals act on your resources when the request comes from your organization or from `222222222222`. Requests without `aws:SourceAccount` are not affected, since there is nothing to compare. SNS topics outside the organization that deliver to your SQS queues, such as AWS's public `AmazonIpSpaceChanged` topic or a SaaS vendor's topic, are denied; add those accounts to `aws:SourceAccount`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceConfusedDeputyProtection",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "aoss:*",
        "cognito-identity:*",
        "cognito-idp:*",
        "dynamodb:*",
        "ecr:*",
        "kms:*",
        "logs:*",
        "s3:*",
        "secretsmanager:*",
        "sqs:*",
        "sts:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:SourceOrgID": "o-xxxxxxxxxx",
          "aws:SourceAccount": [
            "222222222222"
          ],
          "aws:ResourceTag/dp:exclude:identity": "true"
        },
        "Null": {
          "aws:SourceAccount": "false"
        },
        "Bool": {
          "aws:PrincipalIsAWSService": "true"
        }
      }
    }
  ]
}
```

### Enforce the network perimeter

> Reference: [AWS data perimeter examples](https://github.com/aws-samples/data-perimeter-policy-examples/blob/main/resource_control_policies/network_perimeter_vpceorgid_rcp.json)

Denies access unless the request comes from a VPC endpoint owned by your organization or from the corporate CIDR. Stolen credentials used from a laptop on the internet stop working.

This one breaks things easily, so it ships opt-in: it only applies to principals tagged `dp:include:network = true`. Tag roles gradually and remove the condition once everything is covered.

- Requests made by AWS services on your behalf (`aws:ViaAWSService`) and by service principals are not affected.
- `aws:ec2-infrastructure` is the role EC2 uses for things like EBS encryption with KMS.
- Use `dp:exclude:network = true` on a principal or resource to exempt it.
- Only add services that support [`aws:VpceOrgID`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-vpceorgid). For the others the key is never present, so every request outside the corporate CIDR would be denied, even through your own VPC endpoints.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceNetworkPerimeter",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "cognito-identity:*",
        "ecr:*",
        "kms:*",
        "s3:*",
        "sqs:*"
      ],
      "Resource": "*",
      "Condition": {
        "NotIpAddressIfExists": {
          "aws:SourceIp": "203.0.113.0/24"
        },
        "StringNotEqualsIfExists": {
          "aws:VpceOrgID": "o-xxxxxxxxxx",
          "aws:PrincipalTag/dp:exclude:network": "true",
          "aws:ResourceTag/dp:exclude:network": "true"
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false",
          "aws:ViaAWSService": "false"
        },
        "ArnNotLikeIfExists": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/aws:ec2-infrastructure"
        },
        "StringEquals": {
          "aws:PrincipalTag/dp:include:network": "true"
        }
      }
    }
  ]
}
```

### Require HTTPS

> Reference: [AWS RCP examples](https://github.com/aws-samples/resource-control-policy-examples/blob/main/Restrict-resource-access-patterns/Restrict-access-to-only-HTTPS-connections-to-your-resources.json)

Denies any request to your resources over plain HTTP. S3 static website endpoints only speak HTTP, so a bucket served that way (directly or as a CloudFront custom origin) stops working; serve it through CloudFront with OAC instead.

All AWS API endpoints have required TLS 1.2 or later since February 2024, so a separate policy denying `s3:TlsVersion` below `1.2` no longer adds anything. If you need TLS 1.3, add a statement with `"NumericLessThan": {"s3:TlsVersion": "1.3"}` and test your clients first.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceSecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "aoss:*",
        "cognito-identity:*",
        "cognito-idp:*",
        "dynamodb:*",
        "ecr:*",
        "kms:*",
        "logs:*",
        "s3:*",
        "secretsmanager:*",
        "sqs:*",
        "sts:*"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

### Isolate production resources

> Reference: [AWS RCP examples](https://github.com/aws-samples/resource-control-policy-examples/tree/main/Establish-intra-organization-boundaries)

The identity perimeter treats every account in the organization the same. This adds a boundary inside it: resources in the production OU can only be accessed by principals from the production OU or the security OU. A compromised dev account can't read prod data even if a bucket or key policy allows it.

Attach it to the production OU. Paths come from `aws organizations list-parents` and follow the format `o-xxxxxxxxxx/r-xxxx/ou-xxxx-xxxxxxxx/`. External principals have no `aws:PrincipalOrgPaths`, so they are denied as well. If prod shares data with a third party, add an exception for that account or tag the resource. If deployment pipelines run in a separate OU and write to prod resources (artifacts in S3, images in ECR), add that OU's path too.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IsolateProductionOU",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "dynamodb:*",
        "ecr:*",
        "kms:*",
        "logs:*",
        "s3:*",
        "secretsmanager:*",
        "sqs:*"
      ],
      "Resource": "*",
      "Condition": {
        "ForAllValues:StringNotLikeIfExists": {
          "aws:PrincipalOrgPaths": [
            "o-xxxxxxxxxx/r-xxxx/ou-xxxx-prod0000/*",
            "o-xxxxxxxxxx/r-xxxx/ou-xxxx-secu0000/*"
          ]
        },
        "StringNotEqualsIfExists": {
          "aws:ResourceTag/dp:exclude:identity": "true"
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
  ]
}
```

---

## Identity federation

### Restrict OIDC federation to trusted providers

> Reference: [AWS RCP examples](https://github.com/aws-samples/resource-control-policy-examples/tree/main/Limit-access-to-trusted-OIDC-identity-providers)

GitHub Actions uses the same issuer for every customer. A role trust policy that checks only `aud` lets any GitHub repository in the world assume it. This policy rejects GitHub tokens that don't come from `my-github-org`, regardless of what the trust policy says.

- `EnforceGitHubOrg`: the `Null` check limits the statement to GitHub tokens. Without it, every other OIDC provider (EKS IRSA, GitLab, Terraform Cloud) would be denied too.
- `DenyBuiltInWebIdentityProviders`: blocks Google, Facebook, Login with Amazon and Cognito identity pools as direct web identity providers. Remove `cognito-identity.amazonaws.com` if you use Cognito identity pools.

Other SaaS providers with a shared issuer (GitLab.com, Terraform Cloud, Pulumi, Vercel) need the same treatment. AWS keeps a [list with ready-made statements](https://github.com/aws-samples/resource-control-policy-examples/blob/main/Limit-access-to-trusted-OIDC-identity-providers/Shared-Issuers.json).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceGitHubOrg",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Resource": "*",
      "Condition": {
        "StringNotLikeIfExists": {
          "token.actions.githubusercontent.com:sub": "repo:my-github-org/*"
        },
        "Null": {
          "token.actions.githubusercontent.com:sub": "false"
        }
      }
    },
    {
      "Sid": "DenyBuiltInWebIdentityProviders",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:FederatedProvider": [
            "accounts.google.com",
            "cognito-identity.amazonaws.com",
            "graph.facebook.com",
            "www.amazon.com"
          ]
        }
      }
    }
  ]
}
```

### Deny unauthenticated Cognito identity pool access

> Reference: [AWS RCP examples](https://github.com/aws-samples/resource-control-policy-examples/blob/main/Service-specific-controls/Cognito-Deny-identity-pool-unauthenticated-access.json)

Guest access in a Cognito identity pool hands out AWS credentials to anyone who knows the pool ID, which is usually embedded in a frontend. This denies credentials for unauthenticated identities in every pool.

This is AWS's own example, but the Service Authorization Reference lists no resource type for these Cognito actions, and RCPs only apply to the resources an action authorizes. Confirm with a test that a guest identity is actually denied before counting on it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnauthenticatedIdentityPoolAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "cognito-identity:GetCredentialsForIdentity",
        "cognito-identity:GetId",
        "cognito-identity:GetOpenIdToken"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "cognito-identity-unauth:IdentityPoolArn": "false"
        }
      }
    }
  ]
}
```

---

## Amazon S3

### Deny SSE-C uploads

> Reference: [AWS RCP examples](https://github.com/aws-samples/resource-control-policy-examples/blob/main/Service-specific-controls/S3-Deny-SSE-C.json)

S3 has encrypted every new object with SSE-S3 by default since January 2023, so a policy requiring the encryption header is no longer needed.

The real risk is SSE-C (customer-provided keys). Ransomware campaigns have used stolen credentials to rewrite objects with SSE-C using a key only the attacker has. Since April 2026, [S3 disables SSE-C by default](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-s3-c-encryption-setting-faq.html) on new buckets, and on existing ones in accounts that never used it. It can still be turned back on per bucket, and accounts that already had SSE-C objects kept their settings. This RCP closes it everywhere, whatever the bucket configuration says.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySSECUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption-customer-algorithm": "false"
        }
      }
    }
  ]
}
```

### Limit presigned URL lifetime

> Reference: [AWS RCP examples](https://github.com/aws-samples/resource-control-policy-examples/blob/main/Service-specific-controls/S3-Prevent-long-term-presigned-url.json)

Presigned URLs can be valid for up to 7 days and work for anyone who has the link. This denies requests whose signature is older than 1 hour (`3600000` ms), which limits how long a leaked URL stays useful.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOldPresignedUrls",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "NumericGreaterThan": {
          "s3:signatureAge": "3600000"
        }
      }
    }
  ]
}
```

### Protect S3 bucket security settings

Only the `admin` and `iac-deploy` roles can change bucket policies, bucket ACLs, ownership controls, Block Public Access, encryption, versioning, Object Lock, lifecycle and replication.

Lifecycle and replication are included because both are used in attacks: a lifecycle rule can expire every object in a day, and replication can copy data to a bucket the attacker controls. `s3:BypassGovernanceRetention` is there too, so objects under Object Lock in governance mode can't be deleted early.

Object ACL actions are left out on purpose. Uploads with an `x-amz-acl` header (CloudTrail, ELB logs and many cross-account writers send `bucket-owner-full-control`) need `s3:PutObjectAcl` and would break. Disable ACLs with `BucketOwnerEnforced` instead.

Combine with the [identity perimeter](#enforce-the-identity-perimeter) so roles with the same names in other accounts are also blocked.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyS3SecuritySettingChanges",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:BypassGovernanceRetention",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl",
        "s3:PutBucketObjectLockConfiguration",
        "s3:PutBucketOwnershipControls",
        "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketVersioning",
        "s3:PutEncryptionConfiguration",
        "s3:PutLifecycleConfiguration",
        "s3:PutReplicationConfiguration"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/admin",
            "arn:aws:iam::*:role/iac-deploy"
          ]
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
  ]
}
```

---

## AWS KMS

### Protect KMS keys

> Reference: [AWS RCP examples](https://github.com/aws-samples/resource-control-policy-examples/tree/main/Service-specific-controls)

- `DenyKeyDeletion`: deleting or disabling a key makes everything encrypted with it unreadable. Only the `admin` role can do it.
- `DenyLockoutSafetyBypass`: a key policy saved with the lockout safety check bypassed can leave the key with no one able to manage it. Creating a key that way is blocked in the [KMS SCP](aws-scp-examples.md#deny-kms-keys-with-external-key-material), since `CreateKey` has no resource for an RCP to apply to.
- `DenyGrantsForNonAWSResources`: grants give access to a key without showing up in the key policy, which makes them a quiet way to keep access. Only grants created by AWS services for their own resources (EBS, RDS and others) are allowed.
- `DenyShortDeletionWindow`: a key scheduled for deletion can be recovered until the waiting period ends. This forces the maximum of 30 days, for everyone, so there is time to notice.
- `DenyDeletingKeysInUse`: KMS tracks when each key was last used. Nobody, not even `admin`, can schedule the deletion of a key that encrypted or decrypted anything in the last 90 days, which stops both ransomware and deleting the wrong key. Disabling is left out on purpose: it can be undone, and during an incident it's how you cut off a compromised key. Some keys are used rarely (an EBS volume only uses its key when attached), so treat a long idle period as a hint, not as proof the key can go.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyKeyDeletion",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:DeleteImportedKeyMaterial",
        "kms:DisableKey",
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    },
    {
      "Sid": "DenyGrantsForNonAWSResources",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:CreateGrant",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "kms:GrantIsForAWSResource": "false",
          "aws:PrincipalIsAWSService": "false"
        }
      }
    },
    {
      "Sid": "DenyShortDeletionWindow",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:ScheduleKeyDeletion",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": {
          "kms:ScheduleKeyDeletionPendingWindowInDays": "30"
        }
      }
    },
    {
      "Sid": "DenyDeletingKeysInUse",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:ScheduleKeyDeletion",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": {
          "kms:TrailingDaysWithoutKeyUsage": "90"
        }
      }
    },
    {
      "Sid": "DenyLockoutSafetyBypass",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:PutKeyPolicy",
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

## AWS Secrets Manager

### Deny immediate secret deletion

By default a deleted secret can be restored for 7 to 30 days. `ForceDeleteWithoutRecovery` skips that window and the secret is gone for good, which is what ransomware and careless cleanup scripts do. This denies it for everyone, so a deleted secret can always be recovered.

The cost: Terraform with `recovery_window_in_days = 0` and cleanup scripts that force-delete will fail, and a pipeline that deletes and recreates a secret with the same name has to wait, because the name stays taken until the window ends.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyForceDeleteSecret",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "secretsmanager:DeleteSecret",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "secretsmanager:ForceDeleteWithoutRecovery": "true"
        }
      }
    }
  ]
}
```

---

## Tagging

### Protect security tags

When access is based on tags (ABAC) or the data perimeter uses `dp:*` tags, removing a tag can remove a restriction. This denies removing `DataClassification`, `ManagedBy` and any `dp:*` tag, except by the `admin` role. `DenyPerimeterSessionTags` blocks `dp:*` tags passed as session tags when assuming a role, since a session tag overrides the role's own tag with the same key and would let anyone opt out of the network perimeter.

Adding `dp:*` tags is blocked by the [Protect data perimeter tags](aws-scp-examples.md#protect-data-perimeter-tags) SCP, which also covers IAM roles.

- S3 is not included. `s3:PutBucketTagging` replaces the whole tag set and `aws:TagKeys` lists the tags being kept, not the ones being removed, so the check can't be expressed reliably.
- RCPs only cover supported services. For EC2, Lambda, RDS and others, use the same statement in an SCP (without `Principal`).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySecurityTagRemoval",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "dynamodb:UntagResource",
        "ecr:UntagResource",
        "kms:UntagResource",
        "logs:UntagLogGroup",
        "logs:UntagResource",
        "secretsmanager:UntagResource",
        "sqs:UntagQueue"
      ],
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringLike": {
          "aws:TagKeys": [
            "DataClassification",
            "ManagedBy",
            "dp:*"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/admin"
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    },
    {
      "Sid": "DenyPerimeterSessionTags",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "sts:TagSession",
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringLike": {
          "aws:TagKeys": "dp:*"
        }
      }
    }
  ]
}
```
