# AWS RCP Examples

## Prevent cross-service confused deputy problem
> Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html#example-rcp-confused-deputy)

Some AWS services use their service principals to interact with resources in other AWS services. When an unintended actor tries to leverage an AWS service principal's trust to access resources they shouldn't, this is known as the cross-service [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).

The following policy ensures that AWS service principals can only access your resources on behalf of requests originating from your organization (`o-1234567890`) and a trusted third party account explicitly listed (`333333333333`) and ensures that AWS services can perform these actions as well.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceConfusedDeputyProtection",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:*",
        "sqs:*",
        "kms:*",
        "secretsmanager:*",
        "sts:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:SourceOrgID": "o-1234567890",
          "aws:SourceAccount": [
            "333333333333"
          ]
        },
        "Bool": {
          "aws:PrincipalIsAWSService": "true"
        },
        "Null": {
          "aws:SourceArn": "false"
        }
      }
    }
  ]
}
```

## Restrict access to only HTTPS connections to your resources
> Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html#example-rcp-enforce-ssl)

The following policy requires that all access to your resources must occur over encrypted connections using HTTPS (TLS). Enforcing this helps mitigate the risk of attackers intercepting or altering network traffic.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceSecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "sts:*",
        "s3:*",
        "sqs:*",
        "secretsmanager:*",
        "kms:*"
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

## Enforce secure TLS connections for access to S3 buckets
> Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html#example-rcp-consistent-bucket)

Transport Layer Security (TLS) is a critical protocol for securing data in transit across networks. In AWS, ensuring that all interactions with Amazon S3 use a secure and up-to-date TLS version is essential for protecting data from potential interception or man-in-the-middle attacks.

This policy ensures that only TLS 1.2 or higher is used when accessing Amazon S3, effectively blocks outdated TLS versions for HTTPs connections.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceS3TlsVersion",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": {
          "s3:TlsVersion": [
            "1.2"
          ]
        }
      }
    }
  ]
}
```

## Enforce object settings controls to S3 buckets

Bucket S3 provides various configuration settings to control access, ownership, versioning, and compliance-related features like object retention and legal holds. However, misconfigurations settings or overly permissive bucket policies can expose sensitive data.

This policy prevents unauthorized changes to critical S3 security configurations with an exception for a admin role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyS3Settings",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketAcl",
        "s3:PutBucketOwnershipControls",
        "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketObjectLockConfiguration",
        "s3:PutBucketVersioning",
        "s3:PutObjectAcl",
        "s3:PutObjectVersionAcl",
        "s3:PutObjectLegalHold",
        "s3:PutObjectRetention"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLikeIfExists": {
          "aws:PrincipalARN":"arn:aws:iam::*:role/admin"
        }
      }
    }
  ]
}
```

## Enforce mandatory encryption to S3 buckets

Ensure that all S3 buckets use server-side encryption (SSE) to protect data at rest.

This policy denies S3 upload objects requests if they do not include Amazon S3 managed keys (SSE-S3) or AWS KMS encryption.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIncorrectEncryptionHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::*/*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
        }
      }
    },
    {
      "Sid": "DenyUnEncryptedObjectUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::<bucket_name>/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": true
        }
      }
    }
  ]
}
```
## Restrict IAM role assumption to trusted AWS accounts only

The following policy ensures that AWS IAM roles can only be assumption only by requests originating from your organization (`o-1234567890`) and a trusted third party account explicitly listed (`333333333333`) and ensures that AWS services can perform the action.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BlockUntrustedIAMAssumption",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:SourceOrgID": "o-1234567890",
          "aws:SourceAccount": [
            "333333333333"
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