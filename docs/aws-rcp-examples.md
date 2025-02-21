# AWS RCP Examples

## Prevent cross-service confused deputy problem

Some AWS services use their service principals to interact with resources in other AWS services. When an unintended actor tries to leverage an AWS service principal's trust to access resources they shouldn't, this is known as the cross-service [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).

The following policy ensures that AWS service principals can only access your resources on behalf of requests originating from your organization. This policy applies the control only on requests that have `aws:SourceAccount` present so that service integrations that do not require the use of `aws:SourceAccount` aren't impacted. If the `aws:SourceAccount` is present in the request context, the `Null` condition will evaluate to `true`, causing the `aws:SourceOrgID` key to be enforced.

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
                        "third-party-account-a",
                        "third-party-account-b"
                    ]
                },  
                "Bool": {
                    "aws:PrincipalIsAWSService": "true"
                }
            }
        }
    ]
}
```

Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html#example-rcp-confused-deputy)

## Restrict access to only HTTPS connections to your resources

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


Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html#example-rcp-enforce-ssl)

## Enforce consistent Amazon S3 bucket policy controls

The following policy contains multiple statements to enforce consistent access controls for Amazon S3 buckets in your organization.

- Statement `EnforceS3TlsVersion`: Require a minimum TLS version of 1.2 for access to S3 buckets.
- Statement `EnforceKMSEncryption`: Require objects to be server-side encrypted with KMS keys.

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
        },
        {
            "Sid": "EnforceKMSEncryption",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "*",
            "Condition": {
                "Null": {
                    "s3:x-amz-server-side-encryption-aws-kms-key-id": "true"
                }
            }
        }
    ]
}
```

Reference: [AWS Official Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html#example-rcp-consistent-bucket)