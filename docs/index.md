# AWS Organizations Policies

## SCP - Service Control Policies

### About

Service Control Policies (SCPs) are authorization policies to help you to centrally manage the security of AWS accounts within an organization.

SCP provide central control over the maximum permissions available to IAM users and IAM roles in an organization. They help enforce security boundaries and ensure compliance by restricting access to specific services or actions.

### [Examples](aws-scp-examples.md)
* [Deny contact information changes](aws-scp-examples.html#deny-contact-information-changes)
* [Prevent region enable and disable actions](aws-scp-examples.html#prevent-region-enable-and-disable-actions)
* [Prevent accounts from leaving the organizations](aws-scp-examples.html#prevent-accounts-from-leaving-the-organizations)
* [Deny access to unused regions](aws-scp-examples.html#deny-access-to-unused-regions)
* [Deny sharing of resources outside the organization](aws-scp-examples.html#deny-sharing-of-resources-outside-the-organization)
* [Prevent disabling of security services](aws-scp-examples.html#prevent-disabling-of-security-services)
* [Deny creating public secrets](aws-scp-examples.html#deny-creating-public-secrets)
* [Block root user access](aws-scp-examples.html#block-root-user-access)
* [Deny critical IAM actions](aws-scp-examples.html#deny-critical-iam-actions)
* [Restrict update of critical IAM roles](aws-scp-examples.html#restrict-update-of-critical-iam-roles)
* [Protect S3 default security public access block settings](aws-scp-examples.html#protect-s3-default-security-public-access-block-settings)
* [Preventing unauthorized AWS Backup modifications](aws-scp-examples.html#preventing-unauthorized-aws-backup-modifications)
* [Require IMDSv2 enabled to launch EC2 instances](aws-scp-examples.html#require-imdsv2-enabled-to-launch-ec2-instances)
* [Protect default security settings EBS encryption](aws-scp-examples.html#protect-default-security-settings-ebs-encryption)
* [Prevent computing log deletion](aws-scp-examples.html#prevent-computing-log-deletion)
* [Enforce secure AWS lambda function URL authentication](aws-scp-examples.html#enforce-secure-aws-lambda-function-url-authentication)
* [Restrict billing modifications](aws-scp-examples.html#restrict-billing-modifications)
* [Prevent modifications to specific cloudformation stacks](aws-scp-examples.html#prevent-modifications-to-specific-cloudformation-stacks)
* [Restrict network modifications to authorized roles for specific squad](aws-scp-examples.html#restrict-network-modifications-to-authorized-roles-for-specific-squad)

### Tips

* Create multiple Organizational Units (OUs) instead of attaching all SCPs to the root of your organization. This approach allows for more granular restrictions and increases the number of SCPs you can attach, due to quota limits.
* Each Organizational Unit (OU) can have up to 5 SCPs attached and maximum policy size limitations of 5120 characters. To avoid hitting this limit, consider combining multiple policies into a single SCP where possible.
* Refine your SCPs and restrict access to only the necessary AWS services using least privilege concept. Keep in mind that Root user accounts are affected by SCPs.
* The default SCP `FullAWSAccess` is automatically created and attached to every entity in your organization (root, OU and AWS accounts), which allows all principals to perform any actions. Use this as a base and then apply additional SCP to restrict access as needed.
* Always test your SCPs in a non-production environment to understand their impact before applying them broadly.
* Policies do not affect users or roles in the management account, so it is recommended not to run workloads in that account and leave it exclusively for managing accounts.
* Unlike IAM policies, SCPs count whitespace towards the character limit. Be mindful of this when writing policies to ensure they stay within the size constraints.

### Quotas

| Value                                                      | Quota           |
|------------------------------------------------------------|-----------------|
| Maximum number of policies attached to root, OU or account | 5               |
| Maximum size of a policy document                          | 5120 characters |

## RCP - Resource Control Policies

### About

Resource Control Policies (RCPs) are authorization policies to help you to centrally manage the security of AWS accounts within an organization.

RCP provide central control over the maximum permissions available permissions for resources in an organization. They help maintain resource-level security and ensure compliance by restricting what actions can be performed on specific resources.

### [Examples](aws-rcp-examples.md)
* [Prevent cross-service confused deputy problem](aws-rcp-examples.html#prevent-cross-service-confused-deputy-problem)
* [Restrict access to only HTTPS connections to your resources](aws-rcp-examples.html#restrict-access-to-only-https-connections-to-your-resources)
* [Enforce secure TLS connections for access to S3 buckets](aws-rcp-examples.html#enforce-secure-tls-connections-for-access-to-s3-buckets)
* [Enforce object settings controls to S3 buckets](aws-rcp-examples.html#enforce-object-settings-controls-to-s3-buckets)
* [Enforce mandatory encryption to S3 buckets](aws-rcp-examples.html#enforce-mandatory-encryption-to-s3-buckets)
* [Restrict IAM role assumption to trusted AWS accounts only](aws-rcp-examples.html#restrict-iam-role-assumption-to-trusted-aws-accounts-only)

### Tips

* Create multiple Organizational Units (OUs) instead of attaching all RCPs to the root of your organization. This approach allows for more granular restrictions and increases the number of RCPs you can attach, due to quota limits.
* Each Organizational Unit (OU) can have up to 5 RCPs attached and maximum policy size limitations of 5120 characters. To avoid hitting this limit, consider combining multiple policies into a single RCP where possible.
* The default RCP `FRCPullAWSAccess` is automatically created and attached to every entity in your organization (root, OU and AWS accounts), which allows all principals to perform any actions. Use this as a base and then apply additional RCP to restrict access as needed.
* Policies does not support all AWS services, currently only works with specific AWS services: S3, STS, KMS, SQS and Secrets Manager.
* Policies does not affect service-linked roles and cannot manage permissions for resources shared across accounts using AWS RAM.
* Policies do not affect resources in the management account, so it is recommended not to run workloads in that account and leave it exclusively for managing accounts.
* Always test your RCPs in a non-production environment to understand their impact before applying them broadly.

### Quotas

| Value                                                      | Quota           |
|------------------------------------------------------------|-----------------|
| Maximum number of policies attached to root, OU or account | 5               |
| Maximum size of a policy document                          | 5120 characters |
