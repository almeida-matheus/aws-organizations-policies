# AWS Organizations Policies


## Organizations Policies

AWS Organizations allows you to centrally manage a multi-account environment. Two of features of this service for governance are Service Control Policies (SCPs) and Resource Control Policies (RCPs). They serve distinctly different purposes in securing your cloud infrastructure and building a data perimeter.

### Differences

Both policies improve security, but they focus on different areas:

| Feature | Service Control Policies (SCPs) | Resource Control Policies (RCPs) |
| :--- | :--- | :--- |
| **Target** | IAM Identities (Users and Roles) | AWS Resources (e.g., S3 Buckets, KMS Keys) |
| **Primary Goal** | Restrict what your identities can do. | Restrict who or what can access your resources. |
| **External Principals** | Does not restrict external accounts from accessing your resources. | Can actively block external accounts from accessing your resources. |
| **Service Support** | Applies to all AWS services. | Applies to specific services that support resource-based policies (e.g., S3, STS, KMS, SQS, Secrets Manager, ECR). |

### Evaluation

Understanding how AWS reads all these policies together is the secret to not accidentally locking yourself out of your own resources. 

When a user or role tries to take an action in AWS, they have to pass through a strict set of checkpoints:

- By default every single request starts with an automatic implicit "Deny".
- If any policy anywhere whether it's an SCP, an RCP, or a standard IAM policy explicitly says "Deny," the request is blocked immediately without exceptions.
- SCPs and RCPs act as guardrails that do not grant permissions on their own. Instead, they define the maximum possible access your accounts and resources can have.
- For an action to successfully go through, an IAM or Resource policy must explicitly say "Allow" and the SCP and RCP bouncers must let it pass. This is usually handled by leaving the default policies (`FullAWSAccess`,`RCPFullAWSAccess`).

The Decision Flow:

1. Does the SCP and RCP allow this action?
    - *If No:* BLOCKED.
    - *If Yes:* Move to Step 2.
2. Does the SCP, RCP, or any other policy explicitly deny the action?
    - *If Yes:* BLOCKED.
    - *If No:* Move to Step 3.
3. Does the user's IAM policy or the resource's policy explicitly allow the action?
    - *If No:* BLOCKED (because of the default deny).
    - *If Yes:* ACCESS GRANTED.

### Troubleshooting

When building a strict data perimeter, you might accidentally block legitimate traffic. AWS provides some services to help you troubleshoot policy denials:

- **AWS CloudTrail:** Search your event history for `AccessDenied` or `UnauthorizedOperation` events. AWS will usually tell you exactly why the action failed (e.g., if it was blocked by a service control policy).
- **IAM Policy Simulator:** Select a specific IAM user or role and run a simulation. The simulator will evaluate all attached policies and tell you exactly which statement is denying the action.
- **IAM Access Analyzer**: Before applying an RCP to an OU, use Access Analyzer to scan your environment. It generates findings showing exactly who currently has access to your resources so you don't accidentally break production.

## SCP - Service Control Policies

### About

Service Control Policies (SCPs) are authorization policies to help you to centrally manage the security across AWS accounts within an organization.

SCP provide central control over the maximum permissions available to IAM users and IAM roles (identities) in an organization. They act as a guardrail, helping enforce security boundaries and ensuring compliance by restricting which services or actions identities can perform, regardless of the permissions granted by their individual IAM identity-based policies.

### Tips

- **Understand the Default:** The default SCP `FullAWSAccess` is automatically created and attached to every entity in your organization (root, OUs, and AWS accounts). It allows all principals to pass SCP evaluation. Use this as a base, then apply Deny statements in additional SCPs to restrict access.
- **Management Account Exemption:** SCPs do not affect users or roles in the management account. Therefore, it is strongly recommended not to run operational workloads in the management account, leaving it strictly for billing and organizational governance.
- **Test Thoroughly:** Always test your SCPs in a non-production environment to understand their impact before applying them broadly.
- **Enforce Least Privilege:** Refine your SCPs to restrict access to only necessary AWS services. Keep in mind that Root user accounts in member accounts are affected by SCPs.
- **Use Organizational Units (OUs):** Create multiple OUs instead of attaching all SCPs directly to the root of your organization. This approach allows for more granular restrictions and helps you avoid hitting the quota limits for policy attachments on a single entity.
- **Combine Policies:** Each OU can have up to 5 SCPs attached, with a maximum policy size limit of 5,120 characters. To avoid hitting this limit, combine multiple statements into a single SCP where possible.
- **Whitespace Matters:** Unlike standard IAM policies, SCPs count whitespace toward the character limit. Be mindful of this and minify your JSON (removing unnecessary spaces and line breaks outside of quotes) to ensure policies stay within the size constraints.

### Quotas

| Value | Quota |
| :--- | :--- |
| Maximum number of policies attached to root, OU, or account | 5 |
| Maximum size of a policy document | 5120 characters |

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

## RCP - Resource Control Policies

### About

Resource Control Policies (RCPs) are authorization policies to help you to centrally enforce a data perimeter across AWS accounts within an organization.

RCP provide central control over the maximum permissions allowed on resources. They help maintain resource-level security and ensure compliance by restricting whor or what can be performed on specific resources.

### Tips

- **Service Support Limitations:** RCPs do not currently support all AWS services. They apply to a specific (but growing) list of services, including Amazon S3, AWS STS, AWS KMS, Amazon SQS, AWS Secrets Manager, Amazon ECR, Amazon OpenSearch Serverless, and Amazon Cognito user pools.
- **Service-Linked Roles:** RCPs do not restrict calls made by AWS service-linked roles and cannot manage permissions for resources shared across accounts using AWS RAM.
- **Understand the Default:** When RCPs are enabled, the default policy `RCPFullAWSAccess` is automatically attached to every entity in your organization. This allows all requests to pass RCP evaluation until you add explicit Deny statements.
- **Management Account Exemption:** SCPs do not affect users or roles in the management account. Therefore, it is strongly recommended not to run operational workloads in the management account, leaving it strictly for billing and organizational governance.
- **Test Thoroughly:** Always test your SCPs in a non-production environment to understand their impact before applying them broadly.
- **Use Organizational Units (OUs):** Create multiple OUs instead of attaching all RCPs directly to the root of your organization. This approach allows for more granular restrictions and helps you avoid hitting the quota limits for policy attachments on a single entity.
- **Combine Policies:** Each OU can have up to 5 RCPs attached, with a maximum policy size limit of 5,120 characters. To avoid hitting this limit, combine multiple statements into a single RCPs where possible.
- **Whitespace Matters:** Unlike standard IAM policies, RCPs count whitespace toward the character limit. Be mindful of this and minify your JSON (removing unnecessary spaces and line breaks outside of quotes) to ensure policies stay within the size constraints.

### Quotas

| Value | Quota |
| :--- | :--- |
| Maximum number of policies attached to root, OU, or account | 5 |
| Maximum size of a policy document | 5120 characters |

### [Examples](aws-rcp-examples.md)
* [Prevent cross-service confused deputy problem](aws-rcp-examples.html#prevent-cross-service-confused-deputy-problem)
* [Restrict access to only HTTPS connections to your resources](aws-rcp-examples.html#restrict-access-to-only-https-connections-to-your-resources)
* [Enforce secure TLS connections for access to S3 buckets](aws-rcp-examples.html#enforce-secure-tls-connections-for-access-to-s3-buckets)
* [Enforce object settings controls to S3 buckets](aws-rcp-examples.html#enforce-object-settings-controls-to-s3-buckets)
* [Enforce mandatory encryption to S3 buckets](aws-rcp-examples.html#enforce-mandatory-encryption-to-s3-buckets)
* [Restrict IAM role assumption to trusted AWS accounts only](aws-rcp-examples.html#restrict-iam-role-assumption-to-trusted-aws-accounts-only)
* [Limit OIDC role assumptions to specific GitHub organizations](aws-rcp-examples.html#limit-oidc-role-assumptions-to-specific-github-organizations)
* [Block the un-tagging of critical security controls](aws-rcp-examples.html#block-the-un-tagging-of-critical-security-controls)