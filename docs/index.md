# AWS Organizations Policies

## SCP - Service Control Policies

### About

AWS Service Control Policies (SCPs) are a feature of the AWS Organizations service.

This feature is responsible for access control, restricting the actions that can be taken in an AWS account so that all IAM users and roles, including the root user, cannot perform them.

This allows you to centrally manage permissions across AWS accounts, enforcing security, compliance, and governance at an organizational level.

### [Examples](aws-scp-examples.md)
* [Protect security services](aws-scp-examples.html#protect-security-services)
* [Require EC2 IMDSv2](aws-scp-examples.html#require-ec2-imdsv2)
* [Deny ability to leave Organization](aws-scp-examples.html#deny-ability-to-leave-organization)
* [Deny sharing of resources outside of the organization using AWS RAM](aws-scp-examples.html#deny-sharing-of-resources-outside-of-the-organization-using-aws-ram)
* [Prevent IAM credencials lake](aws-scp-examples.html#prevent-account-takeover-risk)
* [Prevent account takeover risk](aws-scp-examples.html#prevent-account-takeover-risk)
* [Restrict AWS region access](aws-scp-examples.html#restrict-aws-region-access)
* [Deny account region modification](aws-scp-examples.html#deny-account-region-modification)
* [Prevent critical IAM actions](aws-scp-examples.html#prevent-critical-iam-actions)
* [Deny ability to modify an important IAM role](aws-scp-examples.html#deny-ability-to-modify-an-important-iam-role)
* [Deny root user access](aws-scp-examples.html#deny-root-user-access)
* [Protect default security settings](aws-scp-examples.html#protect-default-security-settings)
* [Prevent public resource via policy](aws-scp-examples.html#prevent-public-resource-via-policy)

### Tips

* Create multiple Organizational Units (OUs) instead of attaching all SCPs to the root of your organization. This approach allows for more granular restrictions and increases the number of SCPs you can attach, due to quota limits.
* Each Organizational Unit (OU) can have up to 5 SCPs attached. To avoid hitting this limit, consider combining multiple policies into a single SCP where possible.
* Refine your SCPs and restrict access to only the necessary AWS services using least privilege concept. Keep in mind that Root user accounts are affected by SCPs.
* The default SCP is `FullAWSAccess`, which allows all actions. Use this as a base and then apply additional SCPs to restrict access as needed.
* Unlike IAM policies, SCPs count whitespace towards the character limit. Be mindful of this when writing policies to ensure they stay within the size constraints.
* Always test your SCPs in a non-production environment to understand their impact before applying them broadly.

### Quotas

| Value                                 | Quota           |
|---------------------------------------|-----------------|
| Maximum SCP attached to root	        | 5               |
| Maximum SCP attached per OU	        | 5               |
| Maximum SCP attached per account	    | 5               |
| Maximum size of a policy document     | 5120 characters |