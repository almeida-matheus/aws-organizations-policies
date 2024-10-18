# AWS SCP – Service Control Policies

AWS Service Control Policies (SCPs) are a feature of the AWS Organizations service.

This feature is responsible for access control, restricting the actions that can be taken in an AWS account so that all IAM users and roles, including the root user, cannot perform them.

This allows you to centrally manage permissions across AWS accounts, enforcing security, compliance, and governance at an organizational level.

## [AWS SPC - Security Examples](security.md)
* [Protect security services](security.html#protect-security-services)
* [Require EC2 IMDSv2](security.html#require-ec2-imdsv2)
* [Deny ability to leave Organization](security.html#deny-ability-to-leave-organization)
* [Deny sharing of resources outside of the organization using AWS RAM](security.html#deny-sharing-of-resources-outside-of-the-organization-using-aws-ram)
* [Prevent account takeover risk](security.html#prevent-account-takeover-risk)
* [Restrict AWS region access](security.html#restrict-aws-region-access)
* [Deny account region modification](security.html#deny-account-region-modification)
* [Prevent critical IAM actions](security.html#prevent-critical-iam-actions)
* [Deny ability to modify an important IAM role](security.html#deny-ability-to-modify-an-important-iam-role)
* [Deny root user access](security.html#deny-root-user-access)
* [Protect default security settings](security.html#protect-default-security-settings)
* [Prevent public resource via policy](security.html#prevent-public-resource-via-policy)

## Tips

* Create multiple Organizational Units (OUs) instead of attaching all SCPs to the root of your organization. This approach allows for more granular restrictions and increases the number of SCPs you can attach, due to quota limits.
* Each Organizational Unit (OU) can have up to 5 SCPs attached. To avoid hitting this limit, consider combining multiple policies into a single SCP where possible.
* Refine your SCPs and restrict access to only the necessary AWS services using least privilege concept. Keep in mind that Root user accounts are affected by SCPs.
* The default SCP is `FullAWSAccess`, which allows all actions. Use this as a base and then apply additional SCPs to restrict access as needed.
* Unlike IAM policies, SCPs count whitespace towards the character limit. Be mindful of this when writing policies to ensure they stay within the size constraints.
* Always test your SCPs in a non-production environment to understand their impact before applying them broadly.

## Quotas

| Value                                 | Quota           |
|---------------------------------------|-----------------|
| Maximum SCP attached to root	        | 5               |
| Maximum SCP attached per OU	        | 5               |
| Maximum SCP attached per account	    | 5               |
| Maximum size of a policy document     | 5120 characters |

