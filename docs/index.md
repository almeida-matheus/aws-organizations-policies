# AWS Organizations Policies

Examples of Service Control Policies (SCPs) and Resource Control Policies (RCPs) to use as guardrails in an AWS organization. Each example explains what it blocks, why, and what to adjust before attaching it.

## Organizations Policies

AWS Organizations lets you manage many AWS accounts from one place. Two of its features do most of the governance work: SCPs limit what your identities can do, and RCPs limit who can reach your resources. Used together, they are the base of a [data perimeter](https://aws.amazon.com/identity/data-perimeters-on-aws/).

### Differences

| | SCP | RCP |
| :--- | :--- | :--- |
| **Target** | IAM users and roles in member accounts, including the root user | Resources in member accounts, such as S3 buckets and KMS keys |
| **Main goal** | Restrict what your identities can do | Restrict who or what can access your resources |
| **External principals** | Not restricted | Restricted |
| **Services** | All | [Supported services only](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services) (S3, STS, KMS, SQS, Secrets Manager, ECR, DynamoDB, CloudWatch Logs, Cognito and others) |
| **Default policy** | `FullAWSAccess` | `RCPFullAWSAccess` (can't be detached) |
| **Effects** | `Allow` and `Deny` | `Deny` only, with `"Principal": "*"` |
| **Not affected** | Management account, service-linked roles | Management account, service-linked roles, AWS managed KMS keys |

### Evaluation

Knowing how AWS combines these policies is what keeps you from locking yourself out of your own accounts. Every request starts as an implicit deny, and SCPs and RCPs never grant anything: they only set the maximum. Since `FullAWSAccess` and `RCPFullAWSAccess` allow everything, in practice only your `Deny` statements count.

The decision flow:

1. Does any policy (SCP, RCP, identity, resource, permissions boundary or session policy) explicitly deny the action?
    - *If yes:* denied.
    - *If no:* go to step 2.
2. If the resource is in a member account, do the RCPs from the root down to that account allow it?
    - *If no:* denied.
    - *If yes:* go to step 3.
3. If the principal is in a member account, do the SCPs from the root down to that account allow it?
    - *If no:* denied.
    - *If yes:* go to step 4.
4. Does the identity policy or the resource policy allow it? For cross-account access, both have to.
    - *If no:* denied by the implicit deny.
    - *If yes:* go to step 5.
5. If there is a permissions boundary or session policy, does it allow it too?
    - *If no:* denied.
    - *If yes:* allowed.

Policies are inherited. A policy attached to an OU applies to every account below it, and nothing at a lower level can override a `Deny` from above.

### Best practices

- **Keep the management account for management only:** no SCP or RCP applies there. Leave workloads out of it and delegate security services to a separate account.
- **Organize OUs by function**, not by org chart: `Security`, `Infrastructure`, `Workloads/Prod`, `Workloads/Dev`, `Sandbox`, `Suspended`. Attach broad guardrails at the root and specific ones at the OU level.
- **Use exception roles, not exception accounts:** an `ArnNotLike` on `aws:PrincipalArn` with a single privileged role keeps exceptions small and easy to audit.
- **Match ARNs with `ArnLike` and `ArnNotLike`:** `StringNotEquals` doesn't support wildcards, so `arn:aws:iam::*:role/admin` never matches and the exception silently stops working.
- **Combine statements:** a root, OU or account takes up to 10 SCPs and 5 RCPs, and the default policies use one slot of each. Group related statements instead of creating one policy per control.
- **Roll out gradually:** attach to a test account, then a test OU, then up the hierarchy. A broken policy at the root breaks every account at once.
- **Keep policies in code:** manage them with Terraform, CloudFormation or Control Tower, and validate on every change.

### Troubleshooting

A strict guardrail can block legitimate traffic. These tools help find out what happened, and ideally catch it before the policy is attached:

- **IAM Access Analyzer:** `aws accessanalyzer validate-policy --policy-type SERVICE_CONTROL_POLICY --policy-document file://policy.json` (or `RESOURCE_CONTROL_POLICY`) catches invalid actions, unknown condition keys and syntax errors. Before attaching data perimeter RCPs, also check the external access findings to see what is already shared outside the organization.
- **Service Authorization Reference:** a condition key on an action that doesn't support it is not an error for IAM. The condition just never matches and the statement silently does nothing, or always applies with negated operators. The [reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html) lists the keys of each action (also available as [JSON](https://servicereference.us-east-1.amazonaws.com/)), and `scripts/validate_policies.py` checks every example in this repository against it.
- **AWS CloudTrail:** search for `AccessDenied` or `UnauthorizedOperation`. The error message says which policy type denied the request, for example `with an explicit deny in a service control policy` or `in a resource control policy`.
- **IAM policy simulator:** evaluates the SCPs attached to an account without running anything, which is useful for actions you wouldn't try for real, like `organizations:LeaveOrganization`. Attach the SCP to a test OU and run:

    ```bash
    aws iam simulate-principal-policy \
      --policy-source-arn arn:aws:iam::111111111111:role/developer \
      --action-names organizations:LeaveOrganization cloudtrail:StopLogging iam:CreateUser \
      --context-entries "ContextKeyName=aws:PrincipalArn,ContextKeyValues=arn:aws:iam::111111111111:role/developer,ContextKeyType=string" \
                        "ContextKeyName=aws:RequestedRegion,ContextKeyValues=us-east-1,ContextKeyType=string" \
      --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
    ```

    Use a role with broad permissions, so any `explicitDeny` comes from the SCP, then repeat with the exception role and expect `allowed`. A few things to keep in mind:

    - It doesn't evaluate RCPs, or SCPs that aren't attached yet.
    - It doesn't fill in `aws:PrincipalArn`. Without it in `--context-entries`, `ArnNotLike` exceptions always match and the exception role shows up as denied.
    - Keys used only in SCPs, like `aws:RequestedRegion`, can only be set from the CLI.
    - Results can differ from real requests. Confirm with one when you can, for example `aws ec2 run-instances --dry-run`.

### Other policy types

Some controls are better enforced by other policy types in AWS Organizations. They configure the service directly instead of blocking API calls, and they also apply to service-linked roles.

| Policy type | Use for |
| :--- | :--- |
| [Amazon EC2 policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ec2.html) | IMDSv2 defaults, block public access for AMIs, snapshots and VPCs, serial console, allowed AMIs |
| [Amazon S3 policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_s3.html) | S3 Block Public Access for every account |
| [Security Hub](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_security_hub.html), [GuardDuty](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_guardduty.html) and [Inspector](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_inspector.html) policies | Turn the service on in every account and keep it on |
| [Amazon Bedrock policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_bedrock.html) | Apply a Bedrock Guardrail to every model call in the organization |
| [Backup policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_backup.html) | Backup plans deployed to every account |
| [Tag policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_tag-policies.html) | Allowed tag keys and values |
| [Chat applications policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_chatbot.html) | Which Slack and Teams workspaces can access your accounts |
| [AI services opt-out policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html) | Prevent AWS from using your content to improve AI services |

## SCP - Service Control Policies

### About

SCPs set the maximum permissions available to IAM users and roles in an organization. Whatever an identity's own policies say, the SCP decides which services and actions are available at all.

### Tips

- **Deny list, not allow list:** keep `FullAWSAccess` attached and write SCPs with only `Deny` statements. With an allow list you have to maintain every action each team needs, and anything you forget stops working.
- **The root user is covered:** in member accounts, SCPs also restrict the root user. They are the main way to keep root credentials from being used.
- **Global services live in `us-east-1`:** a Region restriction has to exempt IAM, Organizations, CloudFront, Route 53 and the other global services, or they stop working. The [Region example](aws-scp-examples.md#deny-access-to-unapproved-regions) has the full list.

### Quotas

| Value | Quota |
| :--- | :--- |
| Maximum number of policies attached to a root, OU or account | 10 |
| Maximum size of a policy document | 10,240 characters |
| Maximum number of SCPs in the organization | 10,000 |

Whitespace counts toward the size, for RCPs too. The console strips it when saving, but the CLI and SDKs don't, so minify the JSON before deploying from code:

```bash
jq -c . policy.json
```

### [Examples](aws-scp-examples.md)

| Category | Policy |
| :--- | :--- |
| Account | [Deny account contact changes and closure](aws-scp-examples.md#deny-account-contact-changes-and-closure) |
| Account | [Deny enabling or disabling Regions](aws-scp-examples.md#deny-enabling-or-disabling-regions) |
| Account | [Deny leaving the organization](aws-scp-examples.md#deny-leaving-the-organization) |
| Account | [Deny access to unapproved Regions](aws-scp-examples.md#deny-access-to-unapproved-regions) |
| IAM | [Deny root user access](aws-scp-examples.md#deny-root-user-access) |
| IAM | [Deny IAM users and long-term credentials](aws-scp-examples.md#deny-iam-users-and-long-term-credentials) |
| IAM | [Deny identity provider changes](aws-scp-examples.md#deny-identity-provider-changes) |
| IAM | [Protect critical IAM roles](aws-scp-examples.md#protect-critical-iam-roles) |
| IAM | [Require a permissions boundary on roles](aws-scp-examples.md#require-a-permissions-boundary-on-roles) |
| IAM | [Control outbound identity federation](aws-scp-examples.md#control-outbound-identity-federation) |
| IAM | [Deny Identity Store changes when users come from an IdP](aws-scp-examples.md#deny-identity-store-changes-when-users-come-from-an-idp) |
| Security services | [Deny disabling security services](aws-scp-examples.md#deny-disabling-security-services) |
| Data protection | [Enforce the resource perimeter](aws-scp-examples.md#enforce-the-resource-perimeter) |
| Data protection | [Protect data perimeter tags](aws-scp-examples.md#protect-data-perimeter-tags) |
| Data protection | [Deny public secrets](aws-scp-examples.md#deny-public-secrets) |
| Data protection | [Protect S3 account-level Block Public Access](aws-scp-examples.md#protect-s3-account-level-block-public-access) |
| Data protection | [Require S3 buckets in the account regional namespace](aws-scp-examples.md#require-s3-buckets-in-the-account-regional-namespace) |
| Data protection | [Deny external resource sharing with RAM](aws-scp-examples.md#deny-external-resource-sharing-with-ram) |
| Data protection | [Protect AWS Backup](aws-scp-examples.md#protect-aws-backup) |
| Data protection | [Require encryption on new RDS instances](aws-scp-examples.md#require-encryption-on-new-rds-instances) |
| Data protection | [Deny publishing to Amazon ECR Public](aws-scp-examples.md#deny-publishing-to-amazon-ecr-public) |
| Data protection | [Deny sharing snapshots and AMIs with other accounts](aws-scp-examples.md#deny-sharing-snapshots-and-amis-with-other-accounts) |
| Data protection | [Deny KMS keys with external key material](aws-scp-examples.md#deny-kms-keys-with-external-key-material) |
| Compute | [Require IMDSv2 on EC2 instances](aws-scp-examples.md#require-imdsv2-on-ec2-instances) |
| Compute | [Protect EC2 and SSM account-level settings](aws-scp-examples.md#protect-ec2-and-ssm-account-level-settings) |
| Compute | [Require IAM auth on Lambda function URLs](aws-scp-examples.md#require-iam-auth-on-lambda-function-urls) |
| Compute | [Require Session Manager instead of SSH keys](aws-scp-examples.md#require-session-manager-instead-of-ssh-keys) |
| Logging | [Deny log deletion](aws-scp-examples.md#deny-log-deletion) |
| Network | [Restrict network changes to the network team](aws-scp-examples.md#restrict-network-changes-to-the-network-team) |
| Network | [Deny public RDS instances and EKS endpoints](aws-scp-examples.md#deny-public-rds-instances-and-eks-endpoints) |
| Network | [Restrict Identity Center sessions to expected networks](aws-scp-examples.md#restrict-identity-center-sessions-to-expected-networks) |
| Messaging | [Restrict Amazon SES setup](aws-scp-examples.md#restrict-amazon-ses-setup) |
| Cost and billing | [Restrict billing changes](aws-scp-examples.md#restrict-billing-changes) |
| Cost and billing | [Deny long-term commitments](aws-scp-examples.md#deny-long-term-commitments) |
| Cost and billing | [Restrict expensive instance types](aws-scp-examples.md#restrict-expensive-instance-types) |
| Cost and billing | [Require a cost allocation tag on creation](aws-scp-examples.md#require-a-cost-allocation-tag-on-creation) |
| Governance | [Protect specific CloudFormation stacks](aws-scp-examples.md#protect-specific-cloudformation-stacks) |
| AI | [Restrict Amazon Bedrock to approved models](aws-scp-examples.md#restrict-amazon-bedrock-to-approved-models) |
| AI | [Limit what AI agents and chat apps can do](aws-scp-examples.md#limit-what-ai-agents-and-chat-apps-can-do) |

## RCP - Resource Control Policies

### About

RCPs set the maximum permissions on resources in an organization, whoever is calling, including principals from outside it. They let you enforce a data perimeter centrally, even when a bucket policy or key policy allows too much.

### Tips

- **Check service support:** RCPs only apply to [supported services](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services), and an action from any other service simply has no effect. The list keeps growing, so check it before writing a new policy.
- **Watch out for outsiders:** RCPs also apply to principals from other AWS accounts. An exception for `arn:aws:iam::*:role/admin` lets in a role named `admin` from someone else's account too. Pair those policies with the [identity perimeter](aws-rcp-examples.md#enforce-the-identity-perimeter), or use account IDs instead of `*`.
- **Leave AWS services alone:** add `"BoolIfExists": {"aws:PrincipalIsAWSService": "false"}` when a policy shouldn't affect service principals, such as CloudTrail delivering logs to a bucket.

### Quotas

| Value | Quota |
| :--- | :--- |
| Maximum number of policies attached to a root, OU or account | 5 |
| Maximum size of a policy document | 5,120 characters |
| Maximum number of RCPs in the organization | 2,000 |

`RCPFullAWSAccess` takes one of the 5 slots and can't be detached, so there are only 4 left for your own policies.

### [Examples](aws-rcp-examples.md)

| Category | Policy |
| :--- | :--- |
| Data perimeter | [Enforce the identity perimeter](aws-rcp-examples.md#enforce-the-identity-perimeter) |
| Data perimeter | [Enforce confused deputy protection](aws-rcp-examples.md#enforce-confused-deputy-protection) |
| Data perimeter | [Enforce the network perimeter](aws-rcp-examples.md#enforce-the-network-perimeter) |
| Data perimeter | [Require HTTPS](aws-rcp-examples.md#require-https) |
| Data perimeter | [Isolate production resources](aws-rcp-examples.md#isolate-production-resources) |
| Identity federation | [Restrict OIDC federation to trusted providers](aws-rcp-examples.md#restrict-oidc-federation-to-trusted-providers) |
| Identity federation | [Deny unauthenticated Cognito identity pool access](aws-rcp-examples.md#deny-unauthenticated-cognito-identity-pool-access) |
| Amazon S3 | [Deny SSE-C uploads](aws-rcp-examples.md#deny-sse-c-uploads) |
| Amazon S3 | [Limit presigned URL lifetime](aws-rcp-examples.md#limit-presigned-url-lifetime) |
| Amazon S3 | [Protect S3 bucket security settings](aws-rcp-examples.md#protect-s3-bucket-security-settings) |
| AWS KMS | [Protect KMS keys](aws-rcp-examples.md#protect-kms-keys) |
| AWS Secrets Manager | [Deny immediate secret deletion](aws-rcp-examples.md#deny-immediate-secret-deletion) |
| Tagging | [Protect security tags](aws-rcp-examples.md#protect-security-tags) |

## References

- [AWS SCP examples](https://github.com/aws-samples/service-control-policy-examples)
- [AWS RCP examples](https://github.com/aws-samples/resource-control-policy-examples)
- [AWS data perimeter policy examples](https://github.com/aws-samples/data-perimeter-policy-examples)
- [SCPs now support the full IAM policy language](https://aws.amazon.com/blogs/security/unlock-new-possibilities-aws-organizations-service-control-policy-now-supports-full-iam-language/)
- [Quotas for AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html)
