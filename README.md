<h1 align="center">aws-organizations-policies</h1>

<p align="center">
    <a href="https://almeida-matheus.github.io/aws-organizations-policies/">Documentation</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
    <a href="#running-locally">Running locally</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
    <a href="#contributing">Contributing</a>&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;
    <a href="#license">License</a>
</p>

<br>

Examples of AWS Organizations Service Control Policies (SCPs) and Resource Control Policies (RCPs) to use as security guardrails across your accounts.

- [Overview](docs/index.md): SCP vs RCP, evaluation, quotas and recommendations
- [SCP examples](docs/aws-scp-examples.md)
- [RCP examples](docs/aws-rcp-examples.md)

Every policy is validated in CI: valid JSON, required elements, minified size within the AWS quota, and every action, condition key and operator checked against the [AWS Service Authorization Reference](https://servicereference.us-east-1.amazonaws.com/), including whether each condition key applies to the actions in its statement.

## Running locally

```bash
git clone git@github.com:almeida-matheus/aws-organizations-policies.git
cd aws-organizations-policies

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python scripts/validate_policies.py
mkdocs serve
```

To also run IAM Access Analyzer `ValidatePolicy` on every policy (needs the AWS CLI and credentials, makes no changes to the account):

```bash
AWS_PROFILE=my-profile python scripts/validate_policies.py --access-analyzer
```

## Contributing

1. Fork the project and create a branch
2. Add or change a policy in `docs/` following the format of the existing ones
3. Run `python scripts/validate_policies.py`
4. Open a pull request

## License

Distributed under the MIT License. See [LICENSE](LICENSE).
