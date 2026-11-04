#!/usr/bin/env python3
"""Turn `terraform output -json stack` into a Helm values overlay with the account-specific settings.

    terraform -chdir=deploy/terraform/aws/environments/prod output -json stack \
      | python deploy/scripts/helm_values_from_terraform.py > /tmp/account-values.yaml

The overlay sets the evidence bucket, IRSA role ARNs, backup upload location, network-policy CIDRs and the
External Secrets key. It is passed to `helm upgrade` after values-<env>.yaml so it takes precedence.
"""
from __future__ import annotations

import json
import sys


def main() -> int:
    stack = json.load(sys.stdin)
    if "value" in stack:  # accept both `output -json stack` and `output -json` | .stack
        stack = stack["value"]
    roles = stack["irsa_role_arns"]
    values = {
        "config": {"s3Bucket": stack["evidence_bucket"]},
        "externalSecrets": {"enabled": True, "remoteKey": stack["runtime_secret_name"]},
        "serviceAccounts": {
            "api": {"roleArn": roles["api"]},
            "worker": {"roleArn": roles["worker"]},
            "ops": {"roleArn": roles["ops"]},
        },
        "backup": {"uploadUrl": f"s3://{stack['backup_bucket']}/app"},
        "networkPolicy": {"postgresCidrs": stack["database_subnet_cidrs"], "awsEndpointCidrs": [stack["vpc_cidr"]]},
    }
    # JSON is valid YAML; Helm reads it directly.
    json.dump(values, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
