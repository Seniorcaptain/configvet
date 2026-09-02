# `configvet.py` - Security Configuration Auditor

## Overview

`configvet.py` is a **unified, command-line security configuration auditor** that validates **14 different rule formats** against security best practices and DISA STIGs. It parses firewall, WAF, SIEM, cloud infrastructure, infrastructure-as-code, and STIG rules, then highlights misconfigurations that could lead to breaches.

- **Runs on Linux** (and any system with Python 3.6+).
- **No root required** - it reads local files only.
- **Modular & extensible** - easily add support for new rule types.
- **STIG integration** - load official DISA XCCDF STIG files and check your configurations for compliance.
- **Colour-coded output** for quick visual assessment.

---

## Table of Contents

1. [Installation & Dependencies](#installation--dependencies)
2. [Supported Rule Types](#supported-rule-types)
3. [Features](#features)
4. [Command-Line Options](#command-line-options)
5. [Usage Examples](#usage-examples)
6. [Output Interpretation](#output-interpretation)
7. [STIG Compliance Checking](#stig-compliance-checking)
8. [Troubleshooting](#troubleshooting)
9. [Extending the Tool](#extending-the-tool)
10. [Integration with CI/CD](#integration-with-cicd)
11. [License & Disclaimer](#license--disclaimer)

---

## Installation & Dependencies

### Prerequisites

- **Python 3.6+**.
- **PyYAML** - required for YAML-based formats (Sigma, capa, CloudFormation YAML, Kubernetes):

  ```bash
  pip install pyyaml
  ```

- **hcl2** - optional, but **recommended** for better Terraform parsing:

  ```bash
  pip install hcl2
  ```

  If `hcl2` is not installed, Terraform auditing falls back to a regex-based check (less accurate).

### Download

Copy the script to a file named `configvet.py`:

```bash
wget -O configvet.py <URL>   # or paste the code
chmod +x configvet.py
```

No other external dependencies - all parsing is handled with Python's built-in modules (`json`, `re`, `xml.etree`, `yaml`).

---

## Supported Rule Types

The tool can parse and audit **14 different configuration formats**:

| Rule Type | Command-line Flag | Input Format | Key Checks |
|-----------|-------------------|--------------|------------|
| **iptables** | `--iptables` | `iptables-save` text | Default ACCEPT policies, any-source rules, duplicates |
| **nftables** | `--nftables` | Text or JSON (`nft list ruleset`) | Empty tables, permissive `accept` from `0.0.0.0/0` |
| **ModSecurity** | `--modsec` | `.conf` with `SecRule`/`SecAction` | Missing ID/phase, non-blocking actions, broad `ARGS` |
| **Sigma** | `--sigma` | YAML file | Missing required fields (`title`, `detection`, `condition`), undefined references |
| **capa** | `--capa` | YAML rule | Missing `meta`/`features`, empty detection logic |
| **AWS Security Groups** | `--aws-sg` | JSON from `describe-security-groups` | Inbound/outbound rules to `0.0.0.0/0` or `::/0` |
| **Azure NSG** | `--azure-nsg` | JSON from `az network nsg show` | Rules allowing `*` or `Internet` as source |
| **GCP Firewall** | `--gcp-firewall` | JSON from `gcloud compute firewall-rules list` | Ingress from `0.0.0.0/0` |
| **CloudFormation** | `--cloudformation` | JSON or YAML template | Security Group ingress from `0.0.0.0/0` |
| **Terraform** | `--terraform` | HCL `.tf` file | `aws_security_group`/`aws_security_group_rule` with `cidr_blocks = ["0.0.0.0/0"]` |
| **Kubernetes NetworkPolicy** | `--k8s-network` | YAML manifest | Ingress/Egress to `0.0.0.0/0` |
| **Elastic Detection** | `--elastic` | JSON rule (single or array) | Missing `type`, `query`, `risk_score`, `severity` |
| **Splunk ES** | `--splunk_es` | `savedsearches.conf` | Missing `search`, `rule_id`, notable mapping |
| **Auditd (basic STIG)** | `--auditd` | `/etc/audit/audit.rules` | Missing critical syscalls and file watches |
| **STIG XCCDF (full)** | `--stig-xml` | XCCDF XML from DISA | Compliance checking against a target config file |

---

## Features

- **Modular parsers** - each rule type is handled by a separate class; easy to extend.
- **Colour-coded output** - critical (red), warning (yellow), info (blue) for quick visual assessment.
- **Cross-platform** - runs on Linux, parses local files.
- **STIG integration** - load official DISA XCCDF STIG files and check a target configuration (e.g., `audit.rules`) against all rules.
- **Batch auditing** - combine multiple rule types in a single command.
- **Extensible** - add new rule types with minimal effort.

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--iptables FILE` | Path to iptables-save output. |
| `--nftables FILE` | Path to nftables ruleset (text or JSON). |
| `--modsec FILE` | Path to ModSecurity rule file. |
| `--sigma FILE` | Path to Sigma rule YAML. |
| `--capa FILE` | Path to capa rule YAML. |
| `--aws-sg FILE` | Path to AWS Security Group JSON. |
| `--azure-nsg FILE` | Path to Azure NSG JSON. |
| `--gcp-firewall FILE` | Path to GCP Firewall JSON. |
| `--cloudformation FILE` | Path to CloudFormation template (JSON/YAML). |
| `--terraform FILE` | Path to Terraform HCL file (.tf). |
| `--k8s-network FILE` | Path to Kubernetes NetworkPolicy YAML. |
| `--elastic FILE` | Path to Elastic detection rule JSON. |
| `--splunk_es FILE` | Path to Splunk ES savedsearches.conf. |
| `--auditd FILE` | Path to Linux audit.rules (basic STIG checks). |
| `--stig-xml FILE` | Path to XCCDF STIG XML file (from DISA). |
| `--target-config FILE` | Configuration file to check against STIG (used with `--stig-xml`). |
| `--stig-list` | List all rules from the STIG XML and exit. |
| `-h, --help` | Show help message. |

---

## Usage Examples

### 1. Audit iptables rules

```bash
sudo iptables-save > iptables.rules
python3 configvet.py --iptables iptables.rules
```

### 2. Audit nftables ruleset (JSON)

```bash
sudo nft -j list ruleset > nftables.json
python3 configvet.py --nftables nftables.json
```

### 3. Audit ModSecurity rule file

```bash
python3 configvet.py --modsec /etc/modsecurity/modsecurity.conf
```

### 4. Audit a Sigma rule

```bash
python3 configvet.py --sigma /path/to/rule.yml
```

### 5. Audit a capa rule

```bash
python3 configvet.py --capa /path/to/capa_rule.yml
```

### 6. Audit AWS Security Groups

```bash
aws ec2 describe-security-groups > sg.json
python3 configvet.py --aws-sg sg.json
```

### 7. Audit Azure NSG

```bash
az network nsg show --resource-group myRG --name myNSG > nsg.json
python3 configvet.py --azure-nsg nsg.json
```

### 8. Audit GCP Firewall rules

```bash
gcloud compute firewall-rules list --format=json > fw.json
python3 configvet.py --gcp-firewall fw.json
```

### 9. Audit a CloudFormation template

```bash
python3 configvet.py --cloudformation template.yaml   # or template.json
```

### 10. Audit Terraform HCL file

```bash
python3 configvet.py --terraform main.tf
```

### 11. Audit Kubernetes NetworkPolicy

```bash
kubectl get networkpolicies -o yaml > policies.yaml
python3 configvet.py --k8s-network policies.yaml
```

### 12. Audit Elastic detection rules

```bash
python3 configvet.py --elastic elastic_rules.json
```

### 13. Audit Splunk ES savedsearches.conf

```bash
python3 configvet.py --splunk_es /opt/splunk/etc/apps/SA-Notable/local/savedsearches.conf
```

### 14. Audit auditd basic STIG rules

```bash
python3 configvet.py --auditd /etc/audit/audit.rules
```

### 15. Combine multiple audits

```bash
python3 configvet.py --iptables iptables.rules --aws-sg sg.json --elastic rules.json
```

### 16. List all rules from a STIG XML file

```bash
python3 configvet.py --stig-xml U_ASD_STIG_V6R4_Manual-xccdf.xml --stig-list
```

### 17. Check a configuration file against a STIG

```bash
python3 configvet.py --stig-xml stig.xml --target-config audit.rules
```

### 18. Audit everything at once

```bash
python3 configvet.py \
  --iptables iptables.rules \
  --nftables nftables.json \
  --modsec modsec.conf \
  --aws-sg sg.json \
  --stig-xml stig.xml \
  --target-config audit.rules
```

---

## Output Interpretation

The report groups issues by rule type. Each issue is prefixed with a severity indicator:

- **`[!]` (red)** - Critical - e.g., firewall default ACCEPT, open to world, missing required field.
- **`[!]` (yellow)** - Warning - e.g., permissive rule, missing optional field.
- **`[*]` (blue)** - Informational - e.g., missing recommended field, disabled rule.

A summary line at the end shows total issues found.

### Example Output

```text
================================================================================
CONFIGURATION VET REPORT
================================================================================

iptables Audit Results:
  [!] filter/INPUT has default policy ACCEPT (should be DROP)
  [!] Rule accepts from any source: filter/INPUT: -s 0.0.0.0/0 -p tcp --dport 22 -j ACCEPT

AWS Security Groups Audit Results:
  [!] my-sg (sg-1234): Open to world - tcp:22 (inbound)
  [*] my-sg (sg-1234): Outbound to world - all (egress)

STIG Compliance Audit Results:
  [!] APSC-DV-000010 (SV-222387r960735_rule): Missing fix lines: -a always,exit -S settimeofday ...

================================================================================
Summary: 4 total issues across 3 rule types
================================================================================
```

---

## STIG Compliance Checking

### What It Does

The STIG auditor parses an official DISA XCCDF XML file (e.g., `U_ASD_STIG_V6R4_Manual-xccdf.xml`) and checks your target configuration against each rule's `fix_text` (the remediation instructions). If any required command or setting is missing from your config, it reports a non-compliance warning.

### How It Works

1. Loads the XCCDF XML and extracts every rule, its `fix_text`, and metadata.
2. Reads your target configuration file (e.g., `audit.rules`, `sysctl.conf`, `nginx.conf`).
3. For each rule, extracts the remediation commands from `fix_text`.
4. Checks if each command appears in your target configuration.
5. Reports any missing commands.

### Example: Checking audit.rules against the ASD STIG

```bash
python3 configvet.py --stig-xml /path/to/U_ASD_STIG_V6R4_Manual-xccdf.xml --target-config /etc/audit/audit.rules
```

### Example: List all rules in a STIG

```bash
python3 configvet.py --stig-xml U_ASD_STIG_V6R4_Manual-xccdf.xml --stig-list
```

### Limitations

- The check is **heuristic** - it works best for clearly defined fixes (e.g., audit rules, sysctl settings, configuration directives).
- More complex requirements (e.g., "ensure TLS 1.2 is used") may require additional logic.
- The check treats `fix_text` lines as literal strings; it does not interpret variables or conditional logic.

If you need more intelligent matching, you can extend the `StigXmlAuditor.audit()` method to parse `check_text` or `vuln_disc` for additional context.

---

## Troubleshooting

### `yaml` module not found

```bash
pip install pyyaml
```

### Terraform parsing errors

- Install `hcl2`: `pip install hcl2` for full AST-based parsing.
- If you cannot install it, the script falls back to regex (less accurate) - ensure your `.tf` file uses standard syntax.

### JSON parsing failures for cloud outputs

- Ensure your `aws`, `az`, or `gcloud` commands output **valid JSON**.
- For Azure: use `--output json`.
- For GCP: use `--format=json`.

### STIG XML fails to parse

- Check that the XML file is valid XCCDF.
- The script uses the namespace `http://checklists.nist.gov/xccdf/1.1`. If your XML uses a different version, update the `ns` dictionary in `StigXmlAuditor.parse()`.

### STIG compliance check too strict

- The check looks for exact matches of `fix_text` lines in the target config.
- Some rules require more complex logic (e.g., checking a file permission, not just a line).
- To improve accuracy, extend the `StigXmlAuditor.audit()` method to parse `check_text` or use regular expressions.

### No rules found in the input file

- Verify the file is not empty and contains the expected syntax.
- For `savedsearches.conf`, ensure it contains stanzas starting with `[` and `]`.

### Duplicate rule IDs reported in ModSecurity

- This is a genuine warning - duplicate IDs cause unpredictable rule execution. Fix by assigning unique IDs.

---

## Extending the Tool

### Adding a new rule type

1. Create a new class with `__init__`, `parse()`, and `audit()` methods.
2. Add a command-line argument in the `main()` function.
3. In the `ConfigVet` class, add a handler method (e.g., `_audit_my_rule()`) and register it in `run()`.
4. Update the documentation.

### Example skeleton for a new auditor

```python
class MyRuleAuditor:
    def __init__(self, content):
        self.content = content
        self.issues = []

    def parse(self):
        # Parse self.content into internal structures
        return self

    def audit(self):
        # Perform checks and append to self.issues
        return self.issues
```

### Improving STIG compliance checks

- Enhance the `StigXmlAuditor.audit()` method to parse `check_text` or `vuln_disc` for more intelligent matching.
- Add support for Windows registry checks by reading `.reg` files or using `pywinreg` on Windows.
- Implement support for `sysctl.conf`, `nginx.conf`, `apache.conf`, and other common configuration formats.

---

## Integration with CI/CD

You can run `configvet.py` in your CI pipeline to catch misconfigurations before deployment:

```yaml
# Example GitLab CI job
audit:
  script:
    - pip install pyyaml hcl2
    - ./configvet.py --terraform ./terraform/main.tf --cloudformation ./cfn/template.yaml
```

The exit code is **0** even if issues are found (the script does not fail by default). You can parse the output or modify the script to exit with a non-zero code on critical issues.

---

## License & Disclaimer

This tool is provided "as is" for security professionals and engineers. Always ensure you have authorisation to audit the configurations you supply. The authors assume no liability for misuse or mis-interpretation of results.

---

**Happy hardening!**
For questions or contributions, please open an issue in your repository.
