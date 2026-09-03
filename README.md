# Full Documentation for `configvet.py` (with Profile Feature)

## Overview

`configvet.py` is a **unified, command-line security configuration auditor** that validates **14 different rule formats** against security best practices and DISA STIGs. It parses firewall, WAF, SIEM, cloud infrastructure, infrastructure-as-code, and STIG rules, then highlights misconfigurations.

- **Runs on Linux** (and any system with Python 3.6+).
- **No root required** - it reads local files only.
- **Modular & extensible** - easily add new rule types.
- **STIG integration** - load official DISA XCCDF STIG files and check your configurations.
- **Colour-coded output** for quick visual assessment.
- **NEW: Audit Profiles** - store audit paths in a YAML file and run all checks with a single command.

---

## Table of Contents

1. [Installation & Dependencies](#installation--dependencies)
2. [Supported Rule Types](#supported-rule-types)
3. [Command-Line Options](#command-line-options)
4. [Usage Examples](#usage-examples)
5. [Audit Profile Feature Explained](#audit-profile-feature-explained)
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
- **PyYAML** - required for YAML-based formats (Sigma, capa, CloudFormation YAML, Kubernetes, and profiles):

  ```bash
  pip install pyyaml
  ```

- **hcl2** - optional, but **recommended** for better Terraform parsing:

  ```bash
  pip install hcl2
  ```

  If `hcl2` is not installed, Terraform auditing falls back to a regex-based check (less accurate).

### Download

Save the script as `configvet.py` and make it executable:

```bash
chmod +x configvet.py
```

No other external dependencies.

---

## Supported Rule Types

The tool can audit:

| Rule Type | Flag | Input Format | Key Checks |
|-----------|------|--------------|------------|
| **iptables** | `--iptables` | `iptables-save` text | Default ACCEPT policies, any-source rules, duplicates |
| **nftables** | `--nftables` | Text or JSON (`nft list ruleset`) | Empty tables, permissive `accept` from `0.0.0.0/0` |
| **ModSecurity** | `--modsec` | `.conf` with `SecRule`/`SecAction` | Missing ID/phase, non-blocking actions, broad `ARGS` |
| **Sigma** | `--sigma` | YAML file | Missing required fields, undefined references |
| **capa** | `--capa` | YAML rule | Missing `meta`/`features`, empty detection logic |
| **AWS Security Groups** | `--aws-sg` | JSON from `describe-security-groups` | Inbound/outbound rules to `0.0.0.0/0` or `::/0` |
| **Azure NSG** | `--azure-nsg` | JSON from `az network nsg show` | Rules allowing `*` or `Internet` as source |
| **GCP Firewall** | `--gcp-firewall` | JSON from `gcloud compute firewall-rules list` | Ingress from `0.0.0.0/0` |
| **CloudFormation** | `--cloudformation` | JSON or YAML template | Security Group ingress from `0.0.0.0/0` |
| **Terraform** | `--terraform` | HCL `.tf` file | `aws_security_group` with `cidr_blocks = ["0.0.0.0/0"]` |
| **Kubernetes NetworkPolicy** | `--k8s-network` | YAML manifest | Ingress/Egress to `0.0.0.0/0` |
| **Elastic Detection** | `--elastic` | JSON rule | Missing `type`, `query`, `risk_score`, `severity` |
| **Splunk ES** | `--splunk_es` | `savedsearches.conf` | Missing `search`, `rule_id`, notable mapping |
| **Auditd (basic STIG)** | `--auditd` | `/etc/audit/audit.rules` | Missing critical syscalls and file watches |
| **STIG XCCDF (full)** | `--stig-xml` | XCCDF XML from DISA | Compliance checking against a target config |

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
| `--profile FILE` | YAML profile file containing audit paths (new). |
| `-h, --help` | Show help message. |

---

## Usage Examples

### 1. Single Audit (command line)

```bash
python3 configvet.py --iptables /etc/iptables/rules.v4
```

### 2. Multiple Audits

```bash
python3 configvet.py --iptables rules.v4 --aws-sg sg.json --stig-xml stig.xml --target-config audit.rules
```

### 3. List Rules in a STIG

```bash
python3 configvet.py --stig-xml U_ASD_STIG_V6R4_Manual-xccdf.xml --stig-list
```

### 4. Using an Audit Profile (NEW)

Create `profile.yaml`:

```yaml
iptables: /etc/iptables/rules.v4
nftables: /etc/nftables.conf
aws_sg: /home/user/security-groups.json
stig_xml: /home/user/stigs/U_ASD_STIG_V6R4_Manual-xccdf.xml
target_config: /etc/audit/audit.rules
auditd: /etc/audit/audit.rules
```

Then run:

```bash
python3 configvet.py --profile profile.yaml
```

### 5. Combine Profile with Overrides

You can still add extra flags:

```bash
python3 configvet.py --profile profile.yaml --elastic elastic_rules.json
```

### 6. Profile in JSON format (also works)

```json
{
  "iptables": "/etc/iptables/rules.v4",
  "stig_xml": "/home/user/stig.xml",
  "target_config": "/etc/audit/audit.rules"
}
```

```bash
python3 configvet.py --profile profile.json
```

---

## Audit Profile Feature Explained

The `--profile` flag lets you store commonly used audit paths in a YAML or JSON file. This is especially useful for:

- Routine weekly/monthly compliance checks.
- Sharing audit configurations across a team.
- CI/CD pipelines where you want a fixed set of checks.

### How It Works

- The profile file is a mapping of **flag names** (without `--`) to **file paths**.
- The tool loads the file, sets the corresponding arguments, and runs all audits defined.
- If a flag is also given on the command line, it **overrides** the profile value (so you can still customise).

### Profile Keys

Use the same names as the command-line options:

- `iptables`, `nftables`, `modsec`, `sigma`, `capa`,
- `aws_sg`, `azure_nsg`, `gcp_firewall`, `cloudformation`, `terraform`, `k8s_network`,
- `elastic`, `splunk_es`, `auditd`,
- `stig_xml`, `target_config`, `stig_list` (boolean).

### Example Profile (with comments)

```yaml
# My weekly compliance audit profile
iptables: /etc/iptables/rules.v4          # Check iptables
nftables: /etc/nftables.conf              # Check nftables (if used)
aws_sg: /home/soc/security-groups.json    # AWS SGs from describe-security-groups
stig_xml: /home/soc/stigs/asd_stig.xml    # DISA STIG XML
target_config: /etc/audit/audit.rules     # Target file for STIG check
auditd: /etc/audit/audit.rules            # Also run basic auditd check
```

### Running with a Profile

```bash
python3 configvet.py --profile weekly.yaml
```

### Combining Profile with Extra Audits

```bash
python3 configvet.py --profile weekly.yaml --elastic /home/soc/elastic_rules.json
```

This runs everything in `weekly.yaml` **plus** the Elastic check.

---

## Output Interpretation

The report groups issues by rule type. Each issue is prefixed with a severity indicator:

- **`[!]` (red)** - Critical (e.g., default ACCEPT, open to world).
- **`[!]` (yellow)** - Warning (e.g., permissive rule, missing optional field).
- **`[*]` (blue)** - Informational (e.g., missing recommended field).

A summary line at the end shows total issues found.

---

## STIG Compliance Checking

### What It Does

- Loads an official DISA XCCDF XML file.
- Extracts each rule's `fix_text` (remediation commands).
- Checks if those commands appear in your target configuration file.
- Reports any missing commands as non-compliant.

### Example

```bash
python3 configvet.py --stig-xml /path/to/stig.xml --target-config /etc/audit/audit.rules
```

### Limitations

- The check is **heuristic** - it works best for clearly defined fixes (audit rules, sysctl settings).
- More complex requirements (e.g., "ensure TLS 1.2") need additional logic; you can extend the `StigXmlAuditor` class.

---

## Troubleshooting

- **`yaml` module not found** -> `pip install pyyaml`
- **Terraform parsing errors** -> install `hcl2` or use the regex fallback (less accurate).
- **JSON parsing failures** -> ensure your cloud commands output valid JSON.
- **STIG XML fails to parse** -> check the namespace; the script uses `http://checklists.nist.gov/xccdf/1.1`. If your XML uses a different version, update the `ns` dictionary in `StigXmlAuditor.parse()`.
- **Profile file not found** -> check the path and file permissions.

---

## Extending the Tool

To add a new rule type:

1. Create a new class with `__init__`, `parse()`, and `audit()` methods.
2. Add a command-line flag in `main()`.
3. In `ConfigVet`, add a handler method (e.g., `_audit_myrule()`) and call it in `run()`.
4. The profile feature will automatically support the new flag if you add it to the profile YAML.

---

## Integration with CI/CD

You can run `configvet.py` in CI pipelines:

```yaml
# Example GitLab CI
audit:
  script:
    - pip install pyyaml hcl2
    - ./configvet.py --profile ci_profile.yaml
```

The exit code is always `0` (it does not fail by default). You can modify the script to exit with a non-zero code on critical findings.

---

## License & Disclaimer

This tool is provided "as is" for security professionals. Ensure you have authorisation to audit the configurations you supply. The authors assume no liability for misuse.

---

**Happy auditing!**
For issues or contributions, please open an issue in your repository.
