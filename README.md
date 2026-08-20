# Security Toolkit: configvet + memguard

Two complementary tools for security configuration auditing and memory forensics.

---

## Table of Contents

- [configvet.py – Security Configuration Auditor](#configvetpy--security-configuration-auditor)
  - [Overview](#overview)
  - [Supported Rule Types](#supported-rule-types-13-formats)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Output Interpretation](#output-interpretation)
  - [Extending the Tool](#extending-the-tool)
  - [Troubleshooting](#troubleshooting)
  - [Integration with CI/CD](#integration-with-cicd)
- [memguard.py – Memory Forensics Tool](#memguardpy--memory-forensics-tool)
- [Combined Workflows](#combined-workflows)
- [License & Disclaimer](#license--disclaimer)

---

## `configvet.py` – Security Configuration Auditor

### Overview

`configvet.py` is a **single-file Python script** that audits security configurations across **firewalls, WAFs, SIEMs, cloud services, and infrastructure-as-code**. It parses common rule formats, performs sanity checks, and highlights misconfigurations that could lead to breaches.

- **Runs on Linux** (and any system with Python 3.6+).
- **No root required** – it reads local files only.
- **Modular & extensible** – you can easily add support for new rule types.

### Supported Rule Types (13 Formats)

| Rule Type | Flag | Input Source | Key Checks |
|-----------|------|--------------|------------|
| **iptables** | `--iptables` | `iptables-save` output | Default ACCEPT policies, any-source rules, duplicates |
| **nftables** | `--nftables` | Text or JSON (`nft list ruleset`) | Empty tables, permissive `accept` from `0.0.0.0/0` |
| **ModSecurity** | `--modsec` | `.conf` with `SecRule`/`SecAction` | Missing ID/phase, non-blocking actions, broad `ARGS` |
| **Sigma** | `--sigma` | YAML rule | Missing required fields (`title`, `detection`, `condition`), undefined condition references |
| **capa** (malware analysis) | `--capa` | YAML rule | Missing `meta`/`features`, empty detection logic |
| **AWS Security Groups** | `--aws-sg` | JSON from `describe-security-groups` | Inbound/outbound rules to `0.0.0.0/0` or `::/0` |
| **Azure NSG** | `--azure-nsg` | JSON from `az network nsg show` | Rules allowing `*` or `Internet` as source |
| **GCP Firewall** | `--gcp-firewall` | JSON from `gcloud compute firewall-rules list` | Ingress from `0.0.0.0/0` |
| **CloudFormation** | `--cloudformation` | JSON or YAML template | Security Group ingress from `0.0.0.0/0` |
| **Terraform** | `--terraform` | HCL `.tf` file | `aws_security_group`/`aws_security_group_rule` with `cidr_blocks = ["0.0.0.0/0"]` |
| **Kubernetes NetworkPolicy** | `--k8s-network` | YAML manifest | Ingress/Egress to `0.0.0.0/0` |
| **Elastic Detection Rules** | `--elastic` | JSON (single rule or array) | Missing `type`, `query`, `risk_score`, `severity` |
| **Splunk ES Correlation Searches** | `--splunk_es` | `savedsearches.conf` | Missing `search`, `rule_id`, notable mapping |

### Installation

#### Prerequisites

- **Python 3.6+**
- **PyYAML** (required for YAML-based formats: Sigma, capa, CloudFormation YAML, Kubernetes):

  ```bash
  pip install pyyaml
  ```

- **hcl2** (optional, but **recommended** for better Terraform parsing):

  ```bash
  pip install hcl2
  ```

  > If `hcl2` is not installed, Terraform auditing falls back to a regex-based check (less accurate).

#### Download

Copy the script to a file named `configvet.py`:

```bash
wget -O configvet.py <URL>   # or just paste the code
chmod +x configvet.py
```

No other dependencies – all parsing is handled with Python's built-in modules (`json`, `re`, `yaml`).

### Usage

#### Basic Syntax

```bash
python3 configvet.py [--flag FILE] [--flag2 FILE] ...
```

You can specify **one or more** rule files. If no flags are given, the script prints a help message.

#### Examples

**1. Audit iptables rules**

```bash
sudo iptables-save > iptables.rules
./configvet.py --iptables iptables.rules
```

**2. Audit nftables ruleset (JSON)**

```bash
sudo nft -j list ruleset > nftables.json
./configvet.py --nftables nftables.json
```

**3. Audit a ModSecurity rule file**

```bash
./configvet.py --modsec /etc/modsecurity/modsecurity.conf
```

**4. Audit a Sigma rule**

```bash
./configvet.py --sigma /path/to/rule.yml
```

**5. Audit a capa rule (malware capability rule)**

```bash
./configvet.py --capa /path/to/capa_rule.yml
```

**6. Audit AWS Security Groups**

```bash
aws ec2 describe-security-groups > sg.json
./configvet.py --aws-sg sg.json
```

**7. Audit Azure NSG**

```bash
az network nsg show --resource-group myRG --name myNSG > nsg.json
./configvet.py --azure-nsg nsg.json
```

**8. Audit GCP Firewall rules**

```bash
gcloud compute firewall-rules list --format=json > fw.json
./configvet.py --gcp-firewall fw.json
```

**9. Audit a CloudFormation template**

```bash
./configvet.py --cloudformation template.yaml   # or template.json
```

**10. Audit Terraform HCL file**

```bash
./configvet.py --terraform main.tf
```

**11. Audit Kubernetes NetworkPolicy**

```bash
kubectl get networkpolicies -o yaml > policies.yaml
./configvet.py --k8s-network policies.yaml
```

**12. Audit Elastic detection rules**

```bash
./configvet.py --elastic elastic_rules.json
```

**13. Audit Splunk ES savedsearches.conf**

```bash
./configvet.py --splunk_es /opt/splunk/etc/apps/SA-Notable/local/savedsearches.conf
```

**14. Combine multiple audits**

```bash
./configvet.py --iptables iptables.rules --aws-sg sg.json --elastic rules.json
```

### Output Interpretation

The tool prints a **colour-coded report** to the terminal:

- **`[!]` (red)** – Critical issue (e.g., default ACCEPT policy, open-to-world rule, missing required field).
- **`[!]` (yellow)** – Warning (e.g., overly permissive rule, missing optional but recommended field).
- **`[*]` (blue)** – Informational (e.g., missing optional field, disabled rule).

At the end, a summary line shows the total number of issues across all audited rule types.

#### Example

```
================================================================================
CONFIGURATION VET REPORT
================================================================================

iptables Audit Results:
  [!] filter/INPUT has default policy ACCEPT (should be DROP)
  [!] Rule accepts from any source: filter/INPUT: -s 0.0.0.0/0 -p tcp --dport 22 -j ACCEPT

AWS Security Groups Audit Results:
  [!] my-sg (sg-1234): Open to world - tcp:22 (inbound)
  [*] my-sg (sg-1234): Outbound to world - all (egress)

================================================================================
Summary: 3 total issues across 2 rule types
================================================================================
```

### Extending the Tool

To add support for a new rule format (e.g., Azure Firewall policies, Cloudflare WAF rules), follow this pattern:

1. **Create a new class** in the script:

   ```python
   class MyRuleAuditor:
       def __init__(self, content):
           self.content = content
           self.issues = []

       def parse(self):
           # parse self.content into internal structures
           return self

       def audit(self):
           # perform checks and append to self.issues
           return self.issues
   ```

2. **Add a command-line flag** in the `main()` function.
3. **Add a handler method** in the `ConfigVet` class (e.g., `_audit_my_rule()`).
4. **Register it** in the `run()` method.

The script is designed to be self-contained, so you can extend it without installing additional libraries (unless your parser needs an external library).

### Troubleshooting

**`yaml` module not found**

```bash
pip install pyyaml
```

**Terraform parsing errors**

- Install `hcl2`: `pip install hcl2` for full AST-based parsing.
- If you cannot install it, the script falls back to regex (less accurate) – ensure your `.tf` file uses standard syntax.

**JSON parsing failures for cloud outputs**

- Ensure your `aws`, `az`, or `gcloud` commands output **valid JSON**.
- For Azure: use `--output json`.
- For GCP: use `--format=json`.

**No rules found in the input file**

- Verify the file is not empty and contains the expected syntax.
- For `savedsearches.conf`, ensure it contains stanzas starting with `[` and `]`.

**Duplicate rule IDs reported in ModSecurity**

This is a genuine warning – duplicate IDs cause unpredictable rule execution. Fix by assigning unique IDs.

**The script reports no issues, but I expected some**

- Check that your rule file actually contains the rules you think it does.
- For some checks (e.g., iptables default policy), the tool only analyses the `filter` table – if you use a different table, extend the parser.

### Integration with CI/CD

You can run `configvet.py` in your CI pipeline to catch misconfigurations before deployment:

```bash
# Example GitLab CI job
audit:
  script:
    - pip install pyyaml hcl2
    - ./configvet.py --terraform ./terraform/main.tf --cloudformation ./cfn/template.yaml
```

The exit code is **0** even if issues are found (the script does not fail by default). You can parse the output or modify the script to exit with a non-zero code on critical issues.

---

## `memguard.py` – Memory Forensics Tool

> ⚠️ **Documentation incomplete.** The sections below are placeholders — send over `memguard.py`'s overview, installation/dependency details, and usage examples (mirroring the structure above) and this section will be filled in to match.

### Overview

*TODO — description of what memguard.py does, supported platforms, and whether root/admin privileges are required.*

### Installation

- Python 3.6+ *(confirm)*
- Requires root/administrator privileges to acquire memory dumps
- Additional dependencies: *TODO — e.g., Volatility, LiME, capstone, yara-python, etc.*

```bash
# TODO: add memguard install command, e.g.
pip install <memguard-dependencies>
```

### Usage

**1. Acquire and scan RAM on a live host, keeping the dump for further analysis**

```bash
sudo ./memguard.py --keep
```

*TODO — add remaining usage examples (e.g., scanning a saved dump file, targeting a specific process, output/report format flags).*

---

## Combined Workflows

The two tools complement each other in a typical incident response or security review process:

1. **Initial detection** — A SIEM rule (audited with `configvet.py`) alerts on suspicious network connections.
2. **Memory forensics** — Use `memguard.py` to acquire and scan the affected machine's RAM for malware artifacts (hidden processes, injected code).
3. **Configuration hardening** — After containment, run `configvet.py` against the firewall, WAF, and cloud security groups to ensure no overly permissive rules allowed the breach.
4. **CI/CD pipeline** — Integrate `configvet.py` into your infrastructure-as-code pipeline to catch misconfigurations before deployment.

### Example Command Sequence

```bash
# 1. Validate SIEM rules
./configvet.py --sigma /opt/sigma/rules/windows/process_creation/win_susp_powershell.yml

# 2. Audit network perimeter
sudo iptables-save | ./configvet.py --iptables /dev/stdin
./configvet.py --aws-sg production_sg.json

# 3. On a compromised host, perform memory scan
sudo ./memguard.py --keep   # keep dump for further analysis
```

---

## License & Disclaimer

This tool is provided "as is" for security professionals and engineers. Always ensure you have authorisation to audit the configurations you supply. The authors assume no liability for misuse or mis-interpretation of results.

**Happy hardening!**
For questions or contributions, please open an issue in your repository.
