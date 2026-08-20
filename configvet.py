#!/usr/bin/env python3
"""
configvet.py - Universal Security Configuration Auditor
Audits: iptables, nftables, ModSecurity, Sigma, capa,
        AWS SGs, Azure NSGs, GCP Firewall, CloudFormation,
        Terraform, Kubernetes Network Policies, Elastic, Splunk ES.
"""

import os
import sys
import re
import json
import argparse
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional

# Try to import hcl2 for Terraform (optional)
try:
    import hcl2
    HAS_HCL2 = True
except ImportError:
    HAS_HCL2 = False

# ANSI Colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ----------------------------------------------------------------------
# 1. FIREWALL (IPTABLES) PARSER & ANALYZER
# ----------------------------------------------------------------------
class IptablesAuditor:
    """Audit iptables-save output."""
    def __init__(self, content):
        self.content = content
        self.rules = []
        self.chains = {}
        self.issues = []

    def parse(self):
        table = "filter"
        lines = self.content.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("*"):
                table = line[1:]
                self.chains[table] = {}
                continue
            if line.startswith(":"):
                parts = line.split()
                chain_name = parts[0][1:]
                policy = parts[1] if len(parts) > 1 else "ACCEPT"
                self.chains[table][chain_name] = {"policy": policy, "rules": []}
                continue
            if line.startswith("-A"):
                parts = line.split()
                if len(parts) < 2:
                    continue
                chain = parts[1]
                rule_text = " ".join(parts[2:])
                self.rules.append({"table": table, "chain": chain, "text": rule_text})
                if table in self.chains and chain in self.chains[table]:
                    self.chains[table][chain]["rules"].append(rule_text)
        return self

    def audit(self):
        for table, chains in self.chains.items():
            if table == "filter":
                for chain, data in chains.items():
                    if chain in ["INPUT", "FORWARD"] and data["policy"].upper() == "ACCEPT":
                        self.issues.append(f"{RED}[!] {table}/{chain} policy ACCEPT (should be DROP){RESET}")
        for rule in self.rules:
            text = rule["text"]
            if "-s 0.0.0.0/0" in text or "-s any" in text:
                self.issues.append(f"{YELLOW}[!] Any source: {rule['table']}/{rule['chain']}: {text}{RESET}")
            if "-d 0.0.0.0/0" in text and "-p" in text:
                self.issues.append(f"{YELLOW}[!] Any destination: {rule['table']}/{rule['chain']}: {text}{RESET}")
        seen = set()
        for rule in self.rules:
            key = (rule["table"], rule["chain"], rule["text"])
            if key in seen:
                self.issues.append(f"{YELLOW}[!] Duplicate rule: {rule['table']}/{rule['chain']}: {rule['text']}{RESET}")
            seen.add(key)
        return self.issues

# ----------------------------------------------------------------------
# 2. FIREWALL (NFTABLES) PARSER & ANALYZER
# ----------------------------------------------------------------------
class NftablesAuditor:
    def __init__(self, content, is_json=False):
        self.content = content
        self.is_json = is_json
        self.data = None
        self.issues = []

    def parse(self):
        if self.is_json:
            try:
                self.data = json.loads(self.content)
            except json.JSONDecodeError as e:
                self.issues.append(f"{RED}[!] Invalid JSON: {e}{RESET}")
        else:
            self.data = {"raw": self.content}
        return self

    def audit(self):
        if self.is_json and self.data:
            tables = self.data.get("nftables", [])
            for table in tables:
                if "table" in table:
                    name = table["table"].get("name")
                    if name and not any("chain" in t for t in tables if t.get("chain", {}).get("table") == name):
                        self.issues.append(f"{YELLOW}[!] Table '{name}' has no chains (empty){RESET}")
            for rule in tables:
                if "rule" in rule:
                    expr = rule["rule"].get("expr", [])
                    if any("accept" in str(e) for e in expr) and any("0.0.0.0/0" in str(e) for e in expr):
                        self.issues.append(f"{YELLOW}[!] Permissive accept rule (any source){RESET}")
        else:
            if "counter accept" in self.content and "0.0.0.0/0" in self.content:
                self.issues.append(f"{YELLOW}[!] Permissive accept rule with any source{RESET}")
            if "hook input" in self.content and "policy accept" in self.content:
                self.issues.append(f"{YELLOW}[!] INPUT chain may have policy ACCEPT (check manually){RESET}")
        return self.issues

# ----------------------------------------------------------------------
# 3. WAF (MODSECURITY) PARSER & ANALYZER
# ----------------------------------------------------------------------
class ModSecurityAuditor:
    def __init__(self, content):
        self.content = content
        self.rules = []
        self.issues = []

    def parse(self):
        pattern = re.compile(r'(SecRule\s+.*?)(?=\n\S|$)', re.DOTALL)
        pattern2 = re.compile(r'(SecAction\s+.*?)(?=\n\S|$)', re.DOTALL)
        self.rules = pattern.findall(self.content) + pattern2.findall(self.content)
        return self

    def audit(self):
        for rule in self.rules:
            if 'id:' not in rule and 'id ' not in rule:
                self.issues.append(f"{YELLOW}[!] Missing ID: {rule[:60]}...{RESET}")
            if 'phase:' not in rule:
                self.issues.append(f"{YELLOW}[!] Missing phase: {rule[:60]}...{RESET}")
            if 'deny' not in rule and 'block' not in rule and 'drop' not in rule:
                self.issues.append(f"{BLUE}[*] Non-blocking: {rule[:60]}...{RESET}")
            if 'ARGS' in rule and 'TX:' not in rule and 'REQUEST_URI' not in rule:
                self.issues.append(f"{YELLOW}[!] Applies to all ARGS: {rule[:60]}...{RESET}")
        ids = re.findall(r'id:\s*["\']?(\d+)["\']?', self.content, re.IGNORECASE)
        if len(ids) != len(set(ids)):
            self.issues.append(f"{RED}[!] Duplicate rule IDs{RESET}")
        return self.issues

# ----------------------------------------------------------------------
# 4. SIEM (SIGMA) RULES PARSER & ANALYZER
# ----------------------------------------------------------------------
class SigmaAuditor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = {}
        self.issues = []

    def parse(self):
        try:
            with open(self.file_path, 'r') as f:
                self.data = yaml.safe_load(f)
        except Exception as e:
            self.issues.append(f"{RED}[!] YAML parse error: {e}{RESET}")
            return self
        required = ['title', 'detection', 'condition']
        for req in required:
            if req not in self.data:
                self.issues.append(f"{RED}[!] Missing required field '{req}'{RESET}")
        return self

    def audit(self):
        if not self.data:
            return self.issues
        detection = self.data.get('detection', {})
        condition = self.data.get('condition', '')
        if condition:
            used_terms = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', condition)
            keywords = {'and', 'or', 'not', 'all', '1', 'of', 'true', 'false'}
            references = [t for t in used_terms if t.lower() not in keywords and t != 'selection']
            for ref in references:
                if ref not in detection and ref not in detection.get('selection', {}):
                    self.issues.append(f"{YELLOW}[!] Condition references '{ref}' not defined{RESET}")
        if 'level' not in self.data:
            self.issues.append(f"{BLUE}[*] Missing 'level'{RESET}")
        if 'status' not in self.data:
            self.issues.append(f"{BLUE}[*] Missing 'status'{RESET}")
        return self.issues

# ----------------------------------------------------------------------
# 5. MALWARE ANALYSIS (CAPA) RULES PARSER & ANALYZER
# ----------------------------------------------------------------------
class CapaAuditor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = {}
        self.issues = []

    def parse(self):
        try:
            with open(self.file_path, 'r') as f:
                self.data = yaml.safe_load(f)
        except Exception as e:
            self.issues.append(f"{RED}[!] YAML parse error: {e}{RESET}")
            return self
        return self

    def audit(self):
        if not self.data:
            return self.issues
        if 'rule' not in self.data:
            self.issues.append(f"{RED}[!] Missing top-level 'rule' key{RESET}")
            return self.issues
        rule = self.data['rule']
        meta = rule.get('meta', {})
        if not meta:
            self.issues.append(f"{YELLOW}[!] Missing 'meta' section{RESET}")
        else:
            if 'name' not in meta:
                self.issues.append(f"{YELLOW}[!] Missing 'name' in meta{RESET}")
            if 'namespace' not in meta:
                self.issues.append(f"{BLUE}[*] Missing 'namespace' (recommended){RESET}")
            if 'description' not in meta:
                self.issues.append(f"{BLUE}[*] Missing 'description' (recommended){RESET}")
        if 'features' not in rule or not rule['features']:
            self.issues.append(f"{RED}[!] Missing/empty 'features' section{RESET}")
        if 'scopes' not in rule:
            self.issues.append(f"{BLUE}[*] Missing 'scopes' (recommended){RESET}")
        return self.issues

# ----------------------------------------------------------------------
# 6. CLOUD (AWS SECURITY GROUPS) PARSER & ANALYZER
# ----------------------------------------------------------------------
class AwsSecurityGroupAuditor:
    def __init__(self, content):
        self.content = content
        self.data = None
        self.issues = []

    def parse(self):
        try:
            self.data = json.loads(self.content)
        except json.JSONDecodeError as e:
            self.issues.append(f"{RED}[!] Invalid JSON: {e}{RESET}")
            return self
        if 'SecurityGroups' not in self.data:
            self.issues.append(f"{YELLOW}[!] Missing 'SecurityGroups' key{RESET}")
        return self

    def audit(self):
        if not self.data or 'SecurityGroups' not in self.data:
            return self.issues
        for sg in self.data['SecurityGroups']:
            sg_name = sg.get('GroupName', sg.get('GroupId', 'unknown'))
            sg_id = sg.get('GroupId', 'unknown')
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = self._get_port(rule)
                        protocol = rule.get('IpProtocol', 'all')
                        self.issues.append(f"{RED}[!] {sg_name} ({sg_id}): Open to world - {protocol}:{port}{RESET}")
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    if ipv6_range.get('CidrIpv6') == '::/0':
                        port = self._get_port(rule)
                        protocol = rule.get('IpProtocol', 'all')
                        self.issues.append(f"{RED}[!] {sg_name} ({sg_id}): Open to world IPv6 - {protocol}:{port}{RESET}")
            for rule in sg.get('IpPermissionsEgress', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = self._get_port(rule)
                        protocol = rule.get('IpProtocol', 'all')
                        self.issues.append(f"{YELLOW}[!] {sg_name} ({sg_id}): Outbound to world - {protocol}:{port}{RESET}")
        return self.issues

    def _get_port(self, rule):
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        if from_port is not None and to_port is not None:
            return str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
        return 'all'

# ----------------------------------------------------------------------
# 7. CLOUD (AZURE NSG) PARSER & ANALYZER
# ----------------------------------------------------------------------
class AzureNsgAuditor:
    def __init__(self, content):
        self.content = content
        self.data = None
        self.issues = []

    def parse(self):
        try:
            self.data = json.loads(self.content)
        except json.JSONDecodeError as e:
            self.issues.append(f"{RED}[!] Invalid JSON: {e}{RESET}")
        return self

    def audit(self):
        if not self.data:
            return self.issues
        # Handle both single NSG and list
        nsgs = self.data if isinstance(self.data, list) else [self.data]
        for nsg in nsgs:
            nsg_name = nsg.get('name', 'unknown')
            # Check properties.securityRules
            rules = nsg.get('properties', {}).get('securityRules', [])
            for rule in rules:
                if rule.get('properties', {}).get('access') == 'Allow':
                    source = rule.get('properties', {}).get('sourceAddressPrefix')
                    if source == '*' or source == '0.0.0.0/0' or source == 'Internet':
                        direction = rule.get('properties', {}).get('direction')
                        port = rule.get('properties', {}).get('destinationPortRange', 'all')
                        self.issues.append(
                            f"{RED}[!] {nsg_name}: {direction} rule allows any source - port {port}{RESET}"
                        )
        return self.issues

# ----------------------------------------------------------------------
# 8. CLOUD (GCP FIREWALL) PARSER & ANALYZER
# ----------------------------------------------------------------------
class GcpFirewallAuditor:
    def __init__(self, content):
        self.content = content
        self.data = None
        self.issues = []

    def parse(self):
        try:
            self.data = json.loads(self.content)
        except json.JSONDecodeError as e:
            self.issues.append(f"{RED}[!] Invalid JSON: {e}{RESET}")
        return self

    def audit(self):
        if not self.data:
            return self.issues
        rules = self.data if isinstance(self.data, list) else [self.data]
        for rule in rules:
            name = rule.get('name', 'unknown')
            if rule.get('direction') == 'INGRESS':
                source_ranges = rule.get('sourceRanges', [])
                if '0.0.0.0/0' in source_ranges:
                    allowed = rule.get('allowed', [])
                    ports = []
                    for a in allowed:
                        ports.extend(a.get('ports', ['all']))
                    self.issues.append(
                        f"{RED}[!] {name}: Ingress from 0.0.0.0/0 on ports {', '.join(ports)}{RESET}"
                    )
        return self.issues

# ----------------------------------------------------------------------
# 9. CLOUD (CLOUDFORMATION SECURITY GROUPS) PARSER & ANALYZER
# ----------------------------------------------------------------------
class CloudFormationAuditor:
    def __init__(self, content, is_yaml=False):
        self.content = content
        self.is_yaml = is_yaml
        self.template = None
        self.issues = []

    def parse(self):
        try:
            if self.is_yaml:
                self.template = yaml.safe_load(self.content)
            else:
                self.template = json.loads(self.content)
        except Exception as e:
            self.issues.append(f"{RED}[!] Parse error: {e}{RESET}")
        return self

    def audit(self):
        if not self.template:
            return self.issues
        resources = self.template.get('Resources', {})
        for res_name, res_body in resources.items():
            res_type = res_body.get('Type')
            if res_type == 'AWS::EC2::SecurityGroup':
                properties = res_body.get('Properties', {})
                sg_name = properties.get('GroupName', res_name)
                ingress = properties.get('SecurityGroupIngress', [])
                for rule in ingress:
                    cidr = rule.get('CidrIp')
                    if cidr == '0.0.0.0/0':
                        ip_protocol = rule.get('IpProtocol', 'all')
                        from_port = rule.get('FromPort', 'all')
                        to_port = rule.get('ToPort', 'all')
                        port_str = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
                        self.issues.append(
                            f"{RED}[!] CFN {sg_name}: Ingress from 0.0.0.0/0 - {ip_protocol}:{port_str}{RESET}"
                        )
            elif res_type == 'AWS::EC2::SecurityGroupIngress':
                # Individual ingress rules
                cidr = res_body.get('Properties', {}).get('CidrIp')
                if cidr == '0.0.0.0/0':
                    self.issues.append(
                        f"{RED}[!] CFN {res_name}: Ingress rule from 0.0.0.0/0{RESET}"
                    )
        return self.issues

# ----------------------------------------------------------------------
# 10. INFRASTRUCTURE (TERRAFORM) PARSER & ANALYZER
# ----------------------------------------------------------------------
class TerraformAuditor:
    def __init__(self, content):
        self.content = content
        self.data = None
        self.issues = []

    def parse(self):
        if HAS_HCL2:
            try:
                self.data = hcl2.loads(self.content)
            except Exception as e:
                self.issues.append(f"{RED}[!] hcl2 parse error: {e}{RESET}")
        else:
            # Fallback: treat as raw text and regex
            self.data = {"raw": self.content}
        return self

    def audit(self):
        if not self.data:
            return self.issues
        if HAS_HCL2 and isinstance(self.data, dict):
            resources = self.data.get('resource', {})
            for res_type, res_blocks in resources.items():
                if res_type == 'aws_security_group':
                    for name, block in res_blocks.items():
                        ingress = block.get('ingress', [])
                        for rule in ingress:
                            cidrs = rule.get('cidr_blocks', [])
                            if '0.0.0.0/0' in cidrs:
                                from_port = rule.get('from_port', 'all')
                                to_port = rule.get('to_port', 'all')
                                port_str = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
                                self.issues.append(
                                    f"{RED}[!] Terraform SG {name}: Ingress from 0.0.0.0/0 port {port_str}{RESET}"
                                )
                elif res_type == 'aws_security_group_rule':
                    for name, block in res_blocks.items():
                        cidrs = block.get('cidr_blocks', [])
                        if '0.0.0.0/0' in cidrs:
                            self.issues.append(
                                f"{RED}[!] Terraform SG rule {name}: from 0.0.0.0/0{RESET}"
                            )
        else:
            # Regex fallback
            if re.search(r'cidr_blocks\s*=\s*\[.*"0\.0\.0\.0/0"', self.content):
                self.issues.append(f"{RED}[!] Terraform: Found 0.0.0.0/0 in security group rules{RESET}")
        return self.issues

# ----------------------------------------------------------------------
# 11. KUBERNETES NETWORK POLICIES PARSER & ANALYZER
# ----------------------------------------------------------------------
class K8sNetworkPolicyAuditor:
    def __init__(self, content):
        self.content = content
        self.data = None
        self.issues = []

    def parse(self):
        try:
            self.data = yaml.safe_load_all(self.content)
        except Exception as e:
            self.issues.append(f"{RED}[!] YAML parse error: {e}{RESET}")
        return self

    def audit(self):
        if not self.data:
            return self.issues
        for doc in self.data:
            if doc and doc.get('kind') == 'NetworkPolicy':
                spec = doc.get('spec', {})
                pod_selector = spec.get('podSelector', {})
                policy_types = spec.get('policyTypes', [])
                # Check if policy is default deny
                if not policy_types:
                    self.issues.append(f"{BLUE}[*] No policyTypes set for {doc.get('metadata', {}).get('name')}{RESET}")
                # Check ingress rules
                for ingress in spec.get('ingress', []):
                    for rule in ingress.get('from', []):
                        ip_block = rule.get('ipBlock', {})
                        if ip_block.get('cidr') == '0.0.0.0/0':
                            self.issues.append(
                                f"{RED}[!] NetworkPolicy {doc['metadata']['name']}: Allows ingress from 0.0.0.0/0{RESET}"
                            )
                # Check egress rules
                for egress in spec.get('egress', []):
                    for rule in egress.get('to', []):
                        ip_block = rule.get('ipBlock', {})
                        if ip_block.get('cidr') == '0.0.0.0/0':
                            self.issues.append(
                                f"{RED}[!] NetworkPolicy {doc['metadata']['name']}: Allows egress to 0.0.0.0/0{RESET}"
                            )
        return self.issues

# ----------------------------------------------------------------------
# 12. SIEM (ELASTIC DETECTION RULES) PARSER & ANALYZER
# ----------------------------------------------------------------------
class ElasticRuleAuditor:
    def __init__(self, content):
        self.content = content
        self.data = None
        self.issues = []

    def parse(self):
        try:
            self.data = json.loads(self.content)
        except json.JSONDecodeError as e:
            self.issues.append(f"{RED}[!] Invalid JSON: {e}{RESET}")
            return self
        if isinstance(self.data, dict):
            self.data = [self.data]
        return self

    def audit(self):
        if not self.data:
            return self.issues
        for idx, rule in enumerate(self.data):
            name = rule.get('name', f'rule_{idx}')
            rule_type = rule.get('type', '')
            if not rule_type:
                self.issues.append(f"{YELLOW}[!] {name}: Missing 'type'{RESET}")
            if rule_type == 'query' and 'query' not in rule:
                self.issues.append(f"{RED}[!] {name}: Query rule missing 'query'{RESET}")
            if 'risk_score' not in rule:
                self.issues.append(f"{BLUE}[*] {name}: Missing 'risk_score'{RESET}")
            if 'severity' not in rule:
                self.issues.append(f"{BLUE}[*] {name}: Missing 'severity'{RESET}")
            if 'enabled' in rule and rule['enabled'] is False:
                self.issues.append(f"{BLUE}[*] {name}: Disabled{RESET}")
        return self.issues

# ----------------------------------------------------------------------
# 13. SIEM (SPLUNK ES CORRELATION SEARCHES) PARSER & ANALYZER
# ----------------------------------------------------------------------
class SplunkESAuditor:
    def __init__(self, content):
        self.content = content
        self.stanzas = []
        self.issues = []

    def parse(self):
        lines = self.content.splitlines()
        current_stanza = None
        current_content = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith('[') and line.endswith(']'):
                if current_stanza:
                    self.stanzas.append({'name': current_stanza, 'content': '\n'.join(current_content)})
                current_stanza = line[1:-1]
                current_content = []
            else:
                current_content.append(line)
        if current_stanza:
            self.stanzas.append({'name': current_stanza, 'content': '\n'.join(current_content)})
        return self

    def audit(self):
        if not self.stanzas:
            self.issues.append(f"{YELLOW}[!] No stanzas found{RESET}")
            return self.issues
        for stanza in self.stanzas:
            name = stanza['name']
            content = stanza['content']
            if 'action.correlationsearch.enabled=1' in content:
                if 'search =' not in content:
                    self.issues.append(f"{RED}[!] {name}: Missing 'search ='{RESET}")
                if 'rule_id' not in content:
                    self.issues.append(f"{YELLOW}[!] {name}: Missing 'rule_id'{RESET}")
                if 'action.correlationsearch.label' not in content:
                    self.issues.append(f"{BLUE}[*] {name}: Missing label{RESET}")
                if 'action.notable.param.mapfields' not in content:
                    self.issues.append(f"{BLUE}[*] {name}: Missing notable mapping{RESET}")
        return self.issues

# ----------------------------------------------------------------------
# MAIN CONTROLLER
# ----------------------------------------------------------------------
class ConfigVet:
    def __init__(self, args):
        self.args = args
        self.report = []

    def run(self):
        if self.args.iptables:
            self.report.append(("iptables", self._audit_iptables()))
        if self.args.nftables:
            self.report.append(("nftables", self._audit_nftables()))
        if self.args.modsec:
            self.report.append(("ModSecurity", self._audit_modsec()))
        if self.args.sigma:
            self.report.append(("Sigma", self._audit_sigma()))
        if self.args.capa:
            self.report.append(("capa", self._audit_capa()))
        if self.args.aws_sg:
            self.report.append(("AWS Security Groups", self._audit_aws_sg()))
        if self.args.azure_nsg:
            self.report.append(("Azure NSG", self._audit_azure_nsg()))
        if self.args.gcp_firewall:
            self.report.append(("GCP Firewall", self._audit_gcp_firewall()))
        if self.args.cloudformation:
            self.report.append(("CloudFormation", self._audit_cloudformation()))
        if self.args.terraform:
            self.report.append(("Terraform", self._audit_terraform()))
        if self.args.k8s_network:
            self.report.append(("Kubernetes NetworkPolicy", self._audit_k8s_network()))
        if self.args.elastic:
            self.report.append(("Elastic Detection", self._audit_elastic()))
        if self.args.splunk_es:
            self.report.append(("Splunk ES", self._audit_splunk_es()))

        if not self.report:
            print("No input files specified. Available options:")
            print("  --iptables, --nftables, --modsec, --sigma, --capa,")
            print("  --aws-sg, --azure-nsg, --gcp-firewall, --cloudformation,")
            print("  --terraform, --k8s-network, --elastic, --splunk_es")
            sys.exit(1)

        self.print_report()

    def _read_file(self, path):
        with open(path, 'r') as f:
            return f.read()

    def _audit_iptables(self):
        auditor = IptablesAuditor(self._read_file(self.args.iptables))
        auditor.parse()
        return auditor.audit()

    def _audit_nftables(self):
        content = self._read_file(self.args.nftables)
        is_json = content.strip().startswith('{')
        auditor = NftablesAuditor(content, is_json)
        auditor.parse()
        return auditor.audit()

    def _audit_modsec(self):
        auditor = ModSecurityAuditor(self._read_file(self.args.modsec))
        auditor.parse()
        return auditor.audit()

    def _audit_sigma(self):
        auditor = SigmaAuditor(self.args.sigma)
        auditor.parse()
        return auditor.audit()

    def _audit_capa(self):
        auditor = CapaAuditor(self.args.capa)
        auditor.parse()
        return auditor.audit()

    def _audit_aws_sg(self):
        auditor = AwsSecurityGroupAuditor(self._read_file(self.args.aws_sg))
        auditor.parse()
        return auditor.audit()

    def _audit_azure_nsg(self):
        auditor = AzureNsgAuditor(self._read_file(self.args.azure_nsg))
        auditor.parse()
        return auditor.audit()

    def _audit_gcp_firewall(self):
        auditor = GcpFirewallAuditor(self._read_file(self.args.gcp_firewall))
        auditor.parse()
        return auditor.audit()

    def _audit_cloudformation(self):
        content = self._read_file(self.args.cloudformation)
        is_yaml = content.strip().startswith('---') or content.strip().startswith('AWSTemplateFormatVersion')
        auditor = CloudFormationAuditor(content, is_yaml)
        auditor.parse()
        return auditor.audit()

    def _audit_terraform(self):
        auditor = TerraformAuditor(self._read_file(self.args.terraform))
        auditor.parse()
        return auditor.audit()

    def _audit_k8s_network(self):
        auditor = K8sNetworkPolicyAuditor(self._read_file(self.args.k8s_network))
        auditor.parse()
        return auditor.audit()

    def _audit_elastic(self):
        auditor = ElasticRuleAuditor(self._read_file(self.args.elastic))
        auditor.parse()
        return auditor.audit()

    def _audit_splunk_es(self):
        auditor = SplunkESAuditor(self._read_file(self.args.splunk_es))
        auditor.parse()
        return auditor.audit()

    def print_report(self):
        print("\n" + "=" * 80)
        print(f"{BOLD}{BLUE}CONFIGURATION VET REPORT{RESET}")
        print("=" * 80 + "\n")
        total = 0
        for rule_type, issues in self.report:
            print(f"{BOLD}{rule_type} Audit Results:{RESET}")
            if issues:
                for issue in issues:
                    print(f"  {issue}")
                total += len(issues)
            else:
                print(f"  {GREEN}No issues found.{RESET}")
            print()
        print("=" * 80)
        print(f"{BOLD}Summary: {total} total issues across {len(self.report)} rule types{RESET}")
        print("=" * 80 + "\n")

# ----------------------------------------------------------------------
# ENTRY POINT
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="configvet.py - Universal Security Configuration Auditor",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--iptables", help="iptables-save output")
    parser.add_argument("--nftables", help="nftables ruleset (text or JSON)")
    parser.add_argument("--modsec", help="ModSecurity rule file")
    parser.add_argument("--sigma", help="Sigma rule YAML")
    parser.add_argument("--capa", help="capa rule YAML")
    parser.add_argument("--aws-sg", help="AWS Security Group JSON")
    parser.add_argument("--azure-nsg", help="Azure NSG JSON")
    parser.add_argument("--gcp-firewall", help="GCP Firewall JSON")
    parser.add_argument("--cloudformation", help="CloudFormation template (JSON/YAML)")
    parser.add_argument("--terraform", help="Terraform HCL file (.tf)")
    parser.add_argument("--k8s-network", help="Kubernetes NetworkPolicy YAML")
    parser.add_argument("--elastic", help="Elastic detection rule JSON")
    parser.add_argument("--splunk_es", help="Splunk ES savedsearches.conf")
    args = parser.parse_args()

    vet = ConfigVet(args)
    vet.run()

if __name__ == "__main__":
    main()