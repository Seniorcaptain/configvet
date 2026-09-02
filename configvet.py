#!/usr/bin/env python3
"""
configvet.py - Universal Security Configuration Auditor
Now with XCCDF STIG parsing (--stig-xml) and compliance checking.
"""

import os
import sys
import re
import json
import argparse
import xml.etree.ElementTree as ET
import yaml
import platform
from pathlib import Path

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
# All previous auditors (Iptables, Nftables, ModSecurity, Sigma, capa,
# AWS, Azure, GCP, CloudFormation, Terraform, K8s, Elastic, Splunk, Auditd)
# ... (I will omit them here for brevity – they are unchanged)
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# NEW: STIG XCCDF Auditor
# ----------------------------------------------------------------------
class StigXmlAuditor:
    """Parse XCCDF STIG XML and check compliance against a target config."""
    def __init__(self, stig_xml_path, target_config_path=None):
        self.stig_xml_path = stig_xml_path
        self.target_config_path = target_config_path
        self.rules = []      # list of dicts
        self.issues = []

    def parse(self):
        """Parse the XCCDF XML and extract rules."""
        try:
            tree = ET.parse(self.stig_xml_path)
            root = tree.getroot()
        except Exception as e:
            self.issues.append(f"{RED}[!] Failed to parse XML: {e}{RESET}")
            return self

        ns = {'cdf': 'http://checklists.nist.gov/xccdf/1.1'}
        for group in root.findall('cdf:Group', ns):
            group_id = group.get('id', '')
            group_title = group.find('cdf:title', ns)
            if group_title is not None:
                group_title = group_title.text
            for rule in group.findall('cdf:Rule', ns):
                rule_id = rule.get('id', '')
                severity = rule.get('severity', 'unknown')
                version = rule.find('cdf:version', ns)
                if version is not None:
                    version = version.text
                title = rule.find('cdf:title', ns)
                if title is not None:
                    title = title.text
                # Description contains VulnDiscussion etc.
                desc_elem = rule.find('cdf:description', ns)
                vuln_disc = ""
                if desc_elem is not None and desc_elem.text:
                    # Try to extract VulnDiscussion
                    match = re.search(r'<VulnDiscussion>(.*?)</VulnDiscussion>', desc_elem.text, re.DOTALL)
                    if match:
                        vuln_disc = match.group(1).strip()
                # Fixtext
                fix_elem = rule.find('cdf:fixtext', ns)
                fix_text = ""
                if fix_elem is not None and fix_elem.text:
                    fix_text = fix_elem.text.strip()
                # Check content
                check_elem = rule.find('.//cdf:check-content', ns)
                check_text = ""
                if check_elem is not None and check_elem.text:
                    check_text = check_elem.text.strip()
                self.rules.append({
                    'group_id': group_id,
                    'group_title': group_title,
                    'rule_id': rule_id,
                    'version': version,
                    'title': title,
                    'severity': severity,
                    'vuln_disc': vuln_disc,
                    'fix_text': fix_text,
                    'check_text': check_text,
                })
        return self

    def audit(self):
        """Check target config against fix_text lines."""
        if not self.target_config_path:
            self.issues.append(f"{YELLOW}[*] No target config provided, skipping compliance check.{RESET}")
            return self.issues

        if not self.rules:
            self.issues.append(f"{RED}[!] No rules parsed from STIG XML.{RESET}")
            return self.issues

        try:
            with open(self.target_config_path, 'r') as f:
                config_lines = [ln.strip() for ln in f.readlines() if ln.strip() and not ln.strip().startswith('#')]
        except Exception as e:
            self.issues.append(f"{RED}[!] Failed to read target config: {e}{RESET}")
            return self.issues

        # For each rule, extract commands from fix_text and check if they appear in config
        for rule in self.rules:
            fix = rule['fix_text']
            # Extract lines that look like commands (starting with -a, -w, or contain '=' etc.)
            # This is simplistic; we look for lines that are not just prose.
            fix_lines = [ln.strip() for ln in fix.splitlines() if ln.strip() and not ln.strip().startswith('#')]
            if not fix_lines:
                continue
            # Check if all fix_lines are present in the config
            missing = []
            for line in fix_lines:
                # If the line contains a full command, we check if any config line contains it
                # But we need to avoid partial matches; we'll check if line is a substring of any config line
                found = any(line in cfg for cfg in config_lines)
                if not found:
                    missing.append(line)
            if missing:
                self.issues.append(
                    f"{YELLOW}[!] {rule['version']} ({rule['rule_id']}): Missing fix lines: {', '.join(missing[:3])}{'...' if len(missing)>3 else ''}{RESET}"
                )
        return self.issues

    def list_rules(self):
        """Return a string list of rules."""
        output = []
        for rule in self.rules:
            output.append(f"{rule['version']} ({rule['rule_id']}): {rule['title']} [Severity: {rule['severity']}]")
        return "\n".join(output)

# ----------------------------------------------------------------------
# MAIN CONTROLLER (updated)
# ----------------------------------------------------------------------
class ConfigVet:
    def __init__(self, args):
        self.args = args
        self.report = []

    def run(self):
        # Existing auditors...
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
        if self.args.auditd:
            self.report.append(("auditd (STIG)", self._audit_auditd()))
        # NEW: STIG XML
        if self.args.stig_xml:
            if self.args.stig_list:
                # Just list rules
                auditor = StigXmlAuditor(self.args.stig_xml)
                auditor.parse()
                self.report.append(("STIG Rules List", [auditor.list_rules()]))
            else:
                auditor = StigXmlAuditor(self.args.stig_xml, self.args.target_config)
                auditor.parse()
                if self.args.target_config:
                    self.report.append(("STIG Compliance", auditor.audit()))
                else:
                    self.report.append(("STIG Rules (loaded)", [f"Loaded {len(auditor.rules)} rules. Use --target-config to check compliance."]))

        if not self.report:
            print("No input files specified. Available options:")
            print("  --iptables, --nftables, --modsec, --sigma, --capa,")
            print("  --aws-sg, --azure-nsg, --gcp-firewall, --cloudformation,")
            print("  --terraform, --k8s-network, --elastic, --splunk_es, --auditd")
            print("  --stig-xml FILE [--target-config FILE] [--stig-list]")
            sys.exit(1)

        self.print_report()

    def _read_file(self, path):
        with open(path, 'r') as f:
            return f.read()

    # ... (all other _audit_* methods unchanged)

    def _audit_auditd(self):
        # Existing auditd check
        auditor = AuditdAuditor(self._read_file(self.args.auditd))
        auditor.parse()
        return auditor.audit()

    # Helper methods for other auditors...
    # (I'll omit them here for brevity, but they are the same as before)

    def print_report(self):
        print("\n" + "=" * 80)
        print(f"{BOLD}{BLUE}CONFIGURATION VET REPORT{RESET}")
        print("=" * 80 + "\n")
        total = 0
        for rule_type, issues in self.report:
            print(f"{BOLD}{rule_type} Audit Results:{RESET}")
            if issues:
                if isinstance(issues, str):
                    print(f"  {issues}")
                else:
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
    # Existing arguments...
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
    parser.add_argument("--auditd", help="Linux audit.rules file (STIG validation)")
    # NEW STIG arguments
    parser.add_argument("--stig-xml", help="XCCDF STIG XML file (from DISA)")
    parser.add_argument("--target-config", help="Configuration file to check against STIG")
    parser.add_argument("--stig-list", action="store_true", help="List all rules from STIG XML and exit")
    args = parser.parse_args()

    vet = ConfigVet(args)
    vet.run()

if __name__ == "__main__":
    main()
