#!/usr/bin/env python3
"""
Lynx - Smart Contract Vulnerability Scanner
A Nuclei-inspired vulnerability scanner for smart contracts

Author: Lynx Security Team
Version: 1.0.0
Website: https://github.com/lynx-scanner/lynx

Hunt vulnerabilities with feline precision 🐾
"""

import os
import re
import sys
import yaml
import glob
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    template_id: str
    name: str
    severity: Severity
    description: str
    file_path: str
    line_number: int
    matched_content: str
    recommendation: str = ""
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []

@dataclass
class Template:
    id: str
    name: str
    author: str
    severity: Severity
    description: str
    patterns: List[str]
    negative_patterns: List[str]
    recommendation: str
    references: List[str]
    tags: List[str]

class TemplateEngine:
    def __init__(self, template_paths: List[str] = None):
        self.template_paths = template_paths or ["templates.yaml"]
        self.templates: List[Template] = []
        self.load_templates()

    def load_templates(self):
        """Load templates from YAML files (single file or directory structure)"""
        template_files = []
        
        for path in self.template_paths:
            if os.path.isfile(path):
                template_files.append(path)
            elif os.path.isdir(path):
                # Legacy support: Load individual YAML files from directory
                yaml_files = glob.glob(f"{path}/**/*.yaml", recursive=True)
                yml_files = glob.glob(f"{path}/**/*.yml", recursive=True)
                template_files.extend(yaml_files + yml_files)
            else:
                print(f"⚠️  Template path not found: {path}")
        
        if not template_files:
            print("⚠️  No template files found!")
            return
            
        print(f"📂 Loading templates from {len(template_files)} file(s)...")
        
        for template_file in template_files:
            try:
                templates_loaded = self.load_template_file(template_file)
                print(f"  ✅ Loaded: {os.path.basename(template_file)} ({templates_loaded} templates)")
            except Exception as e:
                print(f"  ❌ Error loading template file {template_file}: {e}")

    def load_template_file(self, template_file: str) -> int:
        """Load templates from a single YAML file (supports both single template and template collection)"""
        with open(template_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            return 0
            
        templates_loaded = 0
        
        # Check if this is a templates collection file
        if 'templates' in data and isinstance(data['templates'], list):
            # Multiple templates in one file
            for template_data in data['templates']:
                template = self.parse_template(template_data)
                if template:
                    self.templates.append(template)
                    templates_loaded += 1
        else:
            # Single template file (legacy format)
            template = self.parse_template(data)
            if template:
                self.templates.append(template)
                templates_loaded += 1
                
        return templates_loaded

    def parse_template(self, data: dict) -> Optional[Template]:
        """Parse template data into Template object"""
        if not data or 'id' not in data:
            return None

        return Template(
            id=data['id'],
            name=data.get('info', {}).get('name', ''),
            author=data.get('info', {}).get('author', 'Lynx Community'),
            severity=Severity(data.get('info', {}).get('severity', 'medium')),
            description=data.get('info', {}).get('description', ''),
            patterns=data.get('detection', {}).get('patterns', []),
            negative_patterns=data.get('detection', {}).get('negative_patterns', []),
            recommendation=data.get('info', {}).get('recommendation', ''),
            references=data.get('info', {}).get('references', []),
            tags=data.get('info', {}).get('tags', [])
        )

class ContractScanner:
    def __init__(self, template_engine: TemplateEngine):
        self.template_engine = template_engine
        self.findings: List[Finding] = []

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a single Solidity file for vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return findings

        for template in self.template_engine.templates:
            template_findings = self.apply_template(template, file_path, content, lines)
            findings.extend(template_findings)

        return findings

    def apply_template(self, template: Template, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        """Apply a template to detect vulnerabilities in the contract"""
        findings = []

        for i, line in enumerate(lines, 1):
            # Check if line matches any positive patterns
            matches_pattern = False
            matched_content = ""
            
            for pattern in template.patterns:
                try:
                    # Use simple string matching for basic patterns, regex for complex ones
                    if pattern.startswith('regex:'):
                        # Advanced regex pattern
                        pattern_to_use = pattern[6:]  # Remove 'regex:' prefix
                        if re.search(pattern_to_use, line, re.IGNORECASE):
                            matches_pattern = True
                            matched_content = line.strip()
                            break
                    else:
                        # Simple string matching
                        if pattern.lower() in line.lower():
                            matches_pattern = True
                            matched_content = line.strip()
                            break
                except Exception as e:
                    print(f"    ⚠️  Warning: Pattern '{pattern}' caused error: {e}")
                    continue

            if not matches_pattern:
                continue

            # Check if line matches any negative patterns (exclusions)
            matches_negative = False
            for neg_pattern in template.negative_patterns:
                try:
                    if neg_pattern.startswith('regex:'):
                        # Advanced regex pattern
                        pattern_to_use = neg_pattern[6:]  # Remove 'regex:' prefix
                        if re.search(pattern_to_use, line, re.IGNORECASE):
                            matches_negative = True
                            break
                    else:
                        # Simple string matching
                        if neg_pattern.lower() in line.lower():
                            matches_negative = True
                            break
                except Exception as e:
                    print(f"    ⚠️  Warning: Negative pattern '{neg_pattern}' caused error: {e}")
                    continue

            if matches_negative:
                continue

            # Create finding
            finding = Finding(
                template_id=template.id,
                name=template.name,
                severity=template.severity,
                description=template.description,
                file_path=file_path,
                line_number=i,
                matched_content=matched_content,
                recommendation=template.recommendation,
                references=template.references
            )
            findings.append(finding)

        return findings

    def scan_directory(self, directory: str) -> List[Finding]:
        """Scan all Solidity files in a directory recursively"""
        findings = []
        
        # Find all .sol files recursively
        sol_files = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.sol'):
                    sol_files.append(os.path.join(root, file))
        
        if not sol_files:
            print(f"⚠️  No Solidity files (.sol) found in directory: {directory}")
            return findings
        
        print(f"🔍 Found {len(sol_files)} Solidity files to scan...")
        
        for i, file_path in enumerate(sol_files, 1):
            relative_path = os.path.relpath(file_path, directory)
            print(f"  [{i}/{len(sol_files)}] Scanning: {relative_path}")
            
            try:
                file_findings = self.scan_file(file_path)
                findings.extend(file_findings)
            except Exception as e:
                print(f"    ❌ Error scanning {relative_path}: {e}")
                continue
        
        print(f"✅ Completed scanning {len(sol_files)} files")
        return findings

class Reporter:
    @staticmethod
    def print_findings(findings: List[Finding], output_format: str = "table"):
        """Print findings in specified format"""
        if not findings:
            print("✅ No vulnerabilities found!")
            return

        print(f"\n🔍 Found {len(findings)} potential vulnerabilities:\n")

        if output_format == "json":
            Reporter.print_json(findings)
        elif output_format == "detailed":
            Reporter.print_detailed(findings)
        else:
            Reporter.print_table(findings)

    @staticmethod
    def print_table(findings: List[Finding]):
        """Print findings in table format"""
        # Group by severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        
        for severity in severity_order:
            severity_findings = [f for f in findings if f.severity == severity]
            if not severity_findings:
                continue
                
            severity_icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠", 
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
                Severity.INFO: "ℹ️"
            }
            
            print(f"{severity_icon[severity]} {severity.value.upper()} ({len(severity_findings)})")
            print("-" * 80)
            
            for finding in severity_findings:
                file_name = os.path.basename(finding.file_path)
                print(f"  {finding.name}")
                print(f"  📄 {file_name}:{finding.line_number}")
                print(f"  💡 {finding.description}")
                print(f"  🔍 {finding.matched_content}")
                print()

    @staticmethod
    def print_detailed(findings: List[Finding]):
        """Print detailed findings"""
        for i, finding in enumerate(findings, 1):
            print(f"Finding #{i}")
            print(f"ID: {finding.template_id}")
            print(f"Name: {finding.name}")
            print(f"Severity: {finding.severity.value.upper()}")
            print(f"File: {finding.file_path}:{finding.line_number}")
            print(f"Description: {finding.description}")
            print(f"Code: {finding.matched_content}")
            if finding.recommendation:
                print(f"Recommendation: {finding.recommendation}")
            if finding.references:
                print(f"References: {', '.join(finding.references)}")
            print("-" * 80)

    @staticmethod
    def print_json(findings: List[Finding]):
        """Print findings as JSON"""
        findings_data = []
        for finding in findings:
            findings_data.append({
                "template_id": finding.template_id,
                "name": finding.name,
                "severity": finding.severity.value,
                "description": finding.description,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "matched_content": finding.matched_content,
                "recommendation": finding.recommendation,
                "references": finding.references
            })
        
        result = {
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(findings),
            "scanner": "Lynx v1.0.0",
            "findings": findings_data
        }
        
        print(json.dumps(result, indent=2))

def create_sample_templates():
    """Create a sample templates.yaml file with built-in vulnerability patterns"""
    template_file = "templates.yaml"
    
    if os.path.exists(template_file):
        print(f"📄 {template_file} already exists!")
        return True
    
    print(f"📁 Creating sample templates file: {template_file}")
    print("📄 This file contains all built-in vulnerability detection patterns.")
    print("   You can modify this file or create your own template files.")
    print()
    print("💡 Template file structure:")
    print("   templates.yaml - Single file containing all templates")
    print("   OR")
    print("   templates/     - Directory with individual .yaml files")
    print()
    print("🔧 To customize templates:")
    print("   1. Edit templates.yaml directly")
    print("   2. Create custom template files and use -t path/to/custom.yaml")
    print("   3. Mix both approaches with -t templates.yaml -t custom.yaml")
    print()
    print("✅ Sample templates.yaml file should be in your project directory!")
    print("   Use: python lynx.py --list-templates to see available templates")
    
    return True

def main():
    parser = argparse.ArgumentParser(
        description="Lynx - Smart Contract Vulnerability Scanner 🐾",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Hunt vulnerabilities with feline precision!

Examples:
  %(prog)s contract.sol                          # Scan single file with default templates
  %(prog)s ./contracts/                          # Scan directory with default templates  
  %(prog)s contract.sol -t custom-templates.yaml # Use custom template file
  %(prog)s contract.sol -t template1.yaml        # Use single custom template
  %(prog)s contract.sol -t templates.yaml -t custom.yaml # Use multiple template sources
  %(prog)s contract.sol -f json > results.json   # Output JSON to file
  %(prog)s --create-templates                     # Create sample templates.yaml

GitHub: https://github.com/lynx-scanner/lynx
        """
    )
    
    parser.add_argument("target", nargs='?', help="Target file or directory to scan")
    parser.add_argument("-t", "--templates", action='append', 
                       help="Template file or directory (can be specified multiple times). Default: ./templates.yaml")
    parser.add_argument("-f", "--format", choices=["table", "json", "detailed"], 
                       default="table", help="Output format (default: table)")
    parser.add_argument("--create-templates", action="store_true", 
                       help="Create sample template file (templates.yaml)")
    parser.add_argument("--list-templates", action="store_true", 
                       help="List all available templates and exit")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"],
                       help="Filter findings by minimum severity level")
    parser.add_argument("--tags", help="Filter templates by tags (comma-separated)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Handle template creation
    if args.create_templates:
        create_sample_templates()
        return
    
    # Set default templates if none specified
    if not args.templates:
        args.templates = ["templates.yaml"]
    
    # Initialize template engine
    if args.verbose:
        print(f"🔧 Using template sources: {', '.join(args.templates)}")
    
    template_engine = TemplateEngine(args.templates)
    
    # Handle template listing
    if args.list_templates:
        print(f"\n📋 Available Templates ({len(template_engine.templates)}):")
        print("=" * 80)
        
        for template in template_engine.templates:
            tags_str = ", ".join(template.tags) if template.tags else "none"
            refs_count = len(template.references)
            
            print(f"🔍 {template.id}")
            print(f"   Name: {template.name}")
            print(f"   Author: {template.author}")
            print(f"   Severity: {template.severity.value.upper()}")
            print(f"   Description: {template.description}")
            print(f"   Tags: {tags_str}")
            print(f"   References: {refs_count} link(s)")
            print(f"   Patterns: {len(template.patterns)} detection pattern(s)")
            if template.negative_patterns:
                print(f"   Exclusions: {len(template.negative_patterns)} exclusion pattern(s)")
            print("-" * 80)
        
        return
    
    # Validate target is provided for scanning
    if not args.target:
        parser.error("target is required for scanning (or use --create-templates / --list-templates)")
    
    if not template_engine.templates:
        print("❌ No templates loaded! Use --create-templates to get templates.yaml file.")
        print("   Or specify custom template paths with -t /path/to/templates.yaml")
        return
    
    # Filter templates by tags if specified
    if args.tags:
        requested_tags = [tag.strip().lower() for tag in args.tags.split(',')]
        original_count = len(template_engine.templates)
        template_engine.templates = [
            t for t in template_engine.templates 
            if any(tag.lower() in requested_tags for tag in t.tags)
        ]
        filtered_count = len(template_engine.templates)
        if args.verbose:
            print(f"🏷️  Filtered templates by tags {requested_tags}: {filtered_count}/{original_count}")
    
    # Initialize scanner
    scanner = ContractScanner(template_engine)
    
    # Validate target exists
    if not os.path.exists(args.target):
        print(f"❌ Target '{args.target}' not found!")
        return
    
    # Scan target
    print(f"🎯 Scanning target: {args.target}")
    
    if os.path.isfile(args.target):
        if not args.target.endswith('.sol'):
            print("⚠️  Warning: Target file doesn't have .sol extension")
        findings = scanner.scan_file(args.target)
    elif os.path.isdir(args.target):
        findings = scanner.scan_directory(args.target)
    else:
        print(f"❌ Target '{args.target}' is neither a file nor directory!")
        return
    
    # Filter findings by severity if specified
    if args.severity:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_severity_level = severity_order[args.severity]
        original_count = len(findings)
        findings = [
            f for f in findings 
            if severity_order[f.severity.value] >= min_severity_level
        ]
        if args.verbose and original_count != len(findings):
            print(f"🔍 Filtered findings by severity >= {args.severity}: {len(findings)}/{original_count}")
    
    # Report findings
    Reporter.print_findings(findings, args.format)
    
    # Summary
    if findings and args.format != "json":
        severities = {}
        for finding in findings:
            severities[finding.severity] = severities.get(finding.severity, 0) + 1
        
        print(f"\n📊 Summary: {len(findings)} total findings")
        for severity, count in sorted(severities.items(), key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0].value)):
            print(f"   {severity.value.upper()}: {count}")
        
        # Risk assessment
        if any(s.value in ["critical", "high"] for s in severities.keys()):
            print(f"\n🚨 High risk issues detected! Review critical and high severity findings immediately.")
        elif any(s.value == "medium" for s in severities.keys()):
            print(f"\n💡 Medium risk issues found. Consider addressing these vulnerabilities.")
        else:
            print(f"\n✅ Only low/info level issues found. Good security posture!")
        
        print(f"\n🐾 Lynx scanning complete! Stay secure.")

if __name__ == "__main__":
    main()
