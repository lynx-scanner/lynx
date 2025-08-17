# Lynx 🐾

A **Nuclei-inspired** vulnerability scanner for **Smart Contracts**. Lynx uses YAML-based templates to hunt vulnerabilities in Solidity code with feline precision.

*Hunt vulnerabilities with feline precision* 

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-smart%20contracts-red.svg)
![Lynx](https://img.shields.io/badge/🐾-lynx-orange.svg)

## ✨ Features

- 🎯 **Template-based Detection** - YAML templates similar to Nuclei for defining vulnerability patterns
- 📁 **Flexible Scanning** - Scan single files or entire directory trees
- 🔧 **Custom Templates** - Bring your own templates or use community templates
- 📊 **Multiple Output Formats** - Table, JSON, and detailed reporting
- 🚨 **Severity Classification** - Critical, High, Medium, Low, Info levels
- 🏷️ **Tag-based Filtering** - Filter scans by vulnerability categories
- 🔄 **Extensible Architecture** - Easy to add new vulnerability checks
- 🚀 **High Performance** - Fast recursive scanning of large codebases

## 🚀 Quick Start

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/lynx-scanner/lynx.git
   cd lynx
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Get templates file:**
   ```bash
   # The templates.yaml file should be included in the repository
   # Or create a placeholder with:
   python lynx.py --create-templates
   ```

4. **Run your first scan:**
   ```bash
   python lynx.py ./contracts/
   ```

### Requirements

```
PyYAML>=6.0
```

Or install manually:
```bash
pip install PyYAML
```

## 📖 Usage

### Basic Scanning

```bash
# Scan a single Solidity file
python lynx.py MyToken.sol

# Scan entire project directory (recursive)
python lynx.py ./contracts/

# Scan with verbose output
python lynx.py ./contracts/ -v
```

### Custom Templates

```bash
# Use custom template file
python lynx.py contract.sol -t my-templates.yaml

# Use multiple template sources
python lynx.py contract.sol -t templates.yaml -t custom-rules.yaml

# Use individual template files (legacy format)
python lynx.py contract.sol -t templates/
```

### Filtering and Output

```bash
# Filter by minimum severity level
python lynx.py contract.sol --severity high

# Filter by vulnerability tags
python lynx.py contract.sol --tags reentrancy,overflow

# Output as JSON
python lynx.py contract.sol -f json > results.json

# Detailed output format
python lynx.py contract.sol -f detailed
```

### Template Management

```bash
# List all available templates
python lynx.py --list-templates

# Create templates.yaml placeholder
python lynx.py --create-templates
```

## 📝 Template Format

Templates are defined in a single YAML file (`templates.yaml`):

```yaml
templates:
  - id: template-identifier
    info:
      name: "Human-readable vulnerability name"
      author: "Template Author"
      severity: high  # critical|high|medium|low|info
      description: "Detailed description of the vulnerability"
      recommendation: "How to fix this issue"
      references:
        - "https://swcregistry.io/docs/SWC-XXX"
        - "https://consensys.github.io/smart-contract-best-practices/"
      tags:
        - vulnerability-category
        - specific-type
    detection:
      patterns:
        - 'regex-pattern-for-vulnerable-code'
        - 'another-detection-pattern'
      negative_patterns:  # Optional: exclude false positives
        - 'pattern-for-safe-usage'
        - 'pattern-to-ignore'

  - id: another-template
    # ... more templates
```

### Example Template

```yaml
templates:
  - id: reentrancy-attack
    info:
      name: "Potential Reentrancy Attack"
      author: "Lynx Security Team"
      severity: high
      description: "External call before state change may allow reentrancy attacks"
      recommendation: "Use checks-effects-interactions pattern or reentrancy guards"
      references:
        - "https://swcregistry.io/docs/SWC-107"
      tags:
        - reentrancy
        - external-calls
    detection:
      patterns:
        - '\\.call\\s*\\('
        - '\\.send\\s*\\('
        - '\\.transfer\\s*\\('
      negative_patterns:
        - 'nonReentrant'
        - 'ReentrancyGuard'
```

## 🏗️ Built-in Templates

Lynx comes with templates for common vulnerabilities:

| Template ID | Severity | Description |
|-------------|----------|-------------|
| `reentrancy-call` | High | Detects potential reentrancy attacks |
| `tx-origin-auth` | High | Finds dangerous tx.origin usage |
| `unchecked-low-level-calls` | Medium | Unchecked low-level call returns |
| `integer-overflow` | High | Arithmetic overflow/underflow risks |
| `weak-randomness` | Medium | Weak randomness sources |
| `unsafe-delegatecall` | Critical | Unsafe delegatecall usage |
| `unprotected-selfdestruct` | Critical | Unprotected selfdestruct functions |
| `timestamp-dependence` | Medium | Timestamp manipulation risks |
| `dos-gas-limit` | Medium | DoS via gas limit attacks |
| `missing-zero-address-check` | Low | Missing zero address validation |

## 📊 Example Output

### Table Format (Default)
```
🔍 Found 3 potential vulnerabilities:

🔴 HIGH (2)
--------------------------------------------------------------------------------
  Potential Reentrancy Attack
  📄 VulnerableContract.sol:45
  💡 External call before state change may allow reentrancy attacks
  🔍 victim.call{value: amount}("");

  Dangerous use of tx.origin
  📄 VulnerableContract.sol:12
  💡 Using tx.origin for authentication is vulnerable to phishing
  🔍 require(tx.origin == owner);

🟡 MEDIUM (1)
--------------------------------------------------------------------------------
  Unchecked Low-Level Calls
  📄 VulnerableContract.sol:67
  💡 Low-level calls should have their return values checked
  🔍 target.call(data);

📊 Summary: 3 total findings
   HIGH: 2
   MEDIUM: 1

🚨 High risk issues detected! Review critical and high severity findings immediately.
```

### JSON Format
```json
{
  "scan_time": "2024-01-15T10:30:45",
  "total_findings": 3,
  "scanner": "Lynx v1.0.0",
  "findings": [
    {
      "template_id": "reentrancy-call",
      "name": "Potential Reentrancy Attack",
      "severity": "high",
      "file_path": "./contracts/VulnerableContract.sol",
      "line_number": 45,
      "matched_content": "victim.call{value: amount}(\"\");",
      "recommendation": "Use checks-effects-interactions pattern"
    }
  ]
}
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### 🐛 Bug Reports & Feature Requests

1. Check [existing issues](https://github.com/lynx-scanner/lynx/issues)
2. Create a [new issue](https://github.com/lynx-scanner/lynx/issues/new) with:
   - Clear description
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Your environment details

### 🔧 Code Contributions

1. **Fork the repository**
   ```bash
   git clone https://github.com/lynx-scanner/lynx.git
   cd lynx
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-new-feature
   ```

3. **Make your changes**
   - Follow PEP 8 style guidelines
   - Add tests for new functionality
   - Update documentation as needed

4. **Test your changes**
   ```bash
   # Test on sample contracts
   python lynx.py test_contracts/
   
   # Test template loading
   python lynx.py --list-templates
   ```

5. **Submit a Pull Request**
   - Clear title and description
   - Reference any related issues
   - Include test results

### 📋 Template Contributions

We especially welcome new vulnerability detection templates!

1. **Edit templates.yaml** following our template format
2. **Test the template** on real-world contracts
3. **Submit via Pull Request** with:
   - Template addition in `templates.yaml`
   - Test cases showing detection accuracy
   - References to vulnerability documentation

### 🏷️ Template Guidelines

- **Accurate Detection**: Minimize false positives/negatives
- **Clear Documentation**: Good descriptions and recommendations
- **Reference Links**: Include SWC Registry, best practices links
- **Proper Severity**: Use appropriate severity levels
- **Clean Tags**: Use descriptive tags (no CWE numbers needed)

### 📚 Documentation

Help improve documentation:
- Fix typos and clarity issues
- Add usage examples
- Create tutorials for specific use cases
- Translate documentation

## 🛠️ Development

### Project Structure
```
lynx/
├── lynx.py                      # Main scanner application
├── templates.yaml               # All vulnerability templates in one file
├── test_contracts/              # Sample contracts for testing
│   ├── VulnerableContract.sol
│   ├── SafeContract.sol
│   └── SafeMath.sol
├── requirements.txt             # Python dependencies
├── install.sh                   # Installation script
├── README.md                    # This file
└── CONTRIBUTING.md              # Contribution guidelines
```

### Testing

```bash
# Test with sample contracts
python lynx.py test_contracts/

# Test template loading
python lynx.py --list-templates

# Test custom templates
python lynx.py test_contracts/ -t your-templates.yaml

# Test output formats
python lynx.py test_contracts/ -f json
python lynx.py test_contracts/ -f detailed
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [Nuclei](https://github.com/projectdiscovery/nuclei) by ProjectDiscovery
- Vulnerability patterns based on [SWC Registry](https://swcregistry.io/)
- Best practices from [ConsenSys Smart Contract Security](https://consensys.github.io/smart-contract-best-practices/)

## 🔗 Links

- [SWC Registry](https://swcregistry.io/) - Smart Contract Weakness Classification
- [Solidity Security Considerations](https://docs.soliditylang.org/en/latest/security-considerations.html)
- [ConsenSys Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OpenZeppelin Security](https://docs.openzeppelin.com/contracts/security)
