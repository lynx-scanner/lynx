# Contributing to Lynx 🤝

Thank you for your interest in contributing to Lynx! This guide will help you get started with contributing to our smart contract vulnerability scanner.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Types of Contributions](#types-of-contributions)
- [Development Setup](#development-setup)
- [Contributing Templates](#contributing-templates)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)

## 📜 Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences
- Show empathy towards other community members

## 🚀 Getting Started

### Prerequisites

- Python 3.7 or higher
- Basic understanding of smart contract security
- Familiarity with regular expressions (for template creation)
- Git and GitHub knowledge

### Quick Setup

1. **Fork the repository** on GitHub
2. **Clone your fork locally:**
   ```bash
   git clone https://github.com/YOUR-USERNAME/lynx.git
   cd lynx
   ```
3. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
5. **Test the installation:**
   ```bash
   python lynx.py --list-templates
   ```

## 🎯 Types of Contributions

We welcome various types of contributions:

### 🐛 Bug Reports
- Report issues with scanning accuracy
- Documentation errors
- Performance problems
- Installation issues

### ✨ Feature Requests
- New output formats
- Enhanced filtering options
- Integration capabilities
- User experience improvements

### 🔍 Vulnerability Templates
- New vulnerability detection patterns
- Improvements to existing templates
- Reduction of false positives/negatives
- Coverage for emerging vulnerabilities

### 📚 Documentation
- README improvements
- Code documentation
- Usage examples
- Tutorial creation

### 🧪 Testing
- Test case creation
- Performance testing
- Edge case coverage
- Integration testing

## 🛠️ Development Setup

### Project Structure
```
lynx/
├── lynx.py                      # Main scanner application
├── templates.yaml               # All vulnerability templates
├── test_contracts/              # Sample vulnerable contracts
│   ├── VulnerableContract.sol
│   ├── SafeContract.sol
│   └── SafeMath.sol
├── tests/                       # Unit tests
├── docs/                        # Documentation
├── requirements.txt             # Dependencies
├── README.md                    # Main documentation
└── CONTRIBUTING.md              # This file
```

### Development Workflow

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**

3. **Test thoroughly:**
   ```bash
   # Test basic functionality
   python lynx.py test_contracts/
   
   # Test template loading
   python lynx.py --list-templates
   
   # Test different output formats
   python lynx.py test_contracts/ -f json
   python lynx.py test_contracts/ -f detailed
   ```

4. **Commit your changes:**
   ```bash
   git add .
   git commit -m "feat: add new vulnerability template for..."
   ```

5. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request**

## 🔍 Contributing Templates

Vulnerability templates are the heart of Lynx. Here's how to contribute high-quality templates:

### Template Creation Process

1. **Research the Vulnerability:**
   - Study the vulnerability pattern
   - Understand common manifestations
   - Identify edge cases and false positives

2. **Create Test Cases:**
   ```solidity
   // vulnerable_example.sol
   contract VulnerableContract {
       function vulnerable() external {
           // Code that should trigger your template
       }
       
       function safe() external {
           // Code that should NOT trigger your template
       }
   }
   ```

3. **Add Template to templates.yaml:**
   ```yaml
   templates:
     - id: your-vulnerability-id
       info:
         name: "Descriptive Vulnerability Name"
         author: "Your Name <your.email@example.com>"
         severity: high  # critical|high|medium|low|info
         description: "Clear description of the vulnerability"
         recommendation: "Specific steps to fix the issue"
         references:
           - "https://swcregistry.io/docs/SWC-XXX"
           - "https://consensys.github.io/smart-contract-best-practices/"
         tags:
           - vulnerability-category
           - specific-type
       detection:
         patterns:
           - 'regex-pattern-for-detection'
           - 'additional-pattern-if-needed'
         negative_patterns:  # Optional: reduce false positives
           - 'pattern-for-safe-usage'
   ```

4. **Test Your Template:**
   ```bash
   # Test on your vulnerable contract
   python lynx.py vulnerable_example.sol
   
   # Test on safe contracts to check for false positives
   python lynx.py safe_contracts/ --tags your-category
   ```

### Template Quality Guidelines

#### ✅ Good Template Practices

- **Precise Patterns:** Use specific regex patterns that minimize false positives
- **Comprehensive Coverage:** Cover different ways the vulnerability can manifest
- **Clear Documentation:** Provide detailed descriptions and actionable recommendations
- **Proper Severity:** Use appropriate severity levels based on impact
- **Reference Links:** Include authoritative sources (SWC Registry, documentation)
- **Clean Tags:** Use descriptive tags without CWE numbers

#### ❌ Avoid These Pitfalls

- **Overly Broad Patterns:** Avoid patterns that match too much code
- **Missing Context:** Don't ignore legitimate use cases
- **Unclear Descriptions:** Avoid vague or technical jargon without explanation
- **Wrong Severity:** Don't misclassify vulnerability severity
- **Missing References:** Always include supporting documentation

### Template Examples

#### High-Quality Template
```yaml
templates:
  - id: unsafe-delegatecall
    info:
      name: "Unsafe Delegatecall to User-Controlled Address"
      author: "Security Team <security@lynx-scanner.dev>"
      severity: critical
      description: "Delegatecall to user-controlled address can allow arbitrary code execution"
      recommendation: "Validate delegatecall targets against a whitelist of trusted contracts"
      references:
        - "https://swcregistry.io/docs/SWC-112"
        - "https://consensys.github.io/smart-contract-best-practices/attacks/delegatecall/"
      tags:
        - delegatecall
        - arbitrary-execution
    detection:
      patterns:
        - '\\w+\\.delegatecall\\s*\\('
        - 'delegatecall\\s*\\([^)]*msg\\.(sender|data)'
      negative_patterns:
        - 'require\\s*\\(\\s*trusted\\[.*\\]'
        - 'whitelist\\[.*\\]'
        - '// verified contract'
```

## 🔄 Pull Request Process

### Before Submitting

1. **Ensure your code works:**
   - Test on multiple contract examples
   - Verify no regressions in existing functionality
   - Check that new templates don't cause excessive false positives

2. **Update documentation:**
   - Add your template to the README if it's a major addition
   - Update any relevant documentation
   - Include code comments for complex logic

3. **Follow coding standards:**
   - Use consistent formatting
   - Follow Python PEP 8 guidelines
   - Use meaningful variable and function names

### Pull Request Template

When creating a pull request, please include:

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Vulnerability template
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Tested on sample contracts
- [ ] Verified no false positives
- [ ] All existing tests pass
- [ ] Added new tests if applicable

## Templates Added/Modified
List any templates added or modified:
- `template-name` - Description of what it detects

## References
Links to vulnerability documentation, SWC entries, etc.

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No sensitive information included
```

### Review Process

1. **Automated Checks:** Basic linting and functionality tests
2. **Template Review:** Accuracy and quality assessment for templates
3. **Code Review:** Logic, style, and performance review
4. **Security Review:** Ensure no vulnerabilities introduced
5. **Final Approval:** Maintainer approval and merge

## 📏 Coding Standards

### Python Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines
- Use descriptive variable and function names
- Add docstrings for classes and functions
- Keep functions focused and small
- Use type hints where helpful

### Template Standards

- Use descriptive template IDs (kebab-case)
- Include all required fields in template YAML
- Use precise regex patterns
- Test patterns against multiple contract examples
- Include comprehensive documentation

### Documentation Standards

- Use clear, concise language
- Include code examples where helpful
- Keep README and documentation up-to-date
- Use proper markdown formatting
- Include links to external references

## 🧪 Testing Guidelines

### Template Testing

1. **Create Test Contracts:**
   ```solidity
   // Should trigger the template
   contract VulnerableExample {
       // vulnerable code here
   }
   
   // Should NOT trigger the template
   contract SafeExample {
       // safe code here
   }
   ```

2. **Test Against Real Projects:**
   - Test on popular open-source contracts
   - Verify detection accuracy
   - Check for false positives

3. **Edge Case Testing:**
   - Test with unusual but valid syntax
   - Test with comments and documentation
   - Test with mixed coding styles

### Regression Testing

Before submitting changes:
```bash
# Test core functionality
python lynx.py test_contracts/

# Test template loading
python lynx.py --list-templates

# Test different formats
python lynx.py test_contracts/ -f json
python lynx.py test_contracts/ -f detailed

# Test custom templates
python lynx.py test_contracts/ -t your-templates.yaml
```

## 🆘 Getting Help

- **GitHub Issues:** Create an issue for bugs or feature requests
- **GitHub Discussions:** Ask questions in our [Discussions](https://github.com/lynx-scanner/lynx/discussions)
- **Email:** Reach out to maintainers at security@lynx-scanner.dev

## 🏆 Recognition

Contributors will be recognized in:
- README contributors section
- Release notes for significant contributions
- Template author attribution
- Annual contributor acknowledgments

## 📝 License

By contributing to Lynx, you agree that your contributions will be licensed under the same MIT License that covers the project.
