# Contributing to IntelProbe

Thank you for your interest in contributing to **IntelProbe**! This document provides guidelines for contributing to the project.

## 👨‍💻 Project Owner

**Lintshiwe Slade** ([@lintshiwe](https://github.com/lintshiwe))

- Creator and Lead Developer
- GitHub: https://github.com/lintshiwe
- Email: lintshiwe.slade@intelprobe.dev

## 🤝 How to Contribute

### 1. Fork the Repository

1. Fork the [IntelProbe repository](https://github.com/lintshiwe/IntelProbe)
2. Clone your fork locally
3. Create a new branch for your feature or fix

### 2. Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/IntelProbe.git
cd IntelProbe

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8 mypy
```

### 3. Making Changes

- Follow the existing code style
- Write clear, descriptive commit messages
- Add tests for new functionality
- Update documentation as needed

### 4. Testing

```bash
# Run tests
python -m pytest

# Run code formatting
black .

# Run linting
flake8 .

# Run type checking
mypy .
```

### 5. Submit a Pull Request

1. Push your changes to your fork
2. Submit a pull request to the main repository
3. Provide a clear description of your changes
4. Reference any related issues

## 📋 Guidelines

### Code Style

- Follow PEP 8 Python style guidelines
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and concise

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in present tense
- Reference issue numbers when applicable

Example:

```
Add advanced OS detection methods

- Implement TTL-based fingerprinting
- Add MAC vendor analysis
- Improve confidence scoring system

Fixes #123
```

### Documentation

- Update README.md for significant changes
- Add inline comments for complex logic
- Update docstrings for API changes

## 🐛 Reporting Issues

When reporting issues, please include:

- Operating system and version
- Python version
- Steps to reproduce the issue
- Expected vs actual behavior
- Error messages or logs

## 🔒 Security

For security vulnerabilities, please contact:

- Email: lintshiwe.slade@intelprobe.dev
- Do not create public issues for security vulnerabilities

## 📄 License

By contributing to IntelProbe, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

All contributors will be recognized in the project documentation and release notes.

---

**IntelProbe** - Created by [Lintshiwe Slade](https://github.com/lintshiwe)
