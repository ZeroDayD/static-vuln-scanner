# 🛡️ Static Vulnerability Scanner

A lightweight static analysis tool to catch dangerous patterns in `.js`, `.py`, and `.php` files — like `eval()`, raw SQL, or `innerHTML`.

## 🔍 What it Detects

By default, detects:

- XSS via `innerHTML`
- Use of `eval()` in JavaScript
- Raw SQL with string concatenation (Python)
- SQL injection via `$_GET`, `$_POST` (PHP)

Rules are defined in `patterns.yaml`.

## 🚀 How to Run

1. Clone the repository
2. Install Python and PyYAML: `pip install pyyaml`
3. Run the scanner: `python scanner.py`

## 📦 Output

- Console output shows files, lines, and matched rules
- A SARIF report (`results.sarif`) is generated for CI integrations

## 🧪 Example Usage

Scan all supported files in the repo:

`python scanner.py`

Sample match:

`[!] Match: xss-innerhtml in sample-code/insecure.js at line 2: document.body.innerHTML = "<div>" + userInput + "</div>";`

## ⚙️ Customize Patterns

You can edit or add your own rules in `patterns.yaml`, for example:

- id: suspicious-base64  
  description: "Suspicious use of base64"  
  regex: 'base64_decode\\s*\\('

## 🛠️ GitHub Actions CI

A prebuilt GitHub Actions workflow is available in `.github/workflows/security.yml`.  
It runs on pull requests and uploads SARIF artifacts if issues are found.
