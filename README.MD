# Web Application Vulnerability Scanner

## Description

A Python-based automated security testing tool that identifies vulnerabilities in web applications. This scanner combines custom XSS detection with OWASP ZAP integration to perform comprehensive security assessments, providing risk-scored results for actionable insights.

## Features

- **Custom XSS Detection**: Injects payloads into web forms to identify cross-site scripting vulnerabilities
- **OWASP ZAP Integration**: Leverages ZAP API for advanced spider and active scanning capabilities
- **Multi-Vulnerability Detection**: Identifies XSS, SQL Injection, and misconfiguration issues
- **Risk Scoring System**: Classifies findings as High, Medium, Low, or Informational severity
- **Detailed Reporting**: Console-based output with comprehensive scan results

## Tech Stack

- Python 3.8+
- requests
- BeautifulSoup4
- zapv2 (OWASP ZAP API client)

## Installation

### Prerequisites

- Python 3.8 or higher
- OWASP ZAP installed and running

### Steps

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/web-vulnerability-scanner.git
    cd web-vulnerability-scanner
    ```

2. Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Install OWASP ZAP:
    - Download from [zaproxy.org](https://www.zaproxy.org/download/)
    - Extract and run ZAP

4. Start ZAP with API enabled:
    ```bash
    ./zaproxy.sh -config api.disablekey=true
    ```

5. Obtain your ZAP API key from ZAP settings and configure it in the script or environment variables.

## Usage

### Basic Scan

```bash
python scanner.py --url https://example.com --target-form "login"
```

### With Custom Options

```bash
python scanner.py --url https://example.com --xss-only --risk-level high
```

### Parameters

- `--url`: Target URL to scan
- `--target-form`: Specific form to test (optional)
- `--xss-only`: Run XSS detection only (optional)
- `--risk-level`: Filter results by severity (optional)

## Project Structure

```
web-vulnerability-scanner/
├── scanner.py              # Main scanning orchestrator
├── xss_detector.py         # Custom XSS detection module
├── zap_integration.py      # OWASP ZAP API wrapper
├── risk_scorer.py          # Vulnerability severity classifier
├── requirements.txt        # Python dependencies
└── README.md              # Documentation
```

## How It Works

1. **Target Discovery**: Fetches and parses the target URL to identify forms and input fields
2. **XSS Testing**: Injects XSS payloads into discovered forms and analyzes responses
3. **ZAP Scanning**: Triggers ZAP spider and active scan modules for comprehensive coverage
4. **Vulnerability Collection**: Aggregates findings from both custom and ZAP scans
5. **Risk Assessment**: Scores vulnerabilities based on type, severity, and potential impact
6. **Report Generation**: Outputs formatted results to console with actionable details

## Sample Output

```
[*] Starting scan on https://example.com

[+] Scan Summary
     Total Vulnerabilities: 12
     High Severity: 3
     Medium Severity: 5
     Low Severity: 4

[!] High Severity Issues
     [XSS] Reflected XSS in search parameter
     Location: /search?q=
     Payload: <script>alert(1)</script>
     
     [SQL_INJECTION] Possible SQL Injection
     Location: /products?id=
     Evidence: SQL syntax error detected

[*] Scan completed in 45 seconds
```

## Limitations

- Requires OWASP ZAP to be running and accessible
- Does not test client-side vulnerabilities in JavaScript frameworks
- Limited to form-based XSS detection for custom module
- Authentication-based scanning requires manual session configuration
- May generate false positives depending on target application

## Future Improvements

- Headless browser integration for JavaScript-heavy applications
- Automated authentication handling
- Custom payload library expansion
- REST API scanning capabilities
- HTML report generation with graphs
- CI/CD pipeline integration

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes with clear messages
4. Push to the branch and submit a pull request
5. Ensure code follows PEP 8 standards

## License

This project is licensed under the MIT License. See LICENSE file for details.