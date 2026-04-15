import requests
from bs4 import BeautifulSoup
import re
import time
from zapv2 import ZAPv2

# function to perform xss scan
def scan_for_xss(url):
    print(f"\n[*] Starting basic XSS check on: {url}")
    findings = []

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

    except requests.exceptions.Timeout:
        print("[-] Error: Request timed out.")
        return findings
    except requests.exceptions.ConnectionError:
        print("[-] Error: Connection failed.")
        return findings
    except requests.exceptions.HTTPError as e:
        print(f"[-] HTTP Error: {e.response.status_code}")
        return findings

    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        print("[-] No forms found.")
        return findings

    xss_payload = "<script>alert('XSS')</script>"

    for form in forms:
        action = form.get('action')
        if not action:
            continue

        method = form.get('method', 'get').lower()
        form_url = requests.compat.urljoin(url, action)

        inputs = form.find_all('input')
        form_data = {}

        for input_tag in inputs:
            name = input_tag.get('name')
            if not name:
                continue

            if input_tag.get('type') == 'hidden':
                form_data[name] = input_tag.get('value', '')
            else:
                form_data[name] = xss_payload

        try:
            if method == 'post':
                test_response = requests.post(form_url, data=form_data, timeout=10)
            else:
                test_response = requests.get(form_url, params=form_data, timeout=10)

            if re.search(re.escape(xss_payload), test_response.text, re.IGNORECASE):
                print(f"[!!!] Potential XSS found at: {test_response.url}")
                findings.append({
                    "type": "XSS",
                    "url": test_response.url,
                    "risk": "High"
                })
            else:
                print(f"[+] Tested form at {form_url} - No reflection detected")

        except requests.exceptions.RequestException as e:
            print(f"[-] Request error while testing form: {e}")

    return findings

# zap scanning function
def run_zap_scan(target_url, api_key, proxy_address):
    print("\n[*] Connecting to OWASP ZAP...")
    findings = []

    try:
        zap = ZAPv2(
            proxies={'http': proxy_address, 'https': proxy_address},
            apikey=api_key
        )

        # Spider scan
        print("[*] Starting Spider Scan...")
        scan_id = zap.spider.scan(target_url)

        while int(zap.spider.status(scan_id)) < 100:
            print(f"[*] Spider Progress: {zap.spider.status(scan_id)}%")
            time.sleep(2)

        print("[+] Spider completed")

        # Active scan
        print("[*] Starting Active Scan...")
        scan_id = zap.ascan.scan(target_url)

        while int(zap.ascan.status(scan_id)) < 100:
            print(f"[*] Active Scan Progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)

        print("[+] Active scan completed")

        # alerts found
        alerts = zap.core.alerts()

        if not alerts:
            print("[+] No vulnerabilities found by ZAP")
            return findings

        print("\n[--- ZAP RESULTS ---]")

        for alert in alerts:
            finding = {
                "type": alert.get('alert'),
                "url": alert.get('url'),
                "risk": alert.get('risk'),
                "confidence": alert.get('confidence')
            }
            findings.append(finding)

            print("=" * 50)
            print(f"Vulnerability : {alert.get('alert')}")
            print(f"URL           : {alert.get('url')}")
            print(f"Risk          : {alert.get('risk')}")
            print(f"Confidence    : {alert.get('confidence')}")
            print(f"Description   : {alert.get('description')}")

    except Exception as e:
        print(f"[-] ZAP Error: {e}")

    return findings


#function to calculate the risk
def calculate_risk(findings):
    risk_map = {
        "High": 75,
        "Medium": 50,
        "Low": 25,
        "Informational": 10
    }

    if not findings:
        print("\n[+] Overall Risk: 0% (No issues found)")
        return

    total_score = 0

    for f in findings:
        total_score += risk_map.get(f["risk"], 0)

    avg_risk = total_score / len(findings)

    print("\n[--- FINAL RISK REPORT ---]")
    print(f"[+] Total Findings : {len(findings)}")
    print(f"[+] Estimated Risk : {avg_risk:.2f}%")

    if avg_risk > 70:
        print("[!!!] Critical Risk مستوى")
    elif avg_risk > 40:
        print("[!] Moderate Risk")
    else:
        print("[+] Low Risk")


# MAIN
if __name__ == "__main__":
    TARGET_URL = "https://in.www-y2mate.com/"  #website url to be scanned
    API_KEY = "mvbei4ievubc2brtguo8bojpm2"  #ZAP API key
    PROXY = "http://127.0.0.1:8080"    #proxy server

    all_findings = []

    # Run scanners
    xss_findings = scan_for_xss(TARGET_URL)
    zap_findings = run_zap_scan(TARGET_URL, API_KEY, PROXY)

    # Combine results
    all_findings.extend(xss_findings)
    all_findings.extend(zap_findings)

    # Calculate risk
    calculate_risk(all_findings)