from urllib.parse import urlparse
import re
import csv
import os
from datetime import datetime

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "account",
    "update", "password", "signin", "bank", "confirm",
    "wallet", "payment", "unlock", "suspended", "recover",
    "authenticate", "credential", "security", "billing", "webmail"
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "cutt.ly"
]

TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "github.com",
    "linkedin.com",
    "amazon.com",
    "apple.com",
    "microsoftonline.com"
]

HISTORY_FILE = "scan_history.csv"


def check_domain_reputation(domain):
    domain = domain.lower().strip()

    if domain in TRUSTED_DOMAINS:
        return "TRUSTED"

    for trusted in TRUSTED_DOMAINS:
        if domain.endswith("." + trusted):
            return "TRUSTED"

    return "UNKNOWN"


def check_suspicious_domain_words(domain):
    suspicious_words = [
        "login", "verify", "secure", "account", "update",
        "password", "bank", "payment", "wallet", "signin",
        "security", "support", "confirm"
    ]

    found = []

    for word in suspicious_words:
        if word in domain.lower():
            found.append(word)

    return found


def check_domain_numbers(domain):
    return len(re.findall(r"\d", domain))


def check_domain_hyphens(domain):
    return domain.count("-")


def check_subdomains(domain):
    parts = domain.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def check_url_complexity(url):
    score = 0

    if len(url) > 100:
        score += 10

    if len(url) > 150:
        score += 10

    special_characters = re.findall(r"[@?=&%_\-]", url)

    if len(special_characters) >= 6:
        score += 10

    if len(special_characters) >= 12:
        score += 10

    return score


def analyze_url(url):
    score = 0
    indicators = []
    # Basic URL validation
    original_url = url.strip()

    if not original_url:
        return 100, "HIGH RISK", ["URL is empty"]

    if not original_url.startswith(("http://", "https://")):
        test_url = "http://" + original_url
    else:
        test_url = original_url

    parsed_test = urlparse(test_url)

    if not parsed_test.hostname:
        return 100, "HIGH RISK", ["Invalid or malformed URL"]

    if "." not in parsed_test.hostname:
        return 100, "HIGH RISK", ["Invalid domain name"]
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.hostname.lower() if parsed.hostname else ""

    if not domain:
        return 100, "HIGH RISK", ["Invalid or malformed URL"]

    full_url = url.lower()
    path = parsed.path.lower()

    # HTTPS / HTTP
    if parsed.scheme == "http":
        score += 15
        indicators.append("Uses HTTP instead of HTTPS")
    else:
        indicators.append("Uses HTTPS")

    # IP address
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, domain):
        score += 25
        indicators.append(
            "Uses an IP address instead of a domain name"
        )

    # Domain reputation
    reputation = check_domain_reputation(domain)

    if reputation == "TRUSTED":
        indicators.append(
            "Domain is listed in the local trusted-domain database"
        )
    else:
        indicators.append(
            "Domain is not listed in the local trusted-domain database"
        )

    # Suspicious keywords
    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url:
            found_keywords.append(keyword)

    if found_keywords:
        points = min(len(found_keywords) * 5, 30)
        score += points

        indicators.append(
            "Contains suspicious keywords: "
            + ", ".join(found_keywords)
        )

    # Suspicious paths
    suspicious_paths = [
        "/login",
        "/signin",
        "/verify",
        "/verification",
        "/password",
        "/account",
        "/payment",
        "/wallet",
        "/update",
        "/secure",
        "/authenticate"
    ]

    found_paths = [
        item for item in suspicious_paths if item in path
    ]

    if found_paths:
        score += 10
        indicators.append(
            "Contains a suspicious authentication or payment path"
        )

    # @ symbol
    if "@" in url:
        score += 20
        indicators.append(
            "Contains @ symbol, which can obscure the destination"
        )

    # Subdomains
    subdomain_count = check_subdomains(domain)

    if subdomain_count >= 2:
        score += 10
        indicators.append(
            f"Contains multiple subdomains ({subdomain_count})"
        )

    if subdomain_count >= 4:
        score += 10
        indicators.append(
            "Contains an unusually deep subdomain structure"
        )

    # Hyphens
    hyphen_count = check_domain_hyphens(domain)

    if hyphen_count >= 2:
        score += 10
        indicators.append(
            f"Domain contains multiple hyphens ({hyphen_count})"
        )

    if hyphen_count >= 4:
        score += 10
        indicators.append(
            "Domain contains an unusually high number of hyphens"
        )

    # Numbers
    digit_count = check_domain_numbers(domain)

    if digit_count >= 3:
        score += 10
        indicators.append(
            f"Domain contains several numeric characters ({digit_count})"
        )

    if digit_count >= 6:
        score += 10
        indicators.append(
            "Domain contains an unusually high number of digits"
        )

    # URL shortener
    if domain in URL_SHORTENERS:
        score += 20
        indicators.append(
            "Uses a URL shortening service"
        )

    # Suspicious TLD
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        indicators.append(
            "Uses a potentially suspicious top-level domain"
        )

    # Punycode
    if domain.startswith("xn--") or ".xn--" in domain:
        score += 20
        indicators.append(
            "Uses Punycode, which may be associated with "
            "look-alike domains"
        )

    # URL encoding
    if "%" in url:
        score += 5
        indicators.append(
            "Contains URL-encoded characters"
        )

    # Query parameters
    if parsed.query:
        parameter_count = len(parsed.query.split("&"))

        if parameter_count >= 4:
            score += 10
            indicators.append(
                f"Contains many query parameters ({parameter_count})"
            )

        if parameter_count >= 8:
            score += 10
            indicators.append(
                "Contains an unusually large number of query parameters"
            )

    # Deep path
    path_parts = [
        part for part in parsed.path.split("/") if part
    ]

    if len(path_parts) >= 5:
        score += 10
        indicators.append(
            "URL contains an unusually deep path"
        )

    if len(path_parts) >= 8:
        score += 10
        indicators.append(
            "URL contains an extremely deep path structure"
        )

    # Special characters
    special_characters = re.findall(r"[@?=&%]", url)

    if len(special_characters) >= 6:
        score += 10
        indicators.append(
            "Contains an unusually high number of special characters"
        )

    # Non-standard port
    try:
        port = parsed.port
    except ValueError:
        return 100, "HIGH RISK", ["Invalid port number in URL"]

    if port is not None:
        score += 5
        indicators.append(
            f"Uses a non-standard port: {port}"
        )

    # Suspicious words in domain
    suspicious_domain_words = check_suspicious_domain_words(domain)

    if suspicious_domain_words:
        score += min(len(suspicious_domain_words) * 5, 15)

        indicators.append(
            "Suspicious terms found in domain: "
            + ", ".join(suspicious_domain_words)
        )

    # Domain length
    if len(domain) > 40:
        score += 10
        indicators.append(
            "Domain name is unusually long"
        )

    if len(domain) > 60:
        score += 10
        indicators.append(
            "Domain name is extremely long"
        )

    # URL complexity
    complexity_score = check_url_complexity(url)

    score += complexity_score

    if complexity_score >= 10:
        indicators.append(
            "URL has a high level of structural complexity"
        )

    # Limit score
    score = min(score, 100)

    # Verdict
    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return score, verdict, indicators


def save_scan(url, score, verdict, indicators):
    file_exists = os.path.exists(HISTORY_FILE)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(
        HISTORY_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "Timestamp",
                "URL",
                "Risk Score",
                "Verdict",
                "Indicators"
            ])

        writer.writerow([
            timestamp,
            url,
            score,
            verdict,
            " | ".join(indicators)
        ])

    return timestamp


def show_history():
    if not os.path.exists(HISTORY_FILE):
        print("\nNo scan history found.")
        return

    print("\n" + "=" * 75)
    print("                         SCAN HISTORY")
    print("=" * 75)

    with open(
        HISTORY_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)
        scans = list(reader)

    if not scans:
        print("\nNo scans recorded.")
        return

    for number, scan in enumerate(scans, start=1):

        print(f"\nScan #{number}")
        print("-" * 75)
        print(f"Timestamp : {scan['Timestamp']}")
        print(f"URL       : {scan['URL']}")
        print(f"Score     : {scan['Risk Score']}/100")
        print(f"Verdict   : {scan['Verdict']}")
        print(f"Indicators: {scan['Indicators']}")

    print("\n" + "=" * 75)


def main():
    print("=" * 55)
    print("             PHISHING URL DETECTOR")
    print("              PHASE 6 ENGINE")
    print("=" * 55)

    while True:

        print("\n1. Scan URL")
        print("2. View Scan History")
        print("3. Exit")

        choice = input(
            "\nSelect an option: "
        ).strip()

        if choice == "1":

            url = input(
                "\nEnter a URL to analyze: "
            ).strip()

            if not url:
                print("\n[!] Please enter a URL.")
                continue

            score, verdict, indicators = analyze_url(url)

            timestamp = save_scan(
                url,
                score,
                verdict,
                indicators
            )

            print("\n--- Analysis Result ---")
            print(f"URL: {url}")
            print(f"Timestamp: {timestamp}")
            print(f"Risk Score: {score}/100")
            print(f"Verdict: {verdict}")

            print("\nIndicators:")

            for indicator in indicators:
                print(f"[!] {indicator}")

            print(
                "\n[+] Scan saved to scan_history.csv"
            )

        elif choice == "2":
            show_history()

        elif choice == "3":
            print(
                "\nExiting Phishing URL Detector..."
            )
            break

        else:
            print(
                "\n[!] Invalid option. Please choose 1, 2, or 3."
            )


if __name__ == "__main__":
    main()