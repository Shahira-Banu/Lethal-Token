import math
import cv2
import requests
from urllib.parse import urlparse
from notifier import AlertNotifier

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log2(p) for p in prob])

def extract_qr_url(image_path: str) -> str:
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(f"Unable to load image file at: {image_path}")

    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img)

    if not data:
        raise ValueError("No valid QR code pattern detected in the image.")
    return data

def unroll_redirects(initial_url: str, max_hops: int = 10) -> list:
    chain = [initial_url]
    current_url = initial_url
    headers = {"User-Agent": "LethalToken-Security Inspector/1.0"}

    for _ in range(max_hops):
        try:
            response = requests.head(current_url, allow_redirects=False, headers=headers, timeout=5)
            if response.status_code in (301, 302, 303, 307, 308) and "Location" in response.headers:
                next_url = response.headers["Location"]
                if not next_url.startswith("http"):
                    parsed = urlparse(current_url)
                    next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                chain.append(next_url)
                current_url = next_url
            else:
                break
        except requests.RequestException:
            break

    return chain

def analyze_domain_risk(final_url: str) -> dict:
    parsed = urlparse(final_url)
    domain = parsed.netloc.lower()

    entropy = calculate_shannon_entropy(domain)
    suspicious_tlds = [".zip", ".top", ".xyz", ".kim", ".work", ".gq", ".cf", ".fit"]
    suspicious_keywords = ["login", "verify", "banking", "secure", "update", "account"]

    is_high_entropy = entropy > 3.8
    has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
    has_keyword = any(kw in domain for kw in suspicious_keywords)
    has_digit_substitution = any(char.isdigit() for char in domain)

    risk_score = 0
    if is_high_entropy: risk_score += 35
    if has_suspicious_tld: risk_score += 35
    if has_keyword: risk_score += 15
    if has_digit_substitution: risk_score += 15

    return {
        "final_domain": domain,
        "entropy": round(entropy, 2),
        "risk_score": min(risk_score, 100),
        "verdict": "SUSPICIOUS / PHISHING" if risk_score >= 50 else "SAFE / LOW RISK"
    }

def inspect_qr_or_url(target_input: str, is_image: bool = True, notifier: AlertNotifier = None):
    print(f"\n[*] Starting Quishing & Link Inspection...")
    
    if is_image:
        print(f"[*] Extracting URL from QR image: {target_input}")
        initial_url = extract_qr_url(target_input)
    else:
        initial_url = target_input

    print(f"[+] Initial extracted URL: {initial_url}")
    print(f"[*] Unrolling redirect chain...")
    redirect_chain = unroll_redirects(initial_url)

    final_url = redirect_chain[-1]
    hops_count = len(redirect_chain) - 1

    print(f"[+] Redirect Hops ({hops_count}): {' -> '.join(redirect_chain)}")

    risk_report = analyze_domain_risk(final_url)

    if notifier:
        severity = "HIGH" if risk_report["risk_score"] >= 50 else "LOW"
        notifier.send_alert(
            title="Quishing / Link Inspection Completed",
            description=f"Link inspection analyzed {hops_count} redirect hop(s).",
            fields={
                "Initial Target": initial_url,
                "Final Destination": final_url,
                "Redirect Hops": hops_count,
                "Domain Entropy": risk_report["entropy"],
                "Risk Score": f"{risk_report['risk_score']}/100",
                "Verdict": risk_report["verdict"]
            },
            severity=severity
        )

    return {
        "initial_url": initial_url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "analysis": risk_report
    }