import re
from urllib.parse import urlparse


# Known legitimate domains (whitelist)
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "paypal.com", "github.com", "wikipedia.org",
    "yahoo.com", "reddit.com", "whatsapp.com", "zoom.us", "dropbox.com",
    "adobe.com", "shopify.com", "wordpress.com", "stackoverflow.com",
}

# Keywords often found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "payment", "password", "credential", "validate", "unlock",
    "suspended", "alert", "urgent", "ebayisapi", "webscr",
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click", ".link"]


def extract_features(url: str) -> dict:
    """Extract all URL features for analysis."""
    # Normalize
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    full_url = url
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Strip www.
    bare_domain = domain.replace("www.", "")

    features = {
        "url": full_url,
        "domain": domain or parsed.path,
        "protocol": parsed.scheme.upper(),
        "url_length": len(full_url),
        "domain_length": len(bare_domain),
        "path_length": len(path),
        "dot_count": domain.count("."),
        "hyphen_count": domain.count("-"),
        "has_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", bare_domain.split(":")[0])),
        "has_at_symbol": "@" in full_url,
        "has_https": parsed.scheme == "https",
        "has_double_slash": "//" in full_url[7:],
        "subdomain_count": len(bare_domain.split(".")) - 2,
        "phishing_keywords": [kw for kw in PHISHING_KEYWORDS if kw in full_url.lower()],
        "suspicious_tld": any(bare_domain.endswith(tld) for tld in SUSPICIOUS_TLDS),
        "is_trusted": bare_domain in TRUSTED_DOMAINS or any(
            bare_domain.endswith("." + td) for td in TRUSTED_DOMAINS
        ),
        "brand_impersonation": _check_brand_impersonation(bare_domain),
    }
    return features


def _check_brand_impersonation(domain: str) -> str | None:
    """Check if domain impersonates a known brand."""
    brands = ["google", "facebook", "paypal", "apple", "microsoft", "amazon",
              "netflix", "instagram", "twitter", "whatsapp"]
    for brand in brands:
        # Contains brand name but is NOT the real domain
        if brand in domain and not (
            domain == f"{brand}.com"
            or domain.endswith(f".{brand}.com")
        ):
            return brand
    return None


def calculate_score(features: dict) -> tuple[int, list[dict]]:
    """
    Calculate a risk score (0-100) and return flag details.
    100 = fully safe, 0 = definite phishing.
    """
    score = 100
    flags = []

    # ── Immediate trust boost ──────────────────────────────────────
    if features["is_trusted"]:
        score = min(score, 95)
        flags.append({"type": "safe", "msg": "Domain is a well-known trusted website"})
        # Still check HTTPS even for trusted domains
        if not features["has_https"]:
            score -= 10
            flags.append({"type": "warn", "msg": "Connection is not encrypted (HTTP)"})
        return max(score, 0), flags

    # ── Deductions ─────────────────────────────────────────────────
    if features["has_ip"]:
        score -= 40
        flags.append({"type": "danger", "msg": "URL uses an IP address instead of a domain name"})

    if not features["has_https"]:
        score -= 20
        flags.append({"type": "danger", "msg": "Connection is not encrypted (HTTP)"})
    else:
        flags.append({"type": "safe", "msg": "Uses HTTPS encryption"})

    if features["has_at_symbol"]:
        score -= 25
        flags.append({"type": "danger", "msg": "URL contains '@' symbol — browser ignores everything before it"})

    if features["brand_impersonation"]:
        score -= 35
        flags.append({"type": "danger", "msg": f"Domain impersonates '{features['brand_impersonation']}' — likely phishing"})

    if features["phishing_keywords"]:
        deduction = min(len(features["phishing_keywords"]) * 10, 30)
        score -= deduction
        kws = ", ".join(features["phishing_keywords"])
        flags.append({"type": "warn", "msg": f"Suspicious keywords found: {kws}"})

    if features["suspicious_tld"]:
        score -= 20
        flags.append({"type": "warn", "msg": "Domain uses a high-risk top-level domain"})

    if features["hyphen_count"] >= 2:
        score -= 10
        flags.append({"type": "warn", "msg": f"Domain has {features['hyphen_count']} hyphens — common in fake domains"})

    if features["dot_count"] >= 4:
        score -= 15
        flags.append({"type": "warn", "msg": f"Excessive dots ({features['dot_count']}) suggest subdomain spoofing"})
    elif features["subdomain_count"] >= 2:
        score -= 8
        flags.append({"type": "warn", "msg": "Multiple subdomains can mask the real domain"})

    if features["url_length"] > 100:
        score -= 15
        flags.append({"type": "warn", "msg": f"Very long URL ({features['url_length']} chars) — often used to hide true destination"})
    elif features["url_length"] > 75:
        score -= 5
        flags.append({"type": "warn", "msg": f"URL is unusually long ({features['url_length']} chars)"})

    if features["has_double_slash"]:
        score -= 10
        flags.append({"type": "warn", "msg": "URL contains double slash after protocol — redirect attempt"})

    # ── Positive signals ───────────────────────────────────────────
    if features["hyphen_count"] == 0 and features["dot_count"] == 1:
        score = min(score + 5, 100)
        flags.append({"type": "safe", "msg": "Clean, simple domain structure"})

    return max(score, 0), flags


def verdict(score: int) -> dict:
    if score >= 80:
        return {"label": "Legitimate", "emoji": "✅", "color": "safe"}
    elif score >= 50:
        return {"label": "Suspicious", "emoji": "⚠️", "color": "warn"}
    else:
        return {"label": "Phishing", "emoji": "❌", "color": "danger"}


def analyze_url(url: str) -> dict:
    """Main entry point. Returns full analysis result."""
    url = url.strip()
    if not url:
        return {"error": "Please enter a URL."}

    features = extract_features(url)
    score, flags = calculate_score(features)
    result = verdict(score)

    return {
        "url": features["url"],
        "domain": features["domain"],
        "protocol": features["protocol"],
        "url_length": features["url_length"],
        "score": score,
        "verdict": result,
        "flags": flags,
        "details": {
            "Has HTTPS": features["has_https"],
            "IP Address Used": features["has_ip"],
            "@ Symbol Present": features["has_at_symbol"],
            "Suspicious TLD": features["suspicious_tld"],
            "Hyphens in Domain": features["hyphen_count"],
            "Dot Count": features["dot_count"],
            "Subdomains": max(features["subdomain_count"], 0),
        }
    }
