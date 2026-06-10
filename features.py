import re
import urllib.parse

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'secure', 'account',
    'banking', 'confirm', 'password', 'credential', 'ebayisapi',
    'webscr', 'paypal', 'free', 'lucky', 'prize', 'winner',
    'click', 'urgent', 'suspend', 'alert', 'unusual', 'limited'
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.work']

TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'twitter.com', 'linkedin.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'instagram.com'
]

def extract_features(url):
    """Extract 8 features from a URL for phishing detection."""
    features = {}
    url_lower = url.lower().strip()

    # Ensure URL has scheme
    if not url_lower.startswith(('http://', 'https://')):
        url_lower = 'http://' + url_lower

    try:
        parsed = urllib.parse.urlparse(url_lower)
        domain = parsed.netloc
        path = parsed.path
        full_url = url_lower
    except:
        domain = ""
        path = ""
        full_url = url_lower

    # Feature 1: URL Length (longer = more suspicious)
    url_len = len(url)
    if url_len < 54:
        features['url_length'] = 0      # Short = legit
    elif url_len < 75:
        features['url_length'] = 1      # Medium = suspicious
    else:
        features['url_length'] = 2      # Long = phishing

    # Feature 2: Has IP address instead of domain
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    features['has_ip'] = 1 if ip_pattern.search(domain) else 0

    # Feature 3: Count of dots in domain
    dot_count = domain.count('.')
    features['dot_count'] = min(dot_count, 5)

    # Feature 4: Suspicious keywords in URL
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in full_url)
    features['keyword_count'] = min(keyword_count, 5)

    # Feature 5: Has HTTPS
    features['has_https'] = 1 if url_lower.startswith('https://') else 0

    # Feature 6: URL has @ symbol (used to trick browsers)
    features['has_at_symbol'] = 1 if '@' in url else 0

    # Feature 7: Suspicious TLD
    features['suspicious_tld'] = 0
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            features['suspicious_tld'] = 1
            break

    # Feature 8: Subdomain depth (many subdomains = suspicious)
    domain_parts = domain.split('.')
    subdomain_depth = max(len(domain_parts) - 2, 0)
    features['subdomain_depth'] = min(subdomain_depth, 5)

    return features


def get_feature_vector(url):
    """Return features as ordered list for ML model."""
    f = extract_features(url)
    return [
        f['url_length'],
        f['has_ip'],
        f['dot_count'],
        f['keyword_count'],
        f['has_https'],
        f['has_at_symbol'],
        f['suspicious_tld'],
        f['subdomain_depth'],
    ]


def get_feature_explanation(url):
    """Return human-readable explanation of each feature."""
    f = extract_features(url)
    explanations = []

    if f['url_length'] == 2:
        explanations.append(("URL Length", "red", f"Very long URL ({len(url)} chars) — common phishing tactic to hide malicious domain"))
    elif f['url_length'] == 1:
        explanations.append(("URL Length", "orange", f"Moderately long URL ({len(url)} chars)"))
    else:
        explanations.append(("URL Length", "green", f"Normal URL length ({len(url)} chars)"))

    if f['has_ip']:
        explanations.append(("IP Address", "red", "URL uses raw IP address instead of domain — strong phishing indicator"))
    else:
        explanations.append(("IP Address", "green", "Uses proper domain name"))

    if f['dot_count'] >= 4:
        explanations.append(("Dot Count", "red", f"{f['dot_count']} dots in domain — excessive subdomains often indicate phishing"))
    elif f['dot_count'] == 3:
        explanations.append(("Dot Count", "orange", f"{f['dot_count']} dots — slightly elevated"))
    else:
        explanations.append(("Dot Count", "green", f"{f['dot_count']} dots — normal"))

    if f['keyword_count'] >= 3:
        explanations.append(("Phishing Keywords", "red", f"{f['keyword_count']} suspicious keywords found (login, verify, secure, etc.)"))
    elif f['keyword_count'] >= 1:
        explanations.append(("Phishing Keywords", "orange", f"{f['keyword_count']} suspicious keyword(s) found"))
    else:
        explanations.append(("Phishing Keywords", "green", "No suspicious keywords detected"))

    if f['has_https']:
        explanations.append(("HTTPS", "green", "Secure HTTPS connection"))
    else:
        explanations.append(("HTTPS", "red", "No HTTPS — data transmitted insecurely"))

    if f['has_at_symbol']:
        explanations.append(("@ Symbol", "red", "@ symbol in URL — used to trick browsers into visiting malicious domains"))
    else:
        explanations.append(("@ Symbol", "green", "No @ symbol"))

    if f['suspicious_tld']:
        explanations.append(("Domain TLD", "red", "Suspicious TLD (.tk, .ml, .xyz, etc.) — free domains commonly abused by phishers"))
    else:
        explanations.append(("Domain TLD", "green", "Normal domain TLD"))

    if f['subdomain_depth'] >= 3:
        explanations.append(("Subdomain Depth", "red", f"{f['subdomain_depth']} subdomain levels — phishers use deep subdomains to fake legitimate domains"))
    elif f['subdomain_depth'] == 2:
        explanations.append(("Subdomain Depth", "orange", f"{f['subdomain_depth']} subdomain levels"))
    else:
        explanations.append(("Subdomain Depth", "green", f"Normal subdomain structure"))

    return explanations
