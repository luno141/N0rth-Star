import re

CVE_REGEX = r"CVE-\d{4}-\d{4,7}"
IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

def extract_iocs(text: str):
    return {
        "cves": list(set(re.findall(CVE_REGEX, text))),
        "ips": list(set(re.findall(IP_REGEX, text))),
        "domains": list(set(re.findall(DOMAIN_REGEX, text))),
        "emails": list(set(re.findall(EMAIL_REGEX, text))),
    }
