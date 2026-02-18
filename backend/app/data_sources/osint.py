import requests
import xml.etree.ElementTree as ET

# 1. CISA KEV (already in your sources)
def fetch_cisa():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.xml"
    r = requests.get(url, timeout=10)
    root = ET.fromstring(r.content)

    items = []
    for item in root.findall(".//item"):
        title = item.findtext("title")
        desc = item.findtext("description")

        items.append({
            "source": "cisa_kev",
            "title": title,
            "text": desc,
            "url": "cisa://kev"
        })
    return items


# 2. NVD CVE API (lightweight)
def fetch_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"
    r = requests.get(url, timeout=10).json()

    items = []
    for v in r.get("vulnerabilities", []):
        cve = v["cve"]
        desc = cve["descriptions"][0]["value"]

        items.append({
            "source": "nvd",
            "title": cve["id"],
            "text": desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
        })
    return items
