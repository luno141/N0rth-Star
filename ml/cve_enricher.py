import random

# Simulated severity (you can replace later with real API)
def enrich_cves(cves):
    enriched = []
    for cve in cves:
        enriched.append({
            "id": cve,
            "cvss": round(random.uniform(6.0, 9.8), 1),
            "severity": "critical" if random.random() > 0.6 else "high"
        })
    return enriched
