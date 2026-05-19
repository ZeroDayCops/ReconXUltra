#!/usr/bin/env python3
"""ReconX Ultra X — Cloud Exposure Intelligence
Deeply analyzes cloud exposure: AWS, Azure, GCP, Firebase, S3, Blob storage."""
import sys, json, re
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: cloud_exposure.py <domain>")

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "output" / DOMAIN
CLOUD = OUT / "cloud_exposure"
CLOUD.mkdir(parents=True, exist_ok=True)

CLOUD_PATTERNS = {
    "AWS S3": r'([a-zA-Z0-9-\.]+\.s3\.amazonaws\.com|s3-[a-zA-Z0-9-]+\.amazonaws\.com/[a-zA-Z0-9-\.]+)',
    "AWS EC2": r'(ec2-[0-9-]+\.[a-z0-9-]+\.compute\.amazonaws\.com)',
    "AWS API Gateway": r'([a-zA-Z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com)',
    "AWS CloudFront": r'([a-zA-Z0-9]+\.cloudfront\.net)',
    "Azure Blob Storage": r'([a-zA-Z0-9-]+\.blob\.core\.windows\.net)',
    "Azure App Service": r'([a-zA-Z0-9-]+\.azurewebsites\.net)',
    "GCP Storage": r'(storage\.googleapis\.com/[a-zA-Z0-9-\.]+)',
    "Firebase": r'([a-zA-Z0-9-]+\.firebaseio\.com)',
    "DigitalOcean Spaces": r'([a-zA-Z0-9-]+\.[a-z0-9-]+\.digitaloceanspaces\.com)'
}

def load_lines(path):
    try:
        p = Path(path)
        return [l.strip() for l in p.read_text().splitlines() if l.strip()] if p.exists() else []
    except: return []

def run_cloud_analysis():
    print("  ☁️  Cloud Exposure Intelligence")
    
    urls = load_lines(OUT / "urls/all_urls.txt")
    subs = load_lines(OUT / "subs/all_subdomains.txt")
    js = load_lines(OUT / "js/js_urls.txt")
    
    all_targets = urls + subs + js
    
    findings = []
    
    for target in all_targets:
        for cloud_type, pattern in CLOUD_PATTERNS.items():
            matches = re.findall(pattern, target, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": cloud_type,
                    "exposure": match,
                    "source": target
                })
                
    # Deduplicate
    unique_findings = []
    seen = set()
    for f in findings:
        k = f"{f['type']}:{f['exposure']}"
        if k not in seen:
            seen.add(k)
            unique_findings.append(f)
            
    # Save
    report = {
        "timestamp": datetime.now().isoformat(),
        "domain": DOMAIN,
        "total_exposures": len(unique_findings),
        "exposures": unique_findings
    }
    
    (CLOUD / "cloud_exposure.json").write_text(json.dumps(report, indent=2))
    print(f"    ✓ Identified {len(unique_findings)} cloud asset exposures.")

if __name__ == "__main__":
    run_cloud_analysis()
