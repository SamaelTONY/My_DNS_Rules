import os
import requests

# 规则源
SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt"
]

def main():
    raw_rules = set()
    print("Step 1: Downloading rules...")
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=60)
            if r.status_code == 200:
                lines = r.text.splitlines()
                for line in lines:
                    if line.startswith('||') and line.endswith('^'):
                        raw_rules.add(line)
        except Exception as e:
            print(f"Error downloading {url}: {e}")

    print(f"Step 2: Processing rules (Original: {len(raw_rules)})...")
    sorted_rules = sorted(list(raw_rules), key=len)
    final_rules = []
    seen_domains = set()

    for rule in sorted_rules:
        domain = rule.strip('|').strip('^')
        parts = domain.split('.')
        is_sub = False
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[-(len(parts)-i+1):])
            if parent in seen_domains:
                is_sub = True
                break
        if not is_sub:
            final_rules.append(rule)
            seen_domains.add(domain)

    print(f"Step 3: Saving... (Final: {len(final_rules)})")
    with open("my_adg_rules.txt", "w", encoding="utf-8") as f:
        f.write("! Title: OEC Master Rules (Cloud Build)\n")
        f.write(f"! Total: {len(final_rules)}\n\n")
        f.write("\n".join(final_rules))

if __name__ == "__main__":
    main()
