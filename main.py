import pydig
import pandas as pd
import re
from ipwhois import IPWhois

def main():
    # Load municipality domains from the input file
    domains_df = pd.read_csv("domains.csv")
    domains_to_check = domains_df["domain"].tolist()
    results = []
    total_domains = len(domains_to_check)

    for i, domain in enumerate(domains_to_check, 1):
        try:
            # Parse MX records and extract the highest priority mail server
            mx_records_raw = pydig.query(domain, 'MX')
            mx_tuples = []
            for mx in mx_records_raw:
                parts = mx.strip().split()
                if len(parts) == 2 and parts[0].isdigit():
                    priority = int(parts[0])
                    host = parts[1]
                    mx_tuples.append((priority, host))
            mx_tuples.sort(key=lambda x: x[0])
            mx_records = mx_tuples[0][1] if mx_tuples else ""
            # Extract SPF records from TXT records
            txt_records = pydig.query(domain, 'TXT')
            spf_records = []
            ip4_records = []
            include_records = []
            for record in txt_records:
                clean = record.strip('"')
                if clean.lower().startswith("v=spf1"):
                    spf_parts = clean.split()
                    for part in spf_parts:
                        if part.startswith("ip4:"):
                            ip4_records.append(part.replace("ip4:", "").strip())
                        elif part.startswith("include:"):
                            include_records.append(part.replace("include:", "").strip())
            spf_records = {
                "ip4": ip4_records,
                "include": include_records
            }
            # Lookup country codes for MX host A records (instead of base domain)
            mx_hosts = [host.rstrip('.') for _, host in mx_tuples]
            domain_countries = []
            for mx_host in mx_hosts:
                a_records = pydig.query(mx_host, 'A')
                for ip in a_records:
                    country_code = None
                    try:
                        ipwhois_client = IPWhois(ip, timeout=10)
                        rdap_data = ipwhois_client.lookup_rdap(asn_methods=["whois", "http"])
                        country_code = rdap_data.get("asn_country_code")
                    except Exception:
                        country_code = None
                    domain_countries.append(country_code)
            
            # Check for autodiscover CNAME record (used by Exchange/Outlook)
            autodiscover_cname = pydig.query(f"autodiscover.{domain}", 'CNAME')
            autodiscover_records = autodiscover_cname[0].rstrip('.') if autodiscover_cname else ""

            # Check for DKIM selectors used by major email providers
            dkim_patterns = [
                # Microsoft / Office 365, Yahoo / AOL / Verizon, Other / generic
                "selector1._domainkey.{domain}",  # TXT/CNAME record (default selector 1) - used by multiple providers
                # Microsoft / Office 365
                "selector2._domainkey.{domain}",  # TXT/CNAME record (default selector 2)

                # Google Workspace
                "google._domainkey.{domain}",  # TXT record

                # Zoho Mail / Zoho Campaigns
                "zoho._domainkey.{domain}",  # TXT record
                "custom._domainkey.{domain}",  # CNAME for campaigns
                "zmail._domainkey.{domain}",  # Optional TXT for DKIM

                # Mailgun, Mailchimp / Mandrill
                "k1._domainkey.{domain}",  # TXT/CNAME record - used by Mailgun and Mandrill
                "email._domainkey.{domain}",  # Optional CNAME for tracking

                # SendGrid
                "s1._domainkey.{domain}",  # TXT record
                "a1._domainkey.{domain}",  # Optional CNAME for custom selector
                "a12._domainkey.{domain}",  # Optional CNAME for custom selector
            ]
            # Query each DKIM selector and store results
            dkim_selectors = {}
            for pattern in dkim_patterns:
                selector = pattern.format(domain=domain)
                cname_records = pydig.query(selector, 'CNAME')
                if cname_records:
                    key = pattern.split('.')[0]  # Extract selector name (e.g., "selector1")
                    dkim_selectors[key] = cname_records

            results.append({
                "domain": domain,
                "MX": mx_records,
                "autodiscover": autodiscover_records,
                "SPF": spf_records,
                "domain_countries": domain_countries,
                "DKIM": dkim_selectors
            })

            print(f"Processed domain {i} of {total_domains}: {domain}                ", end="\r")
        except Exception as e:
            results.append({
                "domain": domain,
                "MX": None,
                "SPF": None,
                "autodiscover": None,
                "DKIM": None,
                "error": str(e)
            })


    results_df = pd.DataFrame(results)

    # Normalize country codes: single country -> string, multiple -> comma-separated, empty -> None
    if "domain_countries" in results_df.columns:
        def normalize_countries(val):
            if isinstance(val, list):
                vals = [v for v in val if v]
                if len(vals) == 1:
                    return vals[0]
                if len(vals) > 1:
                    return ",".join(sorted(set(vals)))
                return None
            return val
        results_df["domain_countries"] = results_df["domain_countries"].map(normalize_countries)

    # Expand SPF records into separate columns for each IP and include directive
    spf_expanded = results_df["SPF"].apply(pd.Series)
    spf_ip4 = spf_expanded["ip4"].apply(pd.Series).add_prefix("spf_ip4_")
    spf_include = spf_expanded["include"].apply(pd.Series).add_prefix("spf_include_")
    results_df = pd.concat([results_df.drop(columns=["SPF"]), spf_ip4, spf_include], axis=1)

    # Expand DKIM selectors into separate columns, cleaning domain suffixes
    dkim_expanded = results_df["DKIM"].apply(pd.Series)
    # Normalize trailing dots in FQDNs
    dkim_expanded_cleaned = dkim_expanded.stack().map(lambda x: x if pd.isna(x) else [record.rstrip('.') for record in x]).unstack()

    # Clean column names to remove domain-specific parts
    def clean_dkim_col(col):
        return re.sub(r'\._domainkey\..*$', '._domainkey', col)

    dkim_expanded_cleaned.columns = [clean_dkim_col(col) for col in dkim_expanded_cleaned.columns]
    
    # Convert single-item lists to strings for cleaner output
    def flatten_dkim(val):
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val
    dkim_flattened = dkim_expanded_cleaned.stack().map(flatten_dkim).unstack()
    dkim_columns = dkim_flattened.add_prefix("dkim_")
    results_df = pd.concat([results_df.drop(columns=["DKIM"]), dkim_columns], axis=1)
    
    results_df.to_csv("domain_dns_results.csv", index=False)

    # Detect Microsoft 365 usage via MX, autodiscover, SPF, and DKIM signals
    results_df["is_microsoft_365"] = results_df["MX"].apply(lambda x: 1 if x and "mail.protection.outlook.com" in x else 0)
    results_df["is_microsoft_autodiscover"] = results_df["autodiscover"].apply(lambda x: 1 if x and "autodiscover.outlook.com" in x else 0)
    results_df["is_microsoft_spf"] = results_df[[col for col in results_df.columns if col.startswith("spf_include_")]].apply(
        lambda row: 1 if any("spf.protection.outlook.com" in str(val) for val in row if pd.notna(val)) else 0, axis=1
    )
    results_df["is_microsoft_dkim"] = results_df[[col for col in results_df.columns if col.startswith("dkim_")]].apply(
        lambda row: 1 if any(
            ("onmicrosoft.com" in str(val) or "dkim.protection.outlook.com" in str(val))
            for val in row if pd.notna(val)
        ) else 0, axis=1
    )

    # Count total Microsoft indicators per domain
    results_df["microsoft_signs"] = results_df[["is_microsoft_365", "is_microsoft_autodiscover", "is_microsoft_spf", "is_microsoft_dkim"]].sum(axis=1)
    
    print("\nMicrosoft detection summary (overall)")
    print("=" * 80)
    def build_summary(subset_df):
        """Build summary statistics for Microsoft detection indicators"""
        total = len(subset_df)
        signs_gt_0 = subset_df[subset_df["microsoft_signs"] > 0].shape[0]
        signs_1 = subset_df[subset_df["microsoft_signs"] == 1].shape[0]
        signs_2 = subset_df[subset_df["microsoft_signs"] == 2].shape[0]
        signs_3 = subset_df[subset_df["microsoft_signs"] == 3].shape[0]
        signs_4 = subset_df[subset_df["microsoft_signs"] == 4].shape[0]
        return pd.DataFrame([
            {"metric": "total_domains", "value": total},
            {"metric": ">0_signs", "value": signs_gt_0},
            {"metric": "exactly_1", "value": signs_1},
            {"metric": "exactly_2", "value": signs_2},
            {"metric": "exactly_3", "value": signs_3},
            {"metric": "exactly_4", "value": signs_4},
        ])[ ["metric", "value"] ]
    
    summary_overall = build_summary(results_df).copy()
    print(summary_overall.to_string(index=False))
    
    # Signature type distribution (counts and percents) across all municipality domains
    print("\nSignature type distribution (overall)")
    print("=" * 80)
    
    signature_cols = [
        "is_microsoft_365",
        "is_microsoft_autodiscover",
        "is_microsoft_spf",
        "is_microsoft_dkim",
    ]
    def build_signature_distribution(subset_df):
        total = len(subset_df)
        if total == 0:
            return pd.DataFrame([
                {"signature": sig, "count": 0, "percent": 0.0} for sig in signature_cols
            ])[ ["signature", "count", "percent"] ]
        rows = []
        for sig in signature_cols:
            count = int((subset_df[sig] == 1).sum())
            percent = round((count / total) * 100, 1) if total > 0 else 0.0
            rows.append({"signature": sig, "count": count, "percent": percent})
        return pd.DataFrame(rows)[ ["signature", "count", "percent"] ]
    
    distro_overall = build_signature_distribution(results_df).copy()
    print(distro_overall.to_string(index=False))
    
    # Display country distribution for all municipality domains
    print("\nCountry distribution (overall)")
    print("=" * 80)
    
    def build_country_table(subset_df):
        """Build country distribution table for domains with geolocation data"""
        domains_with_countries = subset_df[subset_df["domain_countries"].notna() & (subset_df["domain_countries"] != "")]
        if len(domains_with_countries) == 0:
            return pd.DataFrame([{"country": "-", "count": 0, "percent": 0.0}])[ ["country", "count", "percent"] ]
        country_counts = {}
        for countries in domains_with_countries["domain_countries"]:
            if countries:
                for country in [c.strip() for c in str(countries).split(',')]:
                    if country:
                        country_counts[country] = country_counts.get(country, 0) + 1
        sorted_items = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        total_with_countries = len(domains_with_countries)
        table = pd.DataFrame([
            {"country": c, "count": n, "percent": round((n / total_with_countries) * 100, 1)}
            for c, n in sorted_items
        ])[ ["country", "count", "percent"] ]
        return table

    country_overall = build_country_table(results_df).copy()
    print(country_overall.to_string(index=False))
    
    # Save final analysis results
    results_df.to_csv("analysis_results.csv", index=False)


if __name__ == "__main__":
    main()
