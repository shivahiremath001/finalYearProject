import os
import sys
import random
import pandas as pd
import matplotlib.pyplot as plt

# Add backend to path to import scoring
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend'))

from scoring import score
from schemas import CollectorData

def get_base_data(defaults=False):
    d = CollectorData().model_dump()
    for k in d:
        d[k] = defaults
    return d

def generate_profile(name):
    """Generate CollectorData for a named scenario"""
    # Start with all secure
    d = get_base_data(defaults=False)
    
    # In CollectorData schema:
    # _enabled/_open/_deleted variables: True means insecure (except firewall_on and backup_configured which are opposite)
    
    # Reset opposites
    d["firewall_on"] = True
    d["backup_configured"] = True
    d["vulnerable_driver_blocklist_enabled"] = True
    d["hvci_enabled"] = True
    d["asr_rules_configured"] = True
    d["mock_attack_vss_enum_blocked"] = True
    d["mock_attack_mass_rename_blocked"] = True

    if name == "hardened_server":
        # All secure, already set
        pass
        
    elif name == "typical_unmanaged_workstation":
        # Standard insecure things
        d["autorun_enabled"] = True
        d["macro_execution_enabled"] = True
        d["wdigest_enabled"] = True
        d["laps_absent"] = True
        d["applocker_absent"] = True
        d["admin_shares_enabled"] = True
        d["guest_account_active"] = True
        d["smb_v1_enabled"] = True
        
    elif name == "lockbit_style_exposed_rdp":
        # Critical exposed profile
        d["rdp_open"] = True
        d["nla_disabled"] = True
        d["defender_disabled"] = True
        d["vss_deleted"] = True
        d["lsass_protection_off"] = True
        d["backup_configured"] = False
        d["firewall_on"] = False
        
    elif name == "phishing_macro_chain":
        # Email phishing profile
        d["macro_execution_enabled"] = True
        d["powershell_unrestricted"] = True
        d["vulnerable_driver_blocklist_enabled"] = False
        d["asr_rules_configured"] = False
        d["uac_disabled"] = True
        
    elif name == "partially_hardened_dc":
        # DC but missing some advanced features
        d["wdigest_enabled"] = True
        d["lsass_protection_off"] = True
        d["vulnerable_driver_blocklist_enabled"] = False
        
    return CollectorData(**d)

def run_validation():
    profiles = [
        "hardened_server",
        "typical_unmanaged_workstation",
        "lockbit_style_exposed_rdp",
        "phishing_macro_chain",
        "partially_hardened_dc"
    ]
    
    asset_types = ["Workstation", "Server", "Domain Controller"]
    
    results = []
    
    for p in profiles:
        host = generate_profile(p)
        for asset in asset_types:
            s, c, _, _, _, _ = score(host, asset)
            results.append({
                "Scenario": p,
                "Asset Type": asset,
                "Risk Score": s,
                "Risk Class": c
            })
            
    df_scenarios = pd.DataFrame(results)
    
    # Assert ordering
    hardened = df_scenarios[(df_scenarios["Scenario"] == "hardened_server") & (df_scenarios["Asset Type"] == "Workstation")].iloc[0]["Risk Score"]
    typical = df_scenarios[(df_scenarios["Scenario"] == "typical_unmanaged_workstation") & (df_scenarios["Asset Type"] == "Workstation")].iloc[0]["Risk Score"]
    lockbit = df_scenarios[(df_scenarios["Scenario"] == "lockbit_style_exposed_rdp") & (df_scenarios["Asset Type"] == "Workstation")].iloc[0]["Risk Score"]
    
    print(f"Scores on Workstation: Hardened={hardened}, Typical={typical}, Lockbit={lockbit}")
    assert hardened < typical < lockbit, "Ordering failed!"
    print("Ordering assertion passed: hardened < typical < lockbit-style")
    
    os.makedirs('analysis/output', exist_ok=True)
    
    df_scenarios.to_csv('analysis/output/validate_scenarios_SYNTHETIC.csv', index=False)
    
    with open('analysis/output/validate_scenarios_SYNTHETIC.md', 'w') as f:
        f.write("# Synthetic Scenario Validation\n\n")
        f.write(df_scenarios.to_markdown(index=False))
        
    # Generate 500 random hosts
    random.seed(42)
    random_scores = []
    random_classes = []
    
    from sensitivity import generate_host
    for _ in range(500):
        host = generate_host()
        asset = random.choice(asset_types)
        s, c, _, _, _, _ = score(host, asset)
        random_scores.append(s)
        random_classes.append(c)
        
    df_random = pd.DataFrame({
        "Risk Score": random_scores,
        "Risk Class": random_classes
    })
    
    # Plot histogram
    plt.figure(figsize=(10, 6))
    plt.hist(random_scores, bins=20, edgecolor='black', alpha=0.7)
    plt.title("Distribution of Risk Scores for 500 SYNTHETIC Random Hosts")
    plt.xlabel("Risk Score")
    plt.ylabel("Frequency")
    plt.savefig('analysis/output/validate_histogram_SYNTHETIC.png')
    
    print("\nRandom Host Category Counts:")
    print(df_random["Risk Class"].value_counts())

if __name__ == "__main__":
    run_validation()
