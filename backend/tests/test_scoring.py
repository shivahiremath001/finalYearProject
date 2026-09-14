import pytest
import sys
import os

# Add backend directory to sys.path so we can import modules directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemas import CollectorData
from scoring import score

def test_safe_machine_scoring():
    """Test that a perfectly secure machine yields a 0 score and SAFE classification."""
    data = CollectorData(
        rdp_open=False,
        firewall_on=True,
        backup_configured=True,
        smb_v1_enabled=False,
        vulnerable_driver_blocklist_enabled=True,
        hvci_enabled=True,
        asr_rules_configured=True,
        mock_attack_vss_enum_blocked=True,
        mock_attack_mass_rename_blocked=True,
    )
    risk_score, risk_class, flagged, mitre_hits, criticality = score(data, "Workstation")
    
    assert risk_score == 0.0
    assert risk_class == "SAFE"
    assert len(flagged) == 0
    assert len(mitre_hits) == 0

def test_critical_vulnerability_escalation():
    """Test that a single critical vulnerability forces the risk class to escalate."""
    # A mostly safe machine, but SMBv1 is enabled (Critical weight 5)
    data = CollectorData(
        rdp_open=False,
        firewall_on=True,
        backup_configured=True,
        smb_v1_enabled=True,  # CRITICAL FAILURE
        vulnerable_driver_blocklist_enabled=True,
        hvci_enabled=True,
        asr_rules_configured=True,
        mock_attack_vss_enum_blocked=True,
        mock_attack_mass_rename_blocked=True,
    )
    risk_score, risk_class, flagged, mitre_hits, criticality = score(data, "Workstation")
    
    # Escalation logic dictates that a weight-5 failure forces at least HIGH RISK
    assert risk_class in ["HIGH RISK", "CRITICAL"]
    assert "smb_v1_enabled" in flagged.get("Entry Vector", [])
    
def test_asset_criticality_multiplier():
    """Test that Domain Controllers yield a higher final score than Workstations for the same telemetry."""
    data = CollectorData(
        rdp_open=True,   # Risky
        firewall_on=False # Risky
    )
    
    # Base Workstation score
    w_score, _, _, _, w_crit = score(data, "Workstation")
    
    # Domain Controller score (multiplier applied)
    dc_score, _, _, _, dc_crit = score(data, "Domain Controller")
    
    assert dc_crit == 1.6
    assert w_crit == 1.0
    assert dc_score > w_score
