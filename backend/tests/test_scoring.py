"""
test_scoring.py - T1 comprehensive test suite for scoring engine.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemas import CollectorData
from scoring import (
    score,
    explain_score,
    SEVERITY_WEIGHTS,
    LIKELIHOOD_WEIGHTS,
    RISK_MAX,
    _ALL_SCORED_PARAMS,
)

def _all_clean():
    return CollectorData(
        rdp_open=False, firewall_on=True, backup_configured=True,
        smb_v1_enabled=False, autorun_enabled=False, open_network_shares=False,
        macro_execution_enabled=False, powershell_unrestricted=False,
        uac_disabled=False, applocker_absent=False, defender_disabled=False,
        tamper_protection_off=False, event_logging_disabled=False,
        admin_shares_enabled=False, lsass_protection_off=False,
        guest_account_active=False, vss_deleted=False, bitlocker_off=False,
        wdigest_enabled=False, laps_absent=False, nla_disabled=False,
        always_install_elevated=False,
        vulnerable_driver_blocklist_enabled=True,
        hvci_enabled=True, asr_rules_configured=True,
        mock_attack_vss_enum_blocked=True, mock_attack_mass_rename_blocked=True,
    )

def _all_failed():
    return CollectorData(
        rdp_open=True, firewall_on=False, backup_configured=False,
        smb_v1_enabled=True, autorun_enabled=True, open_network_shares=True,
        macro_execution_enabled=True, powershell_unrestricted=True,
        uac_disabled=True, applocker_absent=True, defender_disabled=True,
        tamper_protection_off=True, event_logging_disabled=True,
        admin_shares_enabled=True, lsass_protection_off=True,
        guest_account_active=True, vss_deleted=True, bitlocker_off=True,
        wdigest_enabled=True, laps_absent=True, nla_disabled=True,
        always_install_elevated=True,
        vulnerable_driver_blocklist_enabled=False,
        hvci_enabled=False, asr_rules_configured=False,
        mock_attack_vss_enum_blocked=False, mock_attack_mass_rename_blocked=False,
    )

def test_a_all_params_have_both_weights():
    missing = [k for k in SEVERITY_WEIGHTS if k not in LIKELIHOOD_WEIGHTS]
    assert missing == []
    missing2 = [k for k in LIKELIHOOD_WEIGHTS if k not in SEVERITY_WEIGHTS]
    assert missing2 == []

def test_b_risk_max_value():
    expected = sum(SEVERITY_WEIGHTS[k]*LIKELIHOOD_WEIGHTS[k] for k in SEVERITY_WEIGHTS)
    assert abs(RISK_MAX - expected) < 1e-9

def test_c_all_clean_scores_zero_safe():
    risk_score, risk_class, flagged, mitre_hits, criticality, top_contributors = score(_all_clean(), 'Workstation')
    assert risk_score == 0.0
    assert risk_class == 'SAFE'
    assert len(flagged) == 0

def test_d_all_failed_workstation_scores_100():
    risk_score, risk_class, flagged, mitre_hits, criticality, top_contributors = score(_all_failed(), 'Workstation')
    assert risk_score == 100.0
    assert risk_class == 'CRITICAL'

def test_e_dc_greater_than_server_greater_than_workstation():
    data = _all_clean()
    data.rdp_open = True
    w_score, _, _, _, w_crit, _ = score(data, 'Workstation')
    s_score, _, _, _, s_crit, _ = score(data, 'Server')
    dc_score, _, _, _, dc_crit, _ = score(data, 'Domain Controller')
    assert dc_crit == 1.6
    assert s_crit == 1.3
    assert w_crit == 1.0
    assert dc_score > s_score > w_score

def test_f_single_s5_failure_escalates():
    data = _all_clean()
    data.smb_v1_enabled = True
    risk_score, risk_class, flagged, _, _, _ = score(data, 'Workstation')
    assert risk_score >= 50.0
    assert risk_class in ('HIGH RISK', 'CRITICAL')
    assert 'smb_v1_enabled' in flagged.get('Entry Vector', [])



def test_h_explain_score_sorted():
    from scoring import _translate, get_asset_criticality, explain_score
    data = _all_failed()
    params = _translate(data)
    criticality = get_asset_criticality('Workstation')
    contributions = explain_score(params, criticality)
    assert len(contributions) > 0
    for i in range(len(contributions)-1):
        assert contributions[i]['contribution'] >= contributions[i+1]['contribution']

def test_safe_machine_scoring():
    data = _all_clean()
    risk_score, risk_class, flagged, mitre_hits, criticality, top_contributors = score(data, 'Workstation')
    assert risk_score == 0.0
    assert risk_class == 'SAFE'

def test_critical_vulnerability_escalation():
    data = _all_clean()
    data.smb_v1_enabled = True
    risk_score, risk_class, flagged, mitre_hits, criticality, top_contributors = score(data, 'Workstation')
    assert risk_score >= 50.0
    assert risk_class in ['HIGH RISK', 'CRITICAL']
    assert 'smb_v1_enabled' in flagged.get('Entry Vector', [])

def test_asset_criticality_multiplier():
    data = _all_clean()
    data.rdp_open = True
    w_score, _, _, _, w_crit, _ = score(data, 'Workstation')
    dc_score, _, _, _, dc_crit, _ = score(data, 'Domain Controller')
    assert dc_crit == 1.6
    assert w_crit == 1.0
    assert dc_score > w_score

