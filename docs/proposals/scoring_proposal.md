# R3P Scoring Engine — Proposed Improvement

## Current Method (What You Have)

```
score = (sum of flagged weights) / (sum of all weights) × 100
```

- Simple weighted sum, normalized to 0–100
- Fixed thresholds: `<20 SAFE`, `<50 LOW`, `<80 HIGH`, `≥80 CRITICAL`
- One escalation rule: any weight-5 param → at least HIGH RISK

### Problems
1. **All checks are equally independent** — no interaction effects
2. **Recovery Prevention dominates** (3 checks = 23% of total weight)
3. **BitLocker = weight 5** inflates almost every machine's score
4. **Thresholds are arbitrary** — can't be justified to an examiner

---

## Proposed Method: Phase-Weighted Risk Scoring (PWRS)

> Inspired by **NIST SP 800-30** (Risk = Likelihood × Impact) and the **Cyber Kill Chain** model.

### Core Idea

Instead of one flat weighted sum, score **each kill-chain phase independently**, then combine them with a **phase importance multiplier** and a **combo penalty** for dangerous pairings.

```
Final Score = Phase Scores + Combo Penalties
```

---

### Step 1: Phase-Level Scoring

Each of your 5 kill-chain phases gets its own sub-score (0–100):

```
Phase Score = (sum of flagged weights in phase) / (sum of all weights in phase) × 100
```

| Phase | Params | Max Weight | Phase Multiplier |
|---|---|---|---|
| Entry Vector | smb_v1, rdp, autorun, open_shares | 14 | **0.30** |
| Execution | macros, powershell, uac, applocker | 13 | **0.25** |
| Evasion & Persistence | defender, firewall, tamper, event_log | 13 | **0.25** |
| Lateral Movement | admin_shares, lsass, guest | 10 | **0.10** |
| Recovery Prevention | vss, backup, bitlocker | 12* | **0.10** |

> *BitLocker reduced from 5.0 → 2.0 (see justification below)

**Why these multipliers?**
- Based on the **Lockheed Martin Cyber Kill Chain**: an attacker MUST complete Entry + Execution before anything else matters. If you block the entry vector, the rest is irrelevant.
- Recovery Prevention is important but only matters AFTER the attacker has already won. It's a "damage reduction" measure, not a "prevention" measure.
- **Total multipliers = 1.00** (they sum to 100%, making it clean)

### Step 2: Base Score Calculation

```python
base_score = 0
for phase in PHASES:
    phase_score = (flagged_weight_in_phase / max_weight_in_phase) * 100
    base_score += phase_score * phase_multiplier
```

This alone fixes the "Recovery Prevention dominates" problem.

### Step 3: Combo Penalties (The Academic Differentiator)

This is what will make your scoring method stand out from a basic weighted sum. Certain parameter **combinations** are exponentially more dangerous than their individual scores suggest.

| Combo | Why It's Deadly | Bonus Penalty |
|---|---|---|
| `rdp_enabled` + `guest_account_active` | Unauthenticated RDP access | +8 |
| `defender_disabled` + `powershell_unrestricted` | Fileless malware has zero resistance | +10 |
| `smb_v1_enabled` + `admin_shares_enabled` | WannaCry-style worm propagation | +10 |
| `lsass_protection_off` + `admin_shares_enabled` | Credential dump → lateral movement | +8 |
| `firewall_disabled` + `rdp_enabled` | RDP exposed to entire network | +6 |
| `defender_disabled` + `tamper_protection_off` | AV permanently killable | +6 |
| `vss_deleted` + `backup_absent` | Zero recovery options | +8 |

```python
combo_penalty = 0
for combo in DANGEROUS_COMBOS:
    if all(params[p] for p in combo.params):
        combo_penalty += combo.bonus

final_score = min(base_score + combo_penalty, 100.0)
```

### Step 4: Classification with Justifiable Thresholds

Instead of arbitrary numbers, use a **quartile-based system** aligned with NIST SP 800-30 risk levels:

| Score Range | Class | NIST SP 800-30 Equivalent | Meaning |
|---|---|---|---|
| 0 – 15 | **SAFE** | Very Low | Minimal attack surface |
| 16 – 40 | **LOW RISK** | Low | Some misconfigurations, no critical combos |
| 41 – 65 | **MODERATE** | Moderate | Multiple phases compromised |
| 66 – 85 | **HIGH RISK** | High | Critical controls missing, combos detected |
| 86 – 100 | **CRITICAL** | Very High | Multiple kill-chain phases fully exposed |

> [!NOTE]
> Adding a 5th level ("MODERATE") is more accurate than 4 levels. NIST SP 800-30 Table I-2 uses 5 levels.

### Step 5: Escalation Rules (Keep Your Existing Idea, Enhanced)

```python
# Rule 1: Any phase scoring 100% → escalate to at least HIGH RISK
if any(phase_score == 100 for phase_score in phase_scores.values()):
    risk_class = max(risk_class, "HIGH RISK")

# Rule 2: 3+ phases with score > 50% → escalate to at least HIGH RISK  
if sum(1 for ps in phase_scores.values() if ps > 50) >= 3:
    risk_class = max(risk_class, "HIGH RISK")

# Rule 3: Entry Vector + Execution both > 70% → CRITICAL
if phase_scores["Entry Vector"] > 70 and phase_scores["Execution"] > 70:
    risk_class = max(risk_class, "CRITICAL")
```

---

## Comparison: Current vs Proposed

### Test Case: Typical Lab/Home Machine

A normal Windows 10 lab PC typically has:
- RDP off, Firewall on, Defender on, UAC on
- But: No BitLocker, no backup, no AppLocker, AutoRun on, Guest might be active

| Parameter | Value | Current Weight | 
|---|---|---|
| autorun_enabled | ✅ flagged | 2.0 |
| applocker_absent | ✅ flagged | 2.0 |
| guest_account_active | ✅ flagged | 2.0 |
| bitlocker_off | ✅ flagged | **5.0** |
| backup_absent | ✅ flagged | **5.0** |
| vss_deleted | ✅ flagged | **5.0** |

**Current Method:**
```
Score = (2+2+2+5+5+5) / 65 × 100 = 32.3% → "LOW RISK"
But escalation rule fires (weight 5) → "HIGH RISK" ⚠️
```

This is **wrong**. A normal lab PC with Defender on, Firewall on, RDP off should NOT be "HIGH RISK". The escalation rule is too aggressive because BitLocker/backup are weight 5.

**Proposed Method (PWRS):**
```
Entry Vector:          2/14 × 100 = 14.3  × 0.30 = 4.3
Execution:             2/13 × 100 = 15.4  × 0.25 = 3.8
Evasion & Persistence: 0/13 × 100 = 0.0   × 0.25 = 0.0
Lateral Movement:      2/10 × 100 = 20.0  × 0.10 = 2.0
Recovery Prevention:   10/12 × 100 = 83.3  × 0.10 = 8.3
                                              ─────────
Base Score:                                    18.4
Combo Penalty:        vss + backup combo       +8.0
                                              ─────────
Final Score:                                   26.4 → "LOW RISK" ✅
```

This is **correct**. The machine has weak recovery options but strong prevention — it's not "HIGH RISK".

---

### Test Case: Actually Dangerous Machine

A compromised-looking machine:
- RDP open, SMBv1 on, Defender off, PowerShell unrestricted, LSASS unprotected

**Current Method:**
```
Score = (5+4+4+4+5+3) / 65 × 100 = 38.5% → "LOW RISK" (with escalation → "HIGH RISK")
```

**Proposed Method (PWRS):**
```
Entry Vector:          9/14 × 100 = 64.3   × 0.30 = 19.3
Execution:             4/13 × 100 = 30.8   × 0.25 = 7.7
Evasion & Persistence: 4/13 × 100 = 30.8   × 0.25 = 7.7
Lateral Movement:      8/10 × 100 = 80.0   × 0.10 = 8.0
Recovery Prevention:   0/12 × 100 = 0.0    × 0.10 = 0.0
                                               ─────────
Base Score:                                     42.7
Combo Penalties:
  smb1 + admin_shares = +10
  defender + powershell = +10
  lsass + admin_shares = +8
                                               ─────────
Final Score:                                    70.7 → "HIGH RISK" ✅
```

The dangerous machine correctly scores much higher, driven by combos.

---

## Weight Adjustments

| Parameter | Current Weight | Proposed Weight | Justification |
|---|---|---|---|
| `bitlocker_off` | 5.0 | **2.0** | Protects data at rest only; doesn't prevent ransomware execution |
| `backup_absent` | 5.0 | **5.0** | Keep — backups are the #1 ransomware recovery tool |
| `vss_deleted` | 5.0 | **5.0** | Keep — VSS deletion is a direct ransomware indicator |
| `applocker_absent` | 2.0 | **3.0** | Raise — application whitelisting is a strong execution blocker |
| `event_logging_disabled` | 2.0 | **3.0** | Raise — without logs, incident response is impossible |

---

## What You Can Say in Your Report/Viva

> *"Our risk scoring engine implements a Phase-Weighted Risk Scoring (PWRS) algorithm inspired by the NIST SP 800-30 risk assessment methodology and the Lockheed Martin Cyber Kill Chain model. Each security parameter is scored within its kill-chain phase, and phases are weighted by their importance in preventing ransomware propagation. Additionally, we implement combinatorial risk escalation — detecting dangerous parameter pairings that create compounding attack surfaces. This approach more accurately reflects real-world ransomware attack patterns than a simple additive scoring model."*

That paragraph alone is worth 10 marks in a viva.

---

## Summary of Changes to Implement

1. **Restructure `score()` to compute per-phase sub-scores**
2. **Apply phase multipliers** (0.30, 0.25, 0.25, 0.10, 0.10)
3. **Add DANGEROUS_COMBOS dictionary** with bonus penalties
4. **Reduce `bitlocker_off` weight** from 5.0 → 2.0
5. **Add 5th risk class "MODERATE"** (aligns with NIST 5-level model)
6. **Update thresholds** to 0–15 / 16–40 / 41–65 / 66–85 / 86–100
7. **Return per-phase scores** in the API response (for frontend visualization)
