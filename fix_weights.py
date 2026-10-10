import re

def fix():
    with open('README_DEEP.md', 'r', encoding='utf-8') as f:
        text = f.read()

    # Revert the unintended test change
    text = text.replace("data.smb_v1_enabled = True # Weight 4.0", "data.smb_v1_enabled = True # Weight 5.0")

    # Lower severity for the checks mentioned:
    # 1. backup_absent (from 5.0 to 4.0)
    text = text.replace('"backup_absent": 5.0', '"backup_absent": 4.0')
    text = text.replace('| **`backup_absent`** | **5.0** |', '| **`backup_absent`** | **4.0** |')
    text = text.replace('| **`backup_absent`** | **5.0** | **0.8** | **4.00** |', '| **`backup_absent`** | **4.0** | **0.8** | **3.20** |')
    
    # 2. bitlocker_off (from 5.0 to 4.0)
    text = text.replace('"bitlocker_off": 5.0', '"bitlocker_off": 4.0')
    text = text.replace('| **`bitlocker_off`** | **5.0** |', '| **`bitlocker_off`** | **4.0** |')
    text = text.replace('| **`bitlocker_off`** | **5.0** | **0.5** | **2.50** |', '| **`bitlocker_off`** | **4.0** | **0.5** | **2.00** |')
    
    # 3. always_install_elevated (from 5.0 to 4.0)
    text = text.replace('"always_install_elevated": 5.0', '"always_install_elevated": 4.0')
    text = text.replace('| **`always_install_elevated`** | **5.0** |', '| **`always_install_elevated`** | **4.0** |')
    text = text.replace('| **`always_install_elevated`** | **5.0** | **0.6** | **3.00** |', '| **`always_install_elevated`** | **4.0** | **0.6** | **2.40** |')
    
    # 4. mock_attack_vss_enum_succeeded (from 5.0 to 4.0)
    text = text.replace('"mock_attack_vss_enum_succeeded": 5.0', '"mock_attack_vss_enum_succeeded": 4.0')
    text = text.replace('| **`mock_attack_vss_enum_succeeded`** | **5.0** |', '| **`mock_attack_vss_enum_succeeded`** | **4.0** |')
    text = text.replace('| **`mock_attack_vss_enum_succeeded`** | **5.0** | **1.0** | **5.00** |', '| **`mock_attack_vss_enum_succeeded`** | **4.0** | **1.0** | **4.00** |')

    # Also, "always_install_elevated" must check HKLM and HKCU. The table currently says:
    # `always_install_elevated` ... 
    text = text.replace("Enabled in registry.", "Enabled in both HKLM and HKCU registry.")

    with open('README_DEEP.md', 'w', encoding='utf-8') as f:
        f.write(text)

fix()
