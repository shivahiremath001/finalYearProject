import re

def final_fixes():
    with open('README_DEEP.md', 'r', encoding='utf-8') as f:
        text = f.read()

    # 1. Defender passive mode
    text = text.replace("`defender_disabled` | Boolean | Defender Anti-Spyware enabled |", "`defender_disabled` | Boolean | Defender Anti-Spyware enabled |")
    text = text.replace("Active Defender engine missing.", "Active Defender engine missing (Note: Third-party AVs put Defender in passive mode, potentially causing a false flag without an exception).")

    # 2. Honeytoken limitations
    text = text.replace("It exercises Windows Defender Controlled Folder Access (CFA)", "It exercises Windows Defender Controlled Folder Access (CFA) (Note: CFA itself may block the agent from writing the bait file to Public Documents)")
    text = text.replace("a rapid batch rename burst loop to test behavioral velocity heuristics", "a rapid batch rename burst loop to test behavioral velocity heuristics (Note: Depends on the filename prefix surviving; misses ransomware that completely renames files)")
    
    # "If the honeypot trips, it appears to stay latched" - just mention it
    text = text.replace("Honeytoken trips (e.g., rapid file modifications or unexpected access)", "Honeytoken trips (latches until admin reset on unexpected access or rapid modifications)")

    with open('README_DEEP.md', 'w', encoding='utf-8') as f:
        f.write(text)

final_fixes()
