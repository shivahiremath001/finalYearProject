import re

def soften_claims(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Replacements dictionary
    replacements = {
        "an enterprise-grade, client-server security platform": "a client-server security platform",
        "enterprise-grade Single-Page Application (SPA)": "Single-Page Application (SPA)",
        "Real-Time Admin Dashboard:": "Live Admin Dashboard:",
        "Real-Time Web Dashboard:": "Live Web Dashboard:",
        "Real-Time WebSocket Indicator:": "WebSocket Indicator:",
        "Real-Time client-side": "Live client-side",
        "Real-Time Visual Pulsing:": "Visual Pulsing:",
        "Real-Time WebSocket Feedback": "WebSocket Feedback",
        "Real-Time Streaming Feed": "Streaming Feed",
        "Real-Time Scan & Anomaly Update": "Live Scan & Anomaly Update",
        "ensure **absolute, unbroken endpoint identity continuity**": "support **endpoint identity continuity**",
        "To eliminate UI freezing": "To prevent UI freezing",
        "Eliminates host recovery mechanisms": "Disables host recovery mechanisms",
        "To eliminate false negatives": "To reduce false negatives",
        "guarantees 100% operational disruption": "causes severe operational disruption",
        "100% Deterministic Formula": "Deterministic Formula",
        "guarantees a minimum score floor": "enforces a minimum score floor",
        "Zero-Latency State Synchronization:": "State Synchronization:",
        "Instant (Requires 3 scans)": "Rapid (Requires 3 scans)",
        "instantaneous logout": "quick logout",
        "instantly filters": "filters",
        "Displays instant count feedback": "Displays count feedback",
        "Instant slide-in notification": "Slide-in notification",
        "Real-time JSON events": "Live JSON events",
        "fully renames files": "changes the entire filename",
        "completely immune": "highly resistant"
    }

    for old, new in replacements.items():
        content = content.replace(old, new)
        # Also try lowercase versions for case-insensitive matches where needed
        if old.lower() != old and "Real-Time" in old:
            content = content.replace(old.replace("Real-Time", "Real-time"), new.replace("Live", "Live"))

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

soften_claims('README_DEEP.md')
