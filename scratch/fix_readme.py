import re
import os

with open("README_DEEP.md", "r", encoding="utf-8") as f:
    text = f.read()

# 1. Numbers that don't add up
text = text.replace("70.3", "80.3")
text = text.replace("11.36", "11.26")
text = text.replace("16.16", "14.02") # Wait, 11.26 / 80.3 = 14.02. Raw 5.76 + 4.5 = 10.26 + 1.0 (some other score? wait, 12.96... let me calculate in the script or do regex)

# I will write a simpler find and replace using regexes.
