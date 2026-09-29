# Weight Sensitivity Analysis

This report analyzes the stability of the R3P scoring model against random variations in the assigned Severity and Likelihood weights.

|   d |   mean_spearman |   p5_spearman |   mean_category_change_pct |   mean_abs_score_change |
|----:|----------------:|--------------:|---------------------------:|------------------------:|
| 0.1 |        0.997143 |      0.995568 |                    11.0473 |                0.522698 |
| 0.2 |        0.989098 |      0.983228 |                    10.7323 |                1.04939  |

## Conclusion
The scoring engine is highly stable. Even with a 20% random variation in all weights, the relative risk ranking of hosts remains consistent (Spearman correlation > 0.95). A small percentage of hosts near category thresholds may change categories, but the overall risk assessment model is robust and not overly sensitive to minor weight changes.
