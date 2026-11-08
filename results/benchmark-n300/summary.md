Items scored by every system: 300

| System | Top-1 | 95% CI | Top-1, parent technique | Top-3 | Invalid IDs in first answer | Any error in first answer | Model calls per item |
|---|---|---|---|---|---|---|---|
| offline | 56/300 (19%) | 15–23% | 88/300 (29%) | 110/300 (37%) | 0/900 (0%) | 0/900 (0%) | 0.0 |
| closed-book | 124/300 (41%) | 36–47% | 150/300 (50%) | 162/300 (54%) | 66/882 (7%) | 244/882 (28%) | 1.0 |
| closed-book+repair | 180/300 (60%) | 54–65% | 215/300 (72%) | 229/300 (76%) | 66/882 (7%) | 244/882 (28%) | 1.0 |
| agent | 175/300 (58%) | 53–64% | 207/300 (69%) | 224/300 (75%) | 0/663 (0%) | 0/663 (0%) | 3.09 |

Errors in first answers, by validator rule (count of mappings):

- offline: none
- closed-book: name_mismatch 3, revoked 66, tactic_mismatch 15, tactic_renamed 163
- closed-book+repair: name_mismatch 3, revoked 66, tactic_mismatch 15, tactic_renamed 163
- agent: none
