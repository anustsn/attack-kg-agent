Items scored by every system: 100

| System | Top-1 | 95% CI | Top-1, parent technique | Top-3 | Invalid IDs in first answer | Any error in first answer | Model calls per item |
|---|---|---|---|---|---|---|---|
| offline | 21/100 (21%) | 14–30% | 30/100 (30%) | 36/100 (36%) | 0/300 (0%) | 0/300 (0%) | 0.0 |
| closed-book | 48/100 (48%) | 38–58% | 55/100 (55%) | 58/100 (58%) | 23/294 (8%) | 87/294 (30%) | 1.0 |
| closed-book+repair | 68/100 (68%) | 58–76% | 78/100 (78%) | 80/100 (80%) | 23/294 (8%) | 87/294 (30%) | 1.0 |
| agent | 67/100 (67%) | 57–75% | 74/100 (74%) | 77/100 (77%) | 0/217 (0%) | 0/217 (0%) | 3.09 |

Errors in first answers, by validator rule (count of mappings):

- offline: none
- closed-book: name_mismatch 1, revoked 23, tactic_mismatch 8, tactic_renamed 56
- closed-book+repair: name_mismatch 1, revoked 23, tactic_mismatch 8, tactic_renamed 56
- agent: none
