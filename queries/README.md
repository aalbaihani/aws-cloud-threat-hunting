# CloudTrail hunting queries

Five Athena queries over the `cloudtrail_hunt.cloudtrail_logs` table, each
mapped to a MITRE ATT&CK technique from the Cloud matrix. Every one was
validated against activity generated in this lab on 2026-09-19.

Each file contains `__DT__` as the partition placeholder. The runner
substitutes it; if you paste a query into the Athena console by hand, replace
it with the date you want (`2026/09/19`).

## Coverage

| # | Technique | ID | What it looks for | Validated against |
|---|---|---|---|---|
| 01 | Create Account: Cloud Account | T1136.003 | New IAM users, roles, login profiles, access keys | `CreateUser` + `CreateAccessKey`, 16:04 |
| 02 | Account Manipulation | T1098 | Privilege grants, and create-then-escalate correlation | `AttachUserPolicy` (AdministratorAccess) 2s after `CreateUser` |
| 03 | Impair Defenses: Disable or Modify Cloud Logs | T1562.008 | Trail stop/delete/reconfigure, with interval measurement | `StopLogging` → `StartLogging`, 61s apart |
| 04 | Cloud Infrastructure Discovery | T1580 | Bursts of distinct read-only APIs per principal per 5 min | `ListUsers`, `ListRoles`, `ListBuckets`, `DescribeInstances`, 15:58 and 16:03 |
| 05 | Valid Accounts: Cloud Accounts | T1078.004 | Failed logins, MFA-less console access, credential errors | Console login failures (run separately from CloudShell) |

## Running them

```bash
chmod +x scripts/run-hunt.sh
./scripts/run-hunt.sh 2026/09/19
```

Results are written to `results/2026-09-19/` as one CSV per technique, with row
counts and bytes scanned printed as it goes. With partition projection each
query reads roughly 100 KB, so a full pass costs a fraction of a cent.

## Notes on the detection logic

**Noise filtering is most of the work.** An unfiltered query over this account
returns `SendHeartBeat` once a minute from CloudShell, service-linked role
assumptions from `resource-explorer-2.amazonaws.com`, and Athena's own Glue
calls. Query 04 in particular is useless without the exclusions — reconnaissance
and normal tooling look identical if you only count API calls. The filters are
listed inline so they can be adjusted rather than inherited blindly.

**Absence of events is not evidence of absence.** Three IAM deletions that
completed successfully in this lab were still missing from S3 twenty minutes
later, because CloudTrail batches deliveries and global IAM events route through
`us-east-1` on a slower cadence than regional ones. Any query that infers
suppression from a quiet window will produce false positives on delivery lag
alone.

**`StopLogging` is not instantaneous.** Events were still being recorded 53
seconds after the call in this lab. Query 03 reports the interval between stop
and start as an upper bound on the blind window rather than asserting it as the
gap, which is the honest reading of what the data supports.

**Thresholds are placeholders.** `distinct_apis >= 3` in query 04 is tuned to a
near-empty lab account. In a real environment it would fire constantly; the
threshold has to come from a baseline of your own traffic, not from this file.
