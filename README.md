# AWS Cloud Threat Hunting Lab

CloudTrail → S3 → Athena detection pipeline, built and validated on a live AWS account. Five hunting queries mapped to MITRE ATT&CK Cloud techniques, each tested against attack activity generated in the account rather than against synthetic data.

This is Project 3 of a security portfolio. Project 1 covered endpoint detection engineering (Sysmon → Splunk, Windows ARM64); Project 2 covered SOAR automation (Shuffle → VirusTotal enrichment). This one moves from host telemetry into cloud control-plane telemetry.

## Architecture

```
AWS API activity (all regions)
        │
        ▼
   CloudTrail trail  ──  multi-region, log file validation enabled
        │
        │  batched delivery, 5–15 min
        ▼
   S3 bucket  ──  SSE-S3, public access blocked, 30-day lifecycle
        │         AWSLogs/<account>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/
        ▼
   Athena external table  ──  partition projection on (region, dt)
        │
        ▼
   Five ATT&CK-mapped hunting queries  →  CSV results
```

| Component | Value |
|---|---|
| Region | ap-southeast-2 (Sydney) |
| Trail | multi-region, global service events on, log file validation on |
| Partitioning | projection on `region` (enum) and `dt` (date), no `MSCK REPAIR` |
| Cost per full query pass | ~850 KB scanned, well under one cent |

## Detection coverage

| # | Technique | ID | Rows (tuned) | Validated against |
|---|---|---|---|---|
| 01 | Create Account: Cloud Account | T1136.003 | 2 | `CreateUser` + `CreateAccessKey` |
| 02 | Account Manipulation | T1098 | 1 | AdministratorAccess granted 2s after user creation |
| 03 | Impair Defenses: Disable Cloud Logs | T1562.008 | 2 | `StopLogging` → `StartLogging`, 61s apart |
| 04 | Cloud Infrastructure Discovery | T1580 | 2 | IAM/S3/EC2 enumeration burst |
| 05 | Valid Accounts: Cloud Accounts | T1078.004 | 0 | no auth anomalies present — correct result |

Query files are in `queries/`, result CSVs in `results/<date>/`.

## The finding that matters: tuning

The first run of the full query set returned **22 rows**. Fifteen of them were AWS console background activity — `GetAccountColor`, `GetAccountPlanState` and `ListDomains` polling every few minutes from the browser session, plus `AccessDenied` responses to those same calls.

| | First run | After tuning |
|---|---|---|
| 01 account creation | 2 | 2 |
| 02 privilege escalation | 1 | 1 |
| 03 impair logging | 2 | 2 |
| 04 discovery burst | 9 | 2 |
| 05 valid accounts | 8 | 0 |
| **Total** | **22** | **7** |

Every row that survives is real activity. The seven that were removed were removed because the noise was identified and excluded, not because the threshold was raised until the output looked clean.

This matters more than the queries themselves. `errorCode = 'AccessDenied'` looks like a reasonable detection signal and is close to useless on its own — legitimate tooling generates it constantly. A query validated only against planted attack data will never reveal that.

## What the data actually showed

**Privilege escalation was two seconds wide.** `CreateUser` at 16:04:32, `AttachUserPolicy` granting AdministratorAccess at 16:04:34. Query 02 correlates the two and reports the interval, which is a stronger signal than either event alone.

**`StopLogging` is not instantaneous.** Events were still being recorded 53 seconds after the call. The 61-second interval between stop and start is therefore an upper bound on the blind window, not its measured width. Query 03 reports it as such.

**Absence of an event is not evidence it didn't happen.** Three IAM deletions that completed successfully were still missing from S3 twenty minutes later. Global IAM events route through `us-east-1` and deliver on a slower cadence than regional batches. Any detection that infers suppression from a quiet window will fire on delivery lag alone.

## Reproducing

```bash
# 1. Infrastructure — see docs/ for the full walkthrough
# 2. Generate activity to hunt
./scripts/generate_activity.sh

# 3. Create the Athena table (run once)
#    queries/00-create-table.sql

# 4. Run the hunt
chmod +x scripts/run-hunt.sh
./scripts/run-hunt.sh 2026/09/19
```

`run-hunt.sh` substitutes the partition date, submits each query, polls for completion, and writes one CSV per technique to `results/<date>/` with row counts and bytes scanned.

Requires an authenticated AWS CLI. AWS CloudShell is the simplest option — pre-authenticated, no long-lived access key on a local machine.

## Known limitations

**Struct field access is not guaranteed safe.** The queries select `userIdentity.userName`, `userIdentity.invokedBy` and `userIdentity.sessionContext.attributes.mfaAuthenticated`. These worked against every event in this dataset, but CloudTrail's `userIdentity` shape varies by event type and a variant-shaped record can raise `HIVE_BAD_DATA` when sub-fields are selected. A production version would either guard these with `try()` or key on scalar top-level columns only.

**Thresholds are calibrated to an almost-empty account.** `distinct_apis >= 3` in query 04 would fire constantly in a real environment. The threshold has to come from a baseline of actual traffic.

**No data events.** Only management events are captured. S3 object-level and Lambda invocation activity is invisible to this pipeline, which is a deliberate cost decision, not an oversight.

**Single-account scope.** No organisation trail, no cross-account role assumption paths, and no GuardDuty correlation.

**Query 05 is under-tested.** It returns zero rows because the account has no failed console logins or MFA-less access to find. Correct, but untested against positive cases.

## Repository layout

```
queries/     00-create-table.sql + five ATT&CK-mapped hunting queries
scripts/     generate_activity.sh (attack simulation), run-hunt.sh (runner)
results/     query output CSVs by date
docs/        build notes and activity run logs
screenshots/ evidence captures
```
