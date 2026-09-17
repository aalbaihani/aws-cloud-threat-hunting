# AWS Cloud Threat Hunting — CloudTrail + Athena

Detection engineering in the cloud control plane. This lab provisions CloudTrail management-event logging, generates a set of reversible adversary actions mapped to MITRE ATT&CK, and hunts them with Amazon Athena SQL over the raw logs in S3.

It is the third project in a detection-engineering portfolio:

1. **[mitre-soc-detection-lab-arm64](https://github.com/aalbaihani/mitre-soc-detection-lab-arm64)** — endpoint detection (Sysmon → Splunk, T1059.001 & T1003.001)
2. **[soar-shuffle-automation](https://github.com/aalbaihani/soar-shuffle-automation)** — automated response (Shuffle SOAR, IOC enrichment)
3. **This repo** — the same detection thinking applied to cloud audit logs

Built and proven end to end in `ap-southeast-2` on an AWS Free-plan account. Every result shown is from this deployment; the failures and workarounds are documented rather than hidden.

---

## Architecture

```
        Adversary actions (scripts/generate_activity.sh)
                        │  reversible IAM / S3 / CloudTrail API calls
                        ▼
                   CloudTrail  ──►  S3 (management events, JSON.gz)
                        │
                        ▼
     Athena external table (cloudtrail_logs)  ──►  6 detection queries
                        │
                        ▼
            Attack chain reconstructed from audit logs
```

- **Telemetry:** a single multi-region CloudTrail trail, management events only, SSE-S3 (no KMS billing), log-file validation enabled.
- **Query engine:** Athena SQL (engine v3) reading the CloudTrail JSON in place via the AWS CloudTrail SerDe — no data copied.
- **Cost:** log volume is a few MB; at $5/TB scanned, each query costs a fraction of a cent. The trail's management events are free.

---

## The adversary activity

`scripts/generate_activity.sh` performs six reversible actions, each mapped to a technique. Every throwaway resource is cleaned up inline; nothing persists.

| # | Action | MITRE ATT&CK |
|---|--------|--------------|
| 1 | IAM enumeration (`ListUsers`, `ListRoles`, `ListPolicies`, `GetAccountAuthorizationDetails`) | T1087 Account Discovery / T1069 Permission Groups Discovery |
| 2 | Create then delete an access key on the admin user | T1098 Account Manipulation |
| 3 | Create a backdoor user, grant then revoke `AdministratorAccess`, delete | T1136 Create Account / T1098 |
| 4 | Create an S3 bucket, drop then restore its public-access block, delete | T1562 Impair Defenses |
| 5 | `AssumeRole` against a nonexistent role (denied) | T1078 Valid Accounts (failed) |
| 6 | `StopLogging` → `StartLogging` on the trail | T1562.001 Disable/Modify Cloud Logs |

---

## Detections

Six Athena queries in `queries/detections.sql`, one per technique. Full run transcript in `docs/`; screenshots in `screenshots/`.

| ID | Detects | Key signal | Result |
|----|---------|-----------|--------|
| D1 | CloudTrail logging disabled | `StopLogging` / `StartLogging` events | ✅ 14:15:06 → 14:15:12 |
| D2 | Rogue admin account lifecycle | `CreateUser` → `AttachUserPolicy` → `DetachUserPolicy` → `DeleteUser` | ✅ 14:14:54 → 14:14:59 |
| D3 | Persistence via access key | `CreateAccessKey` | ✅ 14:14:51 |
| D4 | S3 public-access block changed | `PutBucketPublicAccessBlock` / `DeletePublicAccessBlock` | ✅ 14:15:03 |
| D5 | Failed privilege use | non-null `errorCode` on sensitive calls | ✅ `AccessDenied` on `AssumeRole`, 14:15:05 |
| D6 | IAM discovery burst | ≥3 IAM `List*`/`Get*` calls per minute | ✅ 4 calls at 14:14 |

**D1 is the highest-fidelity detection.** An attacker disabling audit logging is a rare, high-signal event — and the `StopLogging` API call is itself recorded before logging pauses. The captured `userAgent` even preserves the exact CLI command (`...md/command#cloudtrail.stop-logging`).

The full attack chain reconstructs cleanly from the audit trail, in order, all originating from a single source IP within a ~20-second window.

---

## Gotchas (the parts tutorials skip)

Documenting these honestly is the point — each was a real obstacle with a real fix.

- **Free-plan time window.** The account runs on AWS's post-July-2025 Free plan: credit-based, ~6-month window, not the legacy 12-month tier. The lab is built to be self-contained so the repo stands alone as evidence after the account expires.
- **Athena workgroup engine.** The default `primary` workgroup ran the Trino engine, which rejects Hive `CREATE EXTERNAL TABLE` (`mismatched input 'EXTERNAL'`). Fixed by creating a dedicated workgroup pinned to **Athena engine version 3**.
- **CloudTrail SerDe vs. JSON blobs.** The generic JSON SerDe returns zero rows for CloudTrail (it doesn't unwrap the `Records` array). The AWS `CloudTrailSerde` does — but it maps `requestParameters`, `responseElements`, and `additionalEventData` as `STRING` while CloudTrail emits them as variable JSON objects, causing `HIVE_BAD_DATA`. Those columns are excluded from the schema.
- **The `userIdentity` struct.** The SerDe requires `userIdentity` declared as a `STRUCT`, but selecting any sub-field (`userIdentity.userName`, `.arn`) throws `HIVE_BAD_DATA` because failed and service-linked events carry variant `userIdentity` shapes. Detections therefore key on scalar top-level fields (`sourceIPAddress`, `errorCode`, `eventName`). This is an accepted trade-off — the scalar fields carry the detection signal.
- **D4 event source.** The public-access-block *restore* (`PutBucketPublicAccessBlock`) was captured; the *removal* (`DeletePublicAccessBlock`) logs under a different event source and did not surface in the management-event trail. The configuration change is still detected — arguably the `Put` is the more suspicious of the pair.

---

## Reproducing this

1. Create a CloudTrail trail (management events, S3 destination, SSE-S3, validation on).
2. Run `scripts/generate_activity.sh` from CloudShell (uses the caller's IAM identity; region `ap-southeast-2`).
3. Wait ~15 min for log delivery to S3.
4. Create an Athena SQL v3 workgroup and set a query-result bucket.
5. Create the table from `queries/00_create_table.sql` (substitute your account ID and bucket).
6. Run the detections in `queries/detections.sql`.

All queries were executed through the AWS CLI (`aws athena start-query-execution`) rather than the console query editor — see `docs/` for the wrapper used.

---

*Region: ap-southeast-2 · Timestamps in UTC · Account identifiers redacted throughout.*
