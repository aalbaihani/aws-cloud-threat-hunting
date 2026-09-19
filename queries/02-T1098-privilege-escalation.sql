-- T1098  Account Manipulation
-- Two parts: (a) any grant of a high-privilege managed policy, and
-- (b) the create-then-escalate pattern, where a principal is created and
-- granted privileges within a short window by the same actor.
-- Lab expectation: CreateUser 16:04:32 -> AttachUserPolicy 16:04:34 (2s).

WITH grants AS (
  SELECT
    from_iso8601_timestamp(eventTime)                          AS ts,
    eventName,
    userIdentity.userName                                      AS actor,
    COALESCE(
      json_extract_scalar(requestParameters, '$.userName'),
      json_extract_scalar(requestParameters, '$.roleName'),
      json_extract_scalar(requestParameters, '$.groupName')
    )                                                          AS target,
    json_extract_scalar(requestParameters, '$.policyArn')      AS policy_arn,
    sourceIPAddress,
    errorCode
  FROM cloudtrail_hunt.cloudtrail_logs
  WHERE dt = '__DT__'
    AND eventSource = 'iam.amazonaws.com'
    AND eventName IN (
          'AttachUserPolicy','AttachRolePolicy','AttachGroupPolicy',
          'PutUserPolicy','PutRolePolicy','PutGroupPolicy',
          'AddUserToGroup','UpdateAssumeRolePolicy'
        )
    AND userIdentity.invokedBy IS NULL
    AND userIdentity.type <> 'AWSService'
),
creations AS (
  SELECT
    from_iso8601_timestamp(eventTime)                        AS ts,
    userIdentity.userName                                    AS actor,
    json_extract_scalar(requestParameters, '$.userName')     AS target
  FROM cloudtrail_hunt.cloudtrail_logs
  WHERE dt = '__DT__'
    AND eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreateUser'
)
SELECT
  g.ts                                                       AS grant_time,
  g.eventName,
  g.actor,
  g.target,
  g.policy_arn,
  g.sourceIPAddress,
  c.ts                                                       AS created_time,
  date_diff('second', c.ts, g.ts)                            AS seconds_after_creation,
  CASE
    WHEN g.policy_arn LIKE '%AdministratorAccess%'           THEN 'HIGH - admin policy'
    WHEN g.policy_arn LIKE '%PowerUserAccess%'               THEN 'HIGH - power user'
    WHEN g.policy_arn LIKE '%IAMFullAccess%'                 THEN 'HIGH - IAM control'
    WHEN c.ts IS NOT NULL
         AND date_diff('second', c.ts, g.ts) <= 300          THEN 'MEDIUM - escalated within 5m of creation'
    ELSE 'LOW - review'
  END                                                        AS assessment
FROM grants g
LEFT JOIN creations c
  ON c.target = g.target
 AND c.actor  = g.actor
 AND g.ts >= c.ts
ORDER BY g.ts;
