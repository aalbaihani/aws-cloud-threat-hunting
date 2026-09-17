-- ============================================================
-- Cloud threat detections over CloudTrail via Athena
-- Table: cloudtrail_logs | Region: ap-southeast-2
-- Note: userIdentity is declared as a STRUCT (SerDe requirement) but
-- selecting struct sub-fields throws HIVE_BAD_DATA on variant-shaped
-- events, so detections key on scalar top-level columns.
-- ============================================================

-- D1 - Defense evasion: CloudTrail logging disabled (T1562.001)
SELECT eventtime, eventname, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE eventname IN ('StopLogging','StartLogging')
ORDER BY eventtime;

-- D2 - Rogue admin account lifecycle (T1136 / T1098)
SELECT eventtime, eventname, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('CreateUser','AttachUserPolicy','DetachUserPolicy','DeleteUser')
  AND eventtime >= '2026-09-13T14:00:00Z'
ORDER BY eventtime;

-- D3 - Persistence via access key creation (T1098)
SELECT eventtime, eventname, sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'CreateAccessKey'
  AND eventtime >= '2026-09-13T14:00:00Z'
ORDER BY eventtime;

-- D4 - S3 defense weakening: public-access block changed (T1562)
SELECT eventtime, eventname, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('DeletePublicAccessBlock','PutBucketPublicAccessBlock')
ORDER BY eventtime;

-- D5 - Failed privilege use: denied/errored calls (T1078)
SELECT eventtime, eventname, errorcode, sourceipaddress
FROM cloudtrail_logs
WHERE errorcode IS NOT NULL
  AND eventname IN ('AssumeRole','GetSessionToken','CreateUser','AttachUserPolicy')
  AND eventtime >= '2026-09-13T14:00:00Z'
ORDER BY eventtime;

-- D6 - Discovery burst: IAM enumeration volume per minute (T1087)
SELECT date_trunc('minute', from_iso8601_timestamp(eventtime)) AS minute,
       count(*) AS iam_read_calls
FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND (eventname LIKE 'List%' OR eventname LIKE 'Get%')
GROUP BY date_trunc('minute', from_iso8601_timestamp(eventtime))
HAVING count(*) >= 3
ORDER BY minute;
