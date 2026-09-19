-- T1580  Cloud Infrastructure Discovery
-- Reconnaissance rarely shows up as one suspicious call; it shows up as an
-- unusual VARIETY of read-only calls from one principal in a short span.
-- This buckets activity into 5-minute windows and counts distinct API names.
--
-- The noise filters matter more than the detection logic here. CloudShell
-- heartbeats, health checks and service principals will otherwise dominate
-- every bucket -- in this account SendHeartBeat alone fires once a minute.
--
-- Lab expectation: a bucket around 15:58 and 16:03 containing ListUsers,
-- ListRoles, GetCallerIdentity, ListBuckets, DescribeInstances.

WITH reads AS (
  SELECT
    date_trunc('minute', from_iso8601_timestamp(eventTime))   AS minute_ts,
    eventName,
    eventSource,
    COALESCE(userIdentity.userName, userIdentity.arn)         AS principal,
    sourceIPAddress
  FROM cloudtrail_hunt.cloudtrail_logs
  WHERE dt = '__DT__'
    AND readOnly = 'true'
    AND userIdentity.invokedBy IS NULL
    AND userIdentity.type <> 'AWSService'
    -- Background chatter, not discovery.
    AND eventSource NOT IN (
          'cloudshell.amazonaws.com',
          'health.amazonaws.com',
          'notifications.amazonaws.com',
          'athena.amazonaws.com',
          'glue.amazonaws.com'
        )
    AND eventName NOT IN ('SendHeartBeat','GetEnvironmentStatus','PutCredentials','GetAccountColor','GetAccountPlanState','ListDomains','GetAccountInformation')
),
buckets AS (
  SELECT
    principal,
    sourceIPAddress,
    date_trunc('hour', minute_ts)
      + interval '5' minute * (minute(minute_ts) / 5)         AS bucket_start,
    COUNT(*)                                                  AS call_count,
    COUNT(DISTINCT eventName)                                 AS distinct_apis,
    COUNT(DISTINCT eventSource)                               AS distinct_services,
    array_join(array_agg(DISTINCT eventName), ', ')           AS apis_called
  FROM reads
  GROUP BY 1, 2, 3
)
SELECT
  bucket_start,
  principal,
  sourceIPAddress,
  call_count,
  distinct_apis,
  distinct_services,
  apis_called,
  CASE
    WHEN distinct_apis >= 8 AND distinct_services >= 4 THEN 'HIGH - broad enumeration'
    WHEN distinct_apis >= 5                            THEN 'MEDIUM - multi-service recon'
    ELSE 'LOW'
  END                                                         AS assessment
FROM buckets
WHERE distinct_apis >= 3          -- tune this threshold to your own baseline
ORDER BY distinct_apis DESC, bucket_start;
