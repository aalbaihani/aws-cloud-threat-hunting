-- T1078.004  Valid Accounts: Cloud Accounts
-- Authentication and session anomalies: failed console logins, logins without
-- MFA, and principals appearing from source IPs they have not used before.
--
-- The "new source IP" half of this is only meaningful once the trail has run
-- long enough to establish a baseline. On a one-day dataset every IP is new,
-- so treat first_seen_today as informational until you have a week of data.

WITH auth AS (
  SELECT
    from_iso8601_timestamp(eventTime)                         AS ts,
    eventName,
    COALESCE(userIdentity.userName, userIdentity.arn)         AS principal,
    userIdentity.type                                         AS principal_type,
    sourceIPAddress,
    userAgent,
    errorCode,
    errorMessage,
    userIdentity.sessionContext.attributes.mfaAuthenticated   AS mfa,
    json_extract_scalar(additionalEventData, '$.MFAUsed')     AS console_mfa
  FROM cloudtrail_hunt.cloudtrail_logs
  WHERE dt = '__DT__'
    AND (
          eventName IN ('ConsoleLogin','AssumeRole','GetSessionToken',
                        'GetFederationToken','SwitchRole')
       OR errorCode IN ('AccessDenied','UnauthorizedOperation',
                        'InvalidClientTokenId','SignatureDoesNotMatch')
        )
    AND userIdentity.invokedBy IS NULL
    AND eventName NOT IN ('GetAccountColor','GetAccountInformation','DescribeEventAggregates')
),
ip_first_seen AS (
  SELECT principal, sourceIPAddress, MIN(ts) AS first_seen
  FROM auth
  GROUP BY 1, 2
)
SELECT
  a.ts                                                        AS event_time,
  a.eventName,
  a.principal,
  a.principal_type,
  a.sourceIPAddress,
  a.errorCode,
  a.mfa,
  a.console_mfa,
  f.first_seen                                                AS ip_first_seen_today,
  CASE
    WHEN a.eventName = 'ConsoleLogin'
         AND a.errorCode IS NOT NULL                          THEN 'HIGH - failed console login'
    WHEN a.eventName = 'ConsoleLogin'
         AND COALESCE(a.console_mfa, 'No') = 'No'             THEN 'HIGH - console login without MFA'
    WHEN a.errorCode IN ('InvalidClientTokenId',
                         'SignatureDoesNotMatch')             THEN 'MEDIUM - invalid credential use'
    WHEN a.errorCode = 'AccessDenied'                         THEN 'LOW - denied, may be benign'
    ELSE 'INFO'
  END                                                         AS assessment
FROM auth a
LEFT JOIN ip_first_seen f
  ON f.principal = a.principal
 AND f.sourceIPAddress = a.sourceIPAddress
ORDER BY a.ts;
