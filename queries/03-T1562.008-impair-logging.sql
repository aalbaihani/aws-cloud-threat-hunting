-- T1562.008  Impair Defenses: Disable or Modify Cloud Logs
-- Detects tampering with CloudTrail and measures how long logging was off.
--
-- Note on interpretation: StopLogging does not take effect instantly. In this
-- lab, events were still recorded 53 seconds after StopLogging was called, so
-- the interval below is an UPPER bound on the blind window, not its true width.
-- Absence of events in a window is never on its own proof of suppression --
-- CloudTrail delivery to S3 also lags by minutes.
--
-- Lab expectation: StopLogging 16:05:24 -> StartLogging 16:06:25 (61s).

WITH trail_events AS (
  SELECT
    from_iso8601_timestamp(eventTime)                        AS ts,
    eventName,
    userIdentity.userName                                    AS actor,
    userIdentity.arn                                         AS actor_arn,
    json_extract_scalar(requestParameters, '$.name')         AS trail_name,
    sourceIPAddress,
    errorCode
  FROM cloudtrail_hunt.cloudtrail_logs
  WHERE dt = '__DT__'
    AND eventSource = 'cloudtrail.amazonaws.com'
    AND eventName IN (
          'StopLogging','StartLogging','DeleteTrail','UpdateTrail',
          'PutEventSelectors','RemoveTags'
        )
    AND userIdentity.invokedBy IS NULL
)
SELECT
  ts                                                         AS event_time,
  eventName,
  actor,
  trail_name,
  sourceIPAddress,
  errorCode,
  LEAD(ts)      OVER (PARTITION BY trail_name ORDER BY ts)   AS next_trail_event_time,
  LEAD(eventName) OVER (PARTITION BY trail_name ORDER BY ts) AS next_trail_event,
  CASE
    WHEN eventName = 'StopLogging' THEN
      date_diff('second', ts,
        LEAD(ts) OVER (PARTITION BY trail_name ORDER BY ts))
  END                                                        AS seconds_until_next,
  CASE
    WHEN eventName = 'DeleteTrail'                    THEN 'CRITICAL - trail destroyed'
    WHEN eventName = 'StopLogging'                    THEN 'HIGH - logging disabled'
    WHEN eventName = 'PutEventSelectors'              THEN 'MEDIUM - capture scope changed'
    WHEN eventName = 'UpdateTrail'                    THEN 'MEDIUM - trail reconfigured'
    ELSE 'INFO'
  END                                                        AS assessment
FROM trail_events
ORDER BY ts;
