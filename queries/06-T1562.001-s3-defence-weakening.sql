-- T1562.001  Impair Defenses: Disable or Modify Tools (S3 protections)
-- Weakening of bucket-level protections: public access blocks removed,
-- policies rewritten, encryption or logging turned off.
--
-- Carried over from an earlier iteration of this lab, where detections keyed
-- on scalar top-level columns only. Kept in that form deliberately -- see the
-- struct-access limitation in the repo README.
--
-- No hits expected in this dataset: the lab bucket was hardened at creation
-- and never loosened. Included because a hunting pack that only contains
-- queries with known hits has not been tested against a negative case.

SELECT
  eventTime,
  eventName,
  eventSource,
  sourceIPAddress,
  userAgent,
  errorCode,
  json_extract_scalar(requestParameters, '$.bucketName') AS bucket_name,
  CASE
    WHEN eventName = 'DeleteBucketPublicAccessBlock'  THEN 'CRITICAL - public access block removed'
    WHEN eventName = 'PutBucketPublicAccessBlock'     THEN 'HIGH - public access block modified'
    WHEN eventName = 'PutBucketPolicy'                THEN 'HIGH - bucket policy rewritten'
    WHEN eventName = 'DeleteBucketPolicy'             THEN 'HIGH - bucket policy removed'
    WHEN eventName = 'PutBucketAcl'                   THEN 'MEDIUM - bucket ACL changed'
    WHEN eventName = 'DeleteBucketEncryption'         THEN 'HIGH - encryption disabled'
    WHEN eventName = 'PutBucketLogging'               THEN 'MEDIUM - access logging changed'
    WHEN eventName = 'DeleteBucketLifecycle'          THEN 'LOW - lifecycle removed'
    ELSE 'INFO'
  END                                                 AS assessment
FROM cloudtrail_hunt.cloudtrail_logs
WHERE dt = '__DT__'
  AND eventSource = 's3.amazonaws.com'
  AND eventName IN (
        'DeleteBucketPublicAccessBlock',
        'PutBucketPublicAccessBlock',
        'PutBucketPolicy',
        'DeleteBucketPolicy',
        'PutBucketAcl',
        'DeleteBucketEncryption',
        'PutBucketLogging',
        'DeleteBucketLifecycle'
      )
ORDER BY eventTime;
