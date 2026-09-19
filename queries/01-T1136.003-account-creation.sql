-- T1136.003  Create Account: Cloud Account
-- Surfaces new IAM principals and the credentials minted for them.
-- Lab expectation: CreateUser + CreateAccessKey for hunt-test-user at 16:04.

SELECT
  eventTime,
  eventName,
  userIdentity.userName                                   AS actor,
  userIdentity.arn                                        AS actor_arn,
  json_extract_scalar(requestParameters, '$.userName')    AS target_user,
  json_extract_scalar(requestParameters, '$.roleName')    AS target_role,
  sourceIPAddress,
  errorCode
FROM cloudtrail_hunt.cloudtrail_logs
WHERE dt = '__DT__'
  AND eventSource = 'iam.amazonaws.com'
  AND eventName IN (
        'CreateUser',
        'CreateRole',
        'CreateLoginProfile',
        'CreateAccessKey',
        'CreateServiceLinkedRole'
      )
  -- AWS services create their own service-linked roles constantly; those are
  -- not account creation by a human principal.
  AND userIdentity.invokedBy IS NULL
  AND userIdentity.type <> 'AWSService'
ORDER BY eventTime;
