CREATE EXTERNAL TABLE cloudtrail_hunt.cloudtrail_logs (
  eventVersion STRING,
  userIdentity STRUCT<type:STRING,principalId:STRING,arn:STRING,accountId:STRING,invokedBy:STRING,accessKeyId:STRING,userName:STRING,sessionContext:STRUCT<attributes:STRUCT<mfaAuthenticated:STRING,creationDate:STRING>,sessionIssuer:STRUCT<type:STRING,principalId:STRING,arn:STRING,accountId:STRING,userName:STRING>>>,
  eventTime STRING, eventSource STRING, eventName STRING, awsRegion STRING,
  sourceIpAddress STRING, userAgent STRING, errorCode STRING, errorMessage STRING,
  requestParameters STRING, responseElements STRING, additionalEventData STRING,
  requestId STRING, eventId STRING, readOnly STRING,
  resources ARRAY<STRUCT<arn:STRING,accountId:STRING,type:STRING>>,
  eventType STRING, apiVersion STRING, recipientAccountId STRING,
  serviceEventDetails STRING, sharedEventID STRING, vpcEndpointId STRING,
  tlsDetails STRUCT<tlsVersion:STRING,cipherSuite:STRING,clientProvidedHostHeader:STRING>
)
PARTITIONED BY (region STRING, dt STRING)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://cloudtrail-hunt-lab-<ACCOUNT_ID>/AWSLogs/<ACCOUNT_ID>/CloudTrail/'
TBLPROPERTIES (
  'projection.enabled'='true',
  'projection.region.type'='enum',
  'projection.region.values'='ap-southeast-2,us-east-1',
  'projection.dt.type'='date',
  'projection.dt.range'='2026/09/19,NOW',
  'projection.dt.format'='yyyy/MM/dd',
  'projection.dt.interval'='1',
  'projection.dt.interval.unit'='DAYS',
  'storage.location.template'='s3://cloudtrail-hunt-lab-<ACCOUNT_ID>/AWSLogs/<ACCOUNT_ID>/CloudTrail/${region}/${dt}'
)
