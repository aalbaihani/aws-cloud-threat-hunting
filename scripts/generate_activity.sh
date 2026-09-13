#!/usr/bin/env bash
# ============================================================
# Phase 2 — Adversary activity generation
# Region: ap-southeast-2 | Identity: ali-admin
# Every action is reversible; throwaway resources are cleaned up inline.
# Each block maps to a MITRE ATT&CK technique hunted in Phase 3.
# ============================================================
ACCID=$(aws sts get-caller-identity --query Account --output text)
REGION=ap-southeast-2
STAMP=$(date +%s)
TRAIL=cyberlab-management-trail
echo ">> Account $ACCID  Region $REGION"

# 1. Discovery — enumerate IAM (T1087 Account Discovery / T1069)
echo ">> [1] Discovery: IAM enumeration"
aws iam list-users        --query 'Users[].UserName'   --output table
aws iam list-roles        --query 'Roles[].RoleName'   --output table
aws iam list-policies --scope Local --query 'Policies[].PolicyName' --output table
aws iam get-account-authorization-details --max-items 5 >/dev/null

# 2. Persistence — create then delete an access key on the admin (T1098)
echo ">> [2] Persistence: access key on ali-admin"
KEYID=$(aws iam create-access-key --user-name ali-admin --query 'AccessKey.AccessKeyId' --output text)
echo "   created $KEYID"; aws iam delete-access-key --user-name ali-admin --access-key-id "$KEYID"
echo "   deleted $KEYID"

# 3. Rogue account — backdoor admin user, then remove (T1136 / T1098)
echo ">> [3] Rogue account creation"
aws iam create-user       --user-name backdoor-$STAMP >/dev/null
aws iam attach-user-policy --user-name backdoor-$STAMP --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam detach-user-policy --user-name backdoor-$STAMP --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user        --user-name backdoor-$STAMP
echo "   removed backdoor-$STAMP"

# 4. Defense weakening on S3 — drop then restore public-access block (T1562)
echo ">> [4] S3: weaken then restore public-access block"
VICTIM=cyberlab-victim-$ACCID-$STAMP
aws s3api create-bucket --bucket "$VICTIM" --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION >/dev/null
aws s3api delete-public-access-block --bucket "$VICTIM"
aws s3api put-public-access-block --bucket "$VICTIM" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api delete-bucket --bucket "$VICTIM"
echo "   removed $VICTIM"

# 5. Failed privilege use — AssumeRole on a nonexistent role (error event)
echo ">> [5] Failed AssumeRole (expected to fail)"
aws sts assume-role --role-arn arn:aws:iam::$ACCID:role/does-not-exist-$STAMP \
  --role-session-name evil 2>&1 | head -2 || true

# 6. Defense evasion — stop then immediately restart the trail (T1562.001)
echo ">> [6] CloudTrail StopLogging -> StartLogging"
aws cloudtrail stop-logging  --name $TRAIL
sleep 5
aws cloudtrail start-logging --name $TRAIL
echo ">> Phase 2 complete. Wait ~15 min for delivery, then we hunt."
