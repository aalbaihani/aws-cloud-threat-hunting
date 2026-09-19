#!/usr/bin/env bash
# Run every hunting query against the CloudTrail table and save results as CSV.
#
# Usage:
#   ./run-hunt.sh                 # today's partition, UTC
#   ./run-hunt.sh 2026/09/19      # a specific day
#
# Results land in ./results/<date>/ as one CSV per technique.

set -euo pipefail

DT="${1:-$(date -u +%Y/%m/%d)}"
REGION="${AWS_REGION:-ap-southeast-2}"
WORKGROUP="${ATHENA_WORKGROUP:-primary}"
DATABASE="${ATHENA_DATABASE:-cloudtrail_hunt}"

ACCT="$(aws sts get-caller-identity --query Account --output text)"
OUTPUT="s3://athena-results-${ACCT}/"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QDIR="${HERE}/../queries"
RESULTS="${HERE}/../results/${DT//\//-}"
mkdir -p "$RESULTS"

echo "Partition : ${DT}"
echo "Region    : ${REGION}"
echo "Workgroup : ${WORKGROUP}"
echo "Results   : ${RESULTS}"
echo

for sql in "$QDIR"/*.sql; do
  name="$(basename "$sql" .sql)"
  printf '%-44s ' "$name"

  # Substitute the partition date into a temp copy.
  tmp="$(mktemp)"
  sed "s|__DT__|${DT}|g" "$sql" > "$tmp"

  qid="$(aws athena start-query-execution \
          --query-string "file://${tmp}" \
          --work-group "$WORKGROUP" \
          --query-execution-context "Database=${DATABASE}" \
          --result-configuration "OutputLocation=${OUTPUT}" \
          --region "$REGION" \
          --query QueryExecutionId --output text)"

  # Poll until the query leaves the running states.
  state=RUNNING
  for _ in $(seq 1 60); do
    read -r state reason <<<"$(aws athena get-query-execution \
        --query-execution-id "$qid" --region "$REGION" \
        --query 'QueryExecution.Status.[State,StateChangeReason]' \
        --output text)"
    [[ "$state" == "QUEUED" || "$state" == "RUNNING" ]] || break
    sleep 2
  done

  if [[ "$state" != "SUCCEEDED" ]]; then
    echo "FAILED (${state}): ${reason}"
    rm -f "$tmp"
    continue
  fi

  scanned="$(aws athena get-query-execution --query-execution-id "$qid" \
      --region "$REGION" \
      --query 'QueryExecution.Statistics.DataScannedInBytes' --output text)"

  aws s3 cp "${OUTPUT}${qid}.csv" "${RESULTS}/${name}.csv" --quiet
  rows="$(( $(wc -l < "${RESULTS}/${name}.csv") - 1 ))"

  echo "${rows} rows, $(( scanned / 1024 )) KB scanned"
  rm -f "$tmp"
done

echo
echo "Done. CSVs in ${RESULTS}"
