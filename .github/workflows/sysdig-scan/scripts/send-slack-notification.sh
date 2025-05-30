#!/bin/bash

set -euo pipefail

# Send Slack notification for Sysdig scan results
# Usage: ./send-slack-notification.sh <webhook_url> <repo_name> <branch_name> <commit_sha> <workflow_url> <critical_count> <critical_fixable> <high_count> <high_fixable> <image_name> <scan_result_id>

WEBHOOK_URL="$1"
REPO_NAME="$2"
BRANCH_NAME="$3"
COMMIT_SHA="$4"
WORKFLOW_URL="$5"
CRITICAL_COUNT="$6"
CRITICAL_FIXABLE="$7"
HIGH_COUNT="$8"
HIGH_FIXABLE="$9"
IMAGE_NAME="${10}"
SCAN_RESULT_ID="${11}"

# Check if Slack webhook URL is configured
if [ -z "$WEBHOOK_URL" ]; then
  echo "⚠️  SLACK_WEBHOOK_URL_SYSDIG secret not configured - skipping Slack notification"
  echo "Found vulnerabilities but cannot send notification"
  exit 0
fi

# Build vulnerability summary
if [ "$CRITICAL_COUNT" = "detected" ]; then
  VULN_SUMMARY="Critical vulnerabilities detected"
else
  VULN_PARTS=()
  
  if [ "$CRITICAL_COUNT" != "0" ]; then
    if [ "$CRITICAL_FIXABLE" != "0" ]; then
      VULN_PARTS+=("$CRITICAL_COUNT Critical ($CRITICAL_FIXABLE fixable) \n ")
    else
      VULN_PARTS+=("$CRITICAL_COUNT Critical")
    fi
  fi
  
  if [ "$HIGH_COUNT" != "0" ]; then
    if [ "$HIGH_FIXABLE" != "0" ]; then
      VULN_PARTS+=("$HIGH_COUNT High ($HIGH_FIXABLE fixable)")
    else
      VULN_PARTS+=("$HIGH_COUNT High")
    fi
  fi
  
  # Join array elements with comma
  VULN_SUMMARY=$(IFS=', '; echo "${VULN_PARTS[*]}")
fi

# Build Sysdig URLs
PIPELINE_URL=""
RESULTS_URL=""

if [ -n "$IMAGE_NAME" ]; then
  # URL encode the image name for the pipeline filter
  ENCODED_IMAGE=$(echo "$IMAGE_NAME" | sed 's/:/\%3A/g' | sed 's/\//\%2F/g')
  PIPELINE_URL="https://eu1.app.sysdig.com/secure/#/vulnerabilities/overview/pipeline/?filter=context+%3D+%22pipeline%22+and+pullString+in+%28%22$ENCODED_IMAGE%22%29"
fi

if [ -n "$SCAN_RESULT_ID" ]; then
  RESULTS_URL="https://eu1.app.sysdig.com/secure/#/vulnerabilities/results/$SCAN_RESULT_ID/overview"
fi

# Build Sysdig links section
SYSDIG_LINKS=""
if [ -n "$PIPELINE_URL" ] || [ -n "$RESULTS_URL" ]; then
  SYSDIG_LINKS="\n\n🔍 *Sysdig Reports:*"
  if [ -n "$PIPELINE_URL" ]; then
    SYSDIG_LINKS="$SYSDIG_LINKS\n• <$PIPELINE_URL|Pipeline Overview>"
  fi
  if [ -n "$RESULTS_URL" ]; then
    SYSDIG_LINKS="$SYSDIG_LINKS\n• <$RESULTS_URL|Detailed Results>"
  fi
fi

MESSAGE="🚨 *Sysdig Security Scan Alert* 🚨\n\n*Repository:* $REPO_NAME\n*Branch:* $BRANCH_NAME\n*Commit:* ${COMMIT_SHA:0:7}\n\n❌ *$VULN_SUMMARY* found in the Docker image.$SYSDIG_LINKS\n\n🔗 [View workflow details]($WORKFLOW_URL)"

echo "Sending Slack notification for: $VULN_SUMMARY"

curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"$MESSAGE\"}" \
  "$WEBHOOK_URL"

if [ $? -eq 0 ]; then
  echo "✅ Slack notification sent successfully"
else
  echo "❌ Failed to send Slack notification"
  exit 1
fi 