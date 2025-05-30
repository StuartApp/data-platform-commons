#!/bin/bash

set -euo pipefail

# Parse Sysdig scan output and extract vulnerability counts
# Usage: ./parse-sysdig-output.sh <scan_outcome>

SCAN_OUTCOME="$1"

echo "Sysdig scan outcome: $SCAN_OUTCOME"

SCAN_RESULTS_JSON="scan-results.json"
CRITICAL_COUNT="0"
CRITICAL_FIXABLE="0"
HIGH_COUNT="0"
HIGH_FIXABLE="0"
TOTAL_CRITICAL_HIGH="0"
SCAN_RESULT_ID=""

# Try to parse JSON results first
if [ -f "$SCAN_RESULTS_JSON" ]; then
  if jq . "$SCAN_RESULTS_JSON" > /dev/null 2>&1; then
    echo "Parsing JSON scan results..."
    
    # Get vulnerability counts from scan results
    CRITICAL_COUNT=$(jq -r '.result.vulnTotalBySeverity.critical // 0' "$SCAN_RESULTS_JSON" 2>/dev/null)
    HIGH_COUNT=$(jq -r '.result.vulnTotalBySeverity.high // 0' "$SCAN_RESULTS_JSON" 2>/dev/null)
    
    # Try to get fixable counts (if available in the JSON structure)
    CRITICAL_FIXABLE=$(jq -r '.result.fixableVulnTotalBySeverity.critical // 0' "$SCAN_RESULTS_JSON" 2>/dev/null)
    HIGH_FIXABLE=$(jq -r '.result.fixableVulnTotalBySeverity.high // 0' "$SCAN_RESULTS_JSON" 2>/dev/null)
    
    echo "Found $CRITICAL_COUNT critical vulnerabilities ($CRITICAL_FIXABLE fixable)"
    echo "Found $HIGH_COUNT high vulnerabilities ($HIGH_FIXABLE fixable)"
  fi
fi

# Fallback to log parsing if JSON didn't yield counts
if [ "$CRITICAL_COUNT" = "0" ] && [ "$HIGH_COUNT" = "0" ]; then
  echo "JSON parsing yielded no results, falling back to log parsing..."
  
  for file in scan-logs/*.log scan-logs/*.txt *.log *.txt; do
    if [ -f "$file" ]; then
      echo "Checking file: $file"
      

      CRITICAL_LINE=$(grep -oE "[0-9]+ Critical \([0-9]+ fixable\)" "$file" 2>/dev/null | head -1 || echo "")
      if [ -n "$CRITICAL_LINE" ]; then
        CRITICAL_COUNT=$(echo "$CRITICAL_LINE" | grep -oE "^[0-9]+" || echo "0")
        CRITICAL_FIXABLE=$(echo "$CRITICAL_LINE" | grep -oE "\([0-9]+" | tr -d '(' || echo "0")
      fi
      
      HIGH_LINE=$(grep -oE "[0-9]+ High \([0-9]+ fixable\)" "$file" 2>/dev/null | head -1 || echo "")
      if [ -n "$HIGH_LINE" ]; then
        HIGH_COUNT=$(echo "$HIGH_LINE" | grep -oE "^[0-9]+" || echo "0")
        HIGH_FIXABLE=$(echo "$HIGH_LINE" | grep -oE "\([0-9]+" | tr -d '(' || echo "0")
      fi
      
      # Break if we found some data
      if [ "$CRITICAL_COUNT" != "0" ] || [ "$HIGH_COUNT" != "0" ]; then
        echo "Found $CRITICAL_COUNT critical ($CRITICAL_FIXABLE fixable) and $HIGH_COUNT high ($HIGH_FIXABLE fixable) from log parsing"
        break
      fi
    fi
  done
fi

# Extract scan result ID from logs for detailed URL
for file in scan-logs/*.log scan-logs/*.txt *.log *.txt; do
  if [ -f "$file" ]; then
    SCAN_ID_LINE=$(grep -o "scan-result-id=[a-f0-9]*" "$file" 2>/dev/null | head -1 || echo "")
    if [ -n "$SCAN_ID_LINE" ]; then
      SCAN_RESULT_ID=$(echo "$SCAN_ID_LINE" | cut -d'=' -f2)
      echo "Found scan result ID: $SCAN_RESULT_ID"
      break
    fi
  fi
done

# Calculate total critical + high for notification decision
TOTAL_CRITICAL_HIGH=$((CRITICAL_COUNT + HIGH_COUNT))

# If no specific count found but scan failed, we know there are vulnerabilities
if [ "$TOTAL_CRITICAL_HIGH" = "0" ] && [ "$SCAN_OUTCOME" = "failure" ]; then
  CRITICAL_COUNT="detected"
  TOTAL_CRITICAL_HIGH="1"  # Trigger notification
fi

echo "Final counts: $CRITICAL_COUNT critical ($CRITICAL_FIXABLE fixable), $HIGH_COUNT high ($HIGH_FIXABLE fixable)"

# Export to GitHub environment
echo "CRITICAL_COUNT=$CRITICAL_COUNT" >> "$GITHUB_ENV"
echo "CRITICAL_FIXABLE=$CRITICAL_FIXABLE" >> "$GITHUB_ENV"
echo "HIGH_COUNT=$HIGH_COUNT" >> "$GITHUB_ENV"
echo "HIGH_FIXABLE=$HIGH_FIXABLE" >> "$GITHUB_ENV"
echo "TOTAL_CRITICAL_HIGH=$TOTAL_CRITICAL_HIGH" >> "$GITHUB_ENV"
echo "SCAN_RESULT_ID=$SCAN_RESULT_ID" >> "$GITHUB_ENV" 