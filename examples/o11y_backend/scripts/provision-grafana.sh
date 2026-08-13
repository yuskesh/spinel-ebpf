#!/bin/sh
# Provision Grafana with an Infinity datasource + a logs dashboard, as one
# repeatable command (a fresh Grafana container starts with an empty database,
# so re-provisioning has to be cheap).
#   sh provision-grafana.sh <grafana_base> <backend_base>
#   e.g. sh provision-grafana.sh http://127.0.0.1:3000 http://127.0.0.1:4319
# Auth via GRAFANA_AUTH (default admin:admin -- local testing only).
set -e
graf="${1:?usage: provision-grafana.sh <grafana_base> <backend_base>}"
backend="${2:?usage: provision-grafana.sh <grafana_base> <backend_base>}"
auth="${GRAFANA_AUTH:-admin:admin}"

# datasource (reuse if one with this name exists)
uid=$(curl -sf -u "$auth" "$graf/api/datasources/name/spinel-o11y" 2>/dev/null \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['uid'])" 2>/dev/null || true)
if [ -z "$uid" ]; then
  uid=$(curl -sf -u "$auth" -X POST -H "Content-Type: application/json" "$graf/api/datasources" \
    -d "{\"name\":\"spinel-o11y\",\"type\":\"yesoreyeram-infinity-datasource\",\"access\":\"proxy\",
         \"jsonData\":{\"allowedHosts\":[\"$backend\"]}}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['datasource']['uid'])")
fi
echo "datasource uid: $uid"

target() { # refId, body-json (escaped), extra columns json
  cat <<EOF
{"refId": "$1", "type": "json", "source": "url", "parser": "backend",
 "url": "$backend/api/v1/query",
 "url_options": {"method": "POST", "body_type": "raw", "body_content_type": "application/json", "data": "$2"},
 "root_selector": "rows",
 "columns": [
   {"selector": "ts_ms", "text": "time", "type": "timestamp_epoch"},
   {"selector": "service", "text": "service", "type": "string"},
   {"selector": "severity", "text": "severity", "type": "number"},
   {"selector": "severity_text", "text": "level", "type": "string"},
   {"selector": "body", "text": "body", "type": "string"}
 ],
 "format": "table"}
EOF
}

curl -sf -u "$auth" -X POST -H "Content-Type: application/json" "$graf/api/dashboards/db" -d "{
  \"dashboard\": {
    \"uid\": \"spinel-o11y-logs\",
    \"title\": \"spinel o11y backend — logs\",
    \"time\": {\"from\": \"2023-11-14T22:00:00Z\", \"to\": \"2023-11-14T23:00:00Z\"},
    \"panels\": [
      {\"id\": 1, \"title\": \"All logs\", \"type\": \"table\",
       \"gridPos\": {\"h\": 9, \"w\": 24, \"x\": 0, \"y\": 0},
       \"datasource\": {\"type\": \"yesoreyeram-infinity-datasource\", \"uid\": \"$uid\"},
       \"targets\": [$(target A "{\\\"format\\\":\\\"objects\\\"}")]},
      {\"id\": 2, \"title\": \"Errors (severity >= 17)\", \"type\": \"table\",
       \"gridPos\": {\"h\": 9, \"w\": 24, \"x\": 0, \"y\": 9},
       \"datasource\": {\"type\": \"yesoreyeram-infinity-datasource\", \"uid\": \"$uid\"},
       \"targets\": [$(target B "{\\\"format\\\":\\\"objects\\\",\\\"severity_min\\\":17}")]}
    ]
  },
  \"overwrite\": true
}" | python3 -c "import json,sys; d=json.load(sys.stdin); print('dashboard:', d['status'], '->', '$graf' + d['url'])"
