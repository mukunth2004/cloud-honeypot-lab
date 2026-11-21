#!/bin/bash
# Installs Docker, Cowrie and Filebeat. Runs once, as root, on first boot.
set -euxo pipefail
exec > >(tee /var/log/user-data.log) 2>&1

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io awscli
systemctl enable --now docker

# ---- Cowrie (unchanged) ----
systemctl disable --now ssh || true
systemctl disable --now ssh.socket || true

mkdir -p /var/log/cowrie
chown 999:999 /var/log/cowrie

docker run -d \
  --name cowrie \
  --restart always \
  -p 22:2222 \
  -v /var/log/cowrie:/cowrie/cowrie-git/var/log/cowrie \
  cowrie/cowrie@sha256:99dc2531f317b0d1a44feccd1cdd2a5ec8fc456b31cb0ed59e7bed1a35dbd345

# ---- Filebeat ----
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor --yes -o /usr/share/keyrings/elastic-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" > /etc/apt/sources.list.d/elastic-9.x.list
apt-get update -y
apt-get install -y filebeat=${filebeat_version}

# API key: read from Parameter Store straight into Filebeat's keystore (never printed)
filebeat keystore create --force
aws ssm get-parameter --region ${aws_region} --name /${project_name}/filebeat-api-key --with-decryption --query Parameter.Value --output text | filebeat keystore add ES_API_KEY --stdin --force

cat > /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
  - type: filestream
    id: cowrie-json
    paths:
      - /var/log/cowrie/cowrie.json*
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
          add_error_key: true

processors:
  - timestamp:
      field: timestamp
      layouts:
        - '2006-01-02T15:04:05.999999Z'
        - '2006-01-02T15:04:05Z'
      test:
        - '2026-11-14T14:07:52.551806Z'
  - drop_fields:
      fields: ["timestamp"]
      ignore_missing: true

output.elasticsearch:
  hosts: ["${elastic_endpoint}"]
  api_key: "$${ES_API_KEY}"

setup.ilm.enabled: false
logging.level: info
EOF
chmod 600 /etc/filebeat/filebeat.yml

systemctl enable --now filebeat