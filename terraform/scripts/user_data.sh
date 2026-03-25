#!/bin/bash
set -euxo pipefail

# ---------------------------------------------------------------------------
# 1. Write IoT certificates
# ---------------------------------------------------------------------------
mkdir -p /etc/aws-iot
chmod 755 /etc/aws-iot

cat <<FILE > /etc/aws-iot/device-cert.pem
${DEVICE_CERT}
FILE

cat <<FILE > /etc/aws-iot/private-key.pem
${PRIVATE_KEY}
FILE

chmod 644 /etc/aws-iot/device-cert.pem
chmod 600 /etc/aws-iot/private-key.pem

# Download Amazon Root CA
curl -fsSL -o /etc/aws-iot/AmazonRootCA1.pem \
  https://www.amazontrust.com/repository/AmazonRootCA1.pem

# ---------------------------------------------------------------------------
# 2. System packages
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3-pip python3-dev python3-venv awscli jq

# ---------------------------------------------------------------------------
# 3. Python dependencies
# ---------------------------------------------------------------------------
pip3 install --break-system-packages awsiotsdk python-dotenv

# ---------------------------------------------------------------------------
# 4. Write .env for mqtt_publish.py
#
# FIX 1: CLIENT_ID must match the IoT Thing name ("thing") so that the
#         iot:Connect policy — scoped to client/thing — allows the connection.
#         The original value "python-publisher" did not match and would have
#         caused an immediate CONNACK rejection from IoT Core.
#
# FIX 2: TOPIC must match both the IoT policy resource ARN and the Topic Rule
#         SQL filter, which are now all aligned to "topic/mqtt/thing".
#         The original TOPIC "topic/mqtt" did not match the scoped policy ARN
#         "topic/mqtt/thing" so every Publish would have been unauthorised.
# ---------------------------------------------------------------------------
cat <<EOF > /home/ubuntu/.env
ENDPOINT=${ENDPOINT}
CLIENT_ID=thing
TOPIC=topic/mqtt/thing
PUBLISH_INTERVAL=5
PATH_TO_CERT=/etc/aws-iot/device-cert.pem
PATH_TO_KEY=/etc/aws-iot/private-key.pem
PATH_TO_ROOT=/etc/aws-iot/AmazonRootCA1.pem
EOF

chown ubuntu:ubuntu /home/ubuntu/.env
chmod 600 /home/ubuntu/.env

# ---------------------------------------------------------------------------
# 5. Deploy mqtt_publish.py
# ---------------------------------------------------------------------------
mkdir -p /opt/iot-publisher
cat <<PYEOF > /opt/iot-publisher/mqtt_publish.py
${MQTT_SCRIPT}
PYEOF

chown -R ubuntu:ubuntu /opt/iot-publisher
chmod +x /opt/iot-publisher/mqtt_publish.py

# ---------------------------------------------------------------------------
# 6. Create systemd service
# ---------------------------------------------------------------------------
cat <<'SERVICE' > /etc/systemd/system/mqtt-publisher.service
[Unit]
Description=AWS IoT MQTT Publisher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/iot-publisher
EnvironmentFile=/home/ubuntu/.env
ExecStart=/usr/bin/python3 /opt/iot-publisher/mqtt_publish.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable mqtt-publisher.service
systemctl start mqtt-publisher.service