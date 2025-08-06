#!/bin/bash
mkdir -p /etc/aws-iot
cat <<FILE > /etc/aws-iot/device-cert.pem
${DEVICE_CERT}
FILE

cat <<FILE > /etc/aws-iot/private-key.pem
${PRIVATE_KEY}
FILE

# Download Amazon Root CA
curl -o /etc/aws-iot/AmazonRootCA1.pem https://www.amazontrust.com/repository/AmazonRootCA1.pem
sudo apt-get update
sudo apt-get install -y python3-pip
sudo apt-get install -y python3-dev
sudo apt-get install -y python3-venv
sudo apt-get install -y awscli
sudo apt-get install -y jq
python3 -m pip install awsiotsdk --break-system-packages

echo "ENDPOINT=${ENDPOINT}" > /home/ubuntu/.env