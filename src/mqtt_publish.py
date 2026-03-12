#!/usr/bin/env python3
"""
MQTT Publisher for AWS IoT Core
Publishes simulated IoT sensor data every 5 seconds.
"""
from dotenv import load_dotenv
import os
import json
import time
import logging
from awscrt import io, mqtt
from awsiot import mqtt_connection_builder

load_dotenv('/home/ubuntu/.env')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ENDPOINT       = os.getenv('ENDPOINT')
CLIENT_ID      = os.getenv('CLIENT_ID', 'python-publisher')
TOPIC          = os.getenv('TOPIC', f'devices/{os.getenv("CLIENT_ID", "python-publisher")}/telemetry')
PATH_TO_CERT   = os.getenv('PATH_TO_CERT',   '/etc/aws-iot/device-cert.pem')
PATH_TO_KEY    = os.getenv('PATH_TO_KEY',    '/etc/aws-iot/private-key.pem')
PATH_TO_ROOT   = os.getenv('PATH_TO_ROOT',   '/etc/aws-iot/AmazonRootCA1.pem')
PUBLISH_INTERVAL = int(os.getenv('PUBLISH_INTERVAL', '5'))

if not ENDPOINT:
    raise EnvironmentError("ENDPOINT environment variable is not set.")


# ---------------------------------------------------------------------------
# MQTT callbacks
# ---------------------------------------------------------------------------
def on_connection_interrupted(connection, error, **kwargs):
    logger.warning(f"Connection interrupted: {error}")


def on_connection_resumed(connection, return_code, session_present, **kwargs):
    logger.info(f"Connection resumed. return_code={return_code} session_present={session_present}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def build_message(count: int) -> dict:
    """Build a sensor payload. Timestamp is Unix epoch in MILLISECONDS."""
    return {
        "deviceId":      CLIENT_ID,
        "location":      "warehouse-a",
        # FIX: send milliseconds so transform.py round-trips cleanly
        "timestamp":     int(time.time() * 1000),
        "temperature":   round(20.0 + (count % 20) * 0.5, 2),   # simulated ramp
        "humidity":      round(55.0 + (count % 10) * 0.3, 2),
        "pressure":      round(1013.0 + (count % 5) * 0.1, 2),
        "message_count": count,
        "status":        "normal",
    }


def main():
    # Build MQTT connection
    event_loop_group = io.EventLoopGroup(1)
    host_resolver    = io.DefaultHostResolver(event_loop_group)
    client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        endpoint=ENDPOINT,
        cert_filepath=PATH_TO_CERT,
        pri_key_filepath=PATH_TO_KEY,
        client_bootstrap=client_bootstrap,
        ca_filepath=PATH_TO_ROOT,
        client_id=CLIENT_ID,
        clean_session=False,
        keep_alive_secs=30,
        on_connection_interrupted=on_connection_interrupted,
        on_connection_resumed=on_connection_resumed,
    )

    logger.info(f"Connecting to {ENDPOINT} as '{CLIENT_ID}' …")
    mqtt_connection.connect().result()
    logger.info("Connected!")

    count = 0
    try:
        while True:
            payload = build_message(count)
            message_json = json.dumps(payload)

            logger.info(f"Publishing #{count} → {TOPIC}: {message_json}")

            publish_future, _ = mqtt_connection.publish(
                topic=TOPIC,
                payload=message_json,
                qos=mqtt.QoS.AT_LEAST_ONCE,
            )
            publish_future.result()   # block until broker ACKs
            count += 1
            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt — disconnecting …")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
    finally:
        mqtt_connection.disconnect().result()
        logger.info("Disconnected.")


if __name__ == "__main__":
    main()