#!/usr/bin/env python3
from dotenv import load_dotenv
import os
import json
import time
from awscrt import io, mqtt
from awsiot import mqtt_connection_builder

load_dotenv('/home/ubuntu/.env')

# Configuration - Replace these with your values
ENDPOINT =  os.getenv('ENDPOINT')
CLIENT_ID = "python-publisher"
TOPIC = "topic/mqtt"                          
PATH_TO_CERT = "/etc/aws-iot/device-cert.pem"
PATH_TO_KEY =  "/etc/aws-iot/private-key.pem"
PATH_TO_ROOT = "/etc/aws-iot/AmazonRootCA1.pem"

# Message data
MESSAGE = {
    "deviceId": CLIENT_ID,
    "timestamp": int(time.time()),
    "temperature": 25.4,
    "humidity": 60.2,
    "status": "normal"
}

# Callback when connection is accidentally lost
def on_connection_interrupted(connection, error, **kwargs):
    print(f"Connection interrupted. Error: {error}")

# Callback when an interrupted connection is re-established
def on_connection_resumed(connection, return_code, session_present, **kwargs):
    print(f"Connection resumed. Return code: {return_code} Session present: {session_present}")

def main():
    # Spin up resources
    event_loop_group = io.EventLoopGroup(1)
    host_resolver = io.DefaultHostResolver(event_loop_group)
    client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

    # Create MQTT connection
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
        on_connection_resumed=on_connection_resumed
    )

    print(f"Connecting to {ENDPOINT} with client ID '{CLIENT_ID}'...")
    
    # Make the connect() call
    connect_future = mqtt_connection.connect()
    connect_future.result()  # Wait for connection to complete
    print("Connected!")

    try:
        # Publish messages in a loop
        message_count = 0
        while True:
            # Update message with current timestamp and increment counter
            MESSAGE["timestamp"] = int(time.time())
            MESSAGE["message_count"] = message_count
            
            # Convert message to JSON
            message_json = json.dumps(MESSAGE)
            
            print(f"Publishing message to topic '{TOPIC}': {message_json}")
            
            # Publish message
            mqtt_connection.publish(
                topic=TOPIC,
                payload=message_json,
                qos=mqtt.QoS.AT_LEAST_ONCE
            )
            
            message_count += 1
            time.sleep(5)  # Wait 5 seconds between messages
            
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Disconnecting...")
    finally:
        # Disconnect
        disconnect_future = mqtt_connection.disconnect()
        disconnect_future.result()
        print("Disconnected!")

if __name__ == "__main__":
    main()