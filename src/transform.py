import json
import base64
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
timestream_write = boto3.client('timestream-write')

# Environment variables
TIMESTREAM_DATABASE = os.environ.get('TIMESTREAM_DATABASE', 'iot-timestream-db')
TIMESTREAM_TABLE = os.environ.get('TIMESTREAM_TABLE', 'iot-data')
BATCH_SIZE = int(os.environ.get('BATCH_SIZE', '100'))

class TimestreamWriter:
    """Handles writing records to AWS Timestream"""
    
    def __init__(self, database_name: str, table_name: str):
        self.database_name = database_name
        self.table_name = table_name
        self.client = timestream_write
        
    def write_records(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Write records to Timestream in batches
        
        Args:
            records: List of record dictionaries
            
        Returns:
            Dictionary with success and failure counts
        """
        if not records:
            logger.info("No records to write")
            return {"success": 0, "failed": 0}
        
        success_count = 0
        failed_count = 0
        rejected_records = []
        
        # Process records in batches (Timestream has 100 record limit per request)
        for i in range(0, len(records), BATCH_SIZE):
            batch = records[i:i + BATCH_SIZE]
            
            try:
                response = self.client.write_records(
                    DatabaseName=self.database_name,
                    TableName=self.table_name,
                    Records=batch
                )
                success_count += len(batch)
                logger.info(f"Successfully wrote {len(batch)} records to Timestream")
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                error_message = e.response['Error']['Message']
                
                if error_code == 'RejectedRecordsException':
                    # Handle partial failures
                    rejected = e.response.get('RejectedRecords', [])
                    rejected_records.extend(rejected)
                    success_count += len(batch) - len(rejected)
                    failed_count += len(rejected)
                    
                    logger.warning(
                        f"Batch had {len(rejected)} rejected records. "
                        f"Reason: {rejected[0].get('Reason') if rejected else 'Unknown'}"
                    )
                else:
                    # Complete batch failure
                    failed_count += len(batch)
                    logger.error(
                        f"Failed to write batch to Timestream. "
                        f"Error: {error_code} - {error_message}"
                    )
                    
            except Exception as e:
                failed_count += len(batch)
                logger.error(f"Unexpected error writing to Timestream: {str(e)}")
        
        # Log rejected records for debugging
        if rejected_records:
            for record in rejected_records[:5]:  # Log first 5 only
                logger.error(f"Rejected record: {record}")
        
        return {
            "success": success_count,
            "failed": failed_count,
            "rejected_records": rejected_records
        }


class KinesisRecordProcessor:
    """Processes Kinesis records and transforms them for Timestream"""
    
    @staticmethod
    def decode_record(kinesis_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Decode a Kinesis record
        
        Args:
            kinesis_record: Raw Kinesis record
            
        Returns:
            Decoded data as dictionary or None if decoding fails
        """
        try:
            # Decode base64 data
            payload = base64.b64decode(kinesis_record['data']).decode('utf-8')
            data = json.loads(payload)
            return data
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as e:
            logger.error(f"Failed to decode Kinesis record: {str(e)}")
            return None
    
    @staticmethod
    def transform_to_timestream_record(
        data: Dict[str, Any],
        event_time: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Transform IoT data to Timestream record format
        
        Expected input format:
        {
            "deviceId": "device-001",
            "timestamp": "2024-01-12T10:30:00Z",  # Optional
            "temperature": 25.5,
            "humidity": 60.2,
            "pressure": 1013.25,
            "location": "warehouse-a"
        }
        
        Args:
            data: Decoded IoT data
            event_time: Override timestamp (ISO format or epoch milliseconds)
            
        Returns:
            Timestream record format or None if transformation fails
        """
        try:
            # Extract dimensions (metadata about the record)
            device_id = data.get('deviceId', data.get('device_id', 'unknown'))
            location = data.get('location', 'unknown')
            
            dimensions = [
                {'Name': 'deviceId', 'Value': str(device_id)},
                {'Name': 'location', 'Value': str(location)}
            ]
            
            # Add any custom dimensions from the data
            custom_dimensions = data.get('dimensions', {})
            for key, value in custom_dimensions.items():
                dimensions.append({'Name': str(key), 'Value': str(value)})
            
            # Determine timestamp
            if event_time:
                time_str = event_time
            elif 'timestamp' in data:
                time_str = data['timestamp']
            else:
                # Use current time if no timestamp provided
                time_str = str(int(datetime.now().timestamp() * 1000))
            
            # Convert ISO format to epoch milliseconds if needed
            if isinstance(time_str, str) and 'T' in time_str:
                dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                time_str = str(int(dt.timestamp() * 1000))
            
            # Extract measures (actual metric values)
            # These are the fields we want to store as time-series data
            excluded_fields = {
                'deviceId', 'device_id', 'timestamp', 'location', 
                'dimensions', 'eventTime', 'event_time'
            }
            
            measures = []
            for key, value in data.items():
                if key not in excluded_fields and value is not None:
                    # Determine measure value type
                    if isinstance(value, bool):
                        measure_value_type = 'BOOLEAN'
                        measure_value = str(value).lower()
                    elif isinstance(value, int):
                        measure_value_type = 'BIGINT'
                        measure_value = str(value)
                    elif isinstance(value, float):
                        measure_value_type = 'DOUBLE'
                        measure_value = str(value)
                    else:
                        measure_value_type = 'VARCHAR'
                        measure_value = str(value)
                    
                    measures.append({
                        'Name': key,
                        'Value': measure_value,
                        'Type': measure_value_type
                    })
            
            if not measures:
                logger.warning(f"No measures found in data: {data}")
                return None
            
            # Create Timestream record with multi-measure format
            record = {
                'Dimensions': dimensions,
                'MeasureName': 'iot_metrics',
                'MeasureValueType': 'MULTI',
                'MeasureValues': measures,
                'Time': time_str,
                'TimeUnit': 'MILLISECONDS'
            }
            
            return record
            
        except Exception as e:
            logger.error(f"Failed to transform record to Timestream format: {str(e)}")
            logger.error(f"Problematic data: {data}")
            return None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing Kinesis records and writing to Timestream
    
    Args:
        event: Kinesis event containing records
        context: Lambda context
        
    Returns:
        Response with processing statistics
    """
    logger.info(f"Processing {len(event['Records'])} records from Kinesis")
    
    processor = KinesisRecordProcessor()
    writer = TimestreamWriter(TIMESTREAM_DATABASE, TIMESTREAM_TABLE)
    
    timestream_records = []
    decode_failures = 0
    transform_failures = 0
    
    # Process each Kinesis record
    for record in event['Records']:
        try:
            kinesis_data = record['kinesis']
            
            # Decode the record
            decoded_data = processor.decode_record(kinesis_data)
            if decoded_data is None:
                decode_failures += 1
                continue
            
            # Extract event time from Kinesis metadata
            event_timestamp = record.get('kinesis', {}).get('approximateArrivalTimestamp')
            if event_timestamp:
                # Convert to milliseconds
                event_time = str(int(event_timestamp * 1000))
            else:
                event_time = None
            
            # Transform to Timestream format
            timestream_record = processor.transform_to_timestream_record(
                decoded_data,
                event_time
            )
            
            if timestream_record:
                timestream_records.append(timestream_record)
            else:
                transform_failures += 1
                
        except Exception as e:
            logger.error(f"Error processing record: {str(e)}")
            transform_failures += 1
    
    # Write records to Timestream
    write_result = writer.write_records(timestream_records)
    
    # Prepare response
    response = {
        'statusCode': 200,
        'body': {
            'total_records': len(event['Records']),
            'decode_failures': decode_failures,
            'transform_failures': transform_failures,
            'timestream_success': write_result['success'],
            'timestream_failed': write_result['failed'],
            'processed_successfully': write_result['success']
        }
    }
    
    # Log summary
    logger.info(f"Processing complete: {json.dumps(response['body'])}")
    
    # If there were too many failures, raise an exception
    # This will cause Lambda to retry the batch
    failure_threshold = 0.5  # 50% failure rate
    total_processed = len(event['Records']) - decode_failures
    if total_processed > 0:
        failure_rate = (transform_failures + write_result['failed']) / total_processed
        if failure_rate > failure_threshold:
            error_msg = f"High failure rate: {failure_rate:.2%}"
            logger.error(error_msg)
            raise Exception(error_msg)
    
    return response


# For local testing
if __name__ == "__main__":
    # Sample test event
    test_event = {
        "Records": [
            {
                "kinesis": {
                    "data": base64.b64encode(json.dumps({
                        "deviceId": "device-001",
                        "timestamp": "2024-01-12T10:30:00Z",
                        "temperature": 25.5,
                        "humidity": 60.2,
                        "pressure": 1013.25,
                        "location": "warehouse-a"
                    }).encode()).decode(),
                    "approximateArrivalTimestamp": datetime.now().timestamp()
                },
                "eventID": "test-event-1",
                "eventSource": "aws:kinesis"
            }
        ]
    }
    
    # Mock context
    class Context:
        function_name = "test-function"
        memory_limit_in_mb = 128
        invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
        aws_request_id = "test-request-id"
    
    result = lambda_handler(test_event, Context())
    print(json.dumps(result, indent=2))