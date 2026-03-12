"""
Lambda: Kinesis → AWS Timestream transform
Triggered by aws_lambda_event_source_mapping on the IoT Kinesis stream.
"""
import json
import base64
import logging
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration (set via Lambda env vars in Terraform)
# ---------------------------------------------------------------------------
TIMESTREAM_DATABASE = os.environ.get('TIMESTREAM_DATABASE', 'iot-influxdb')
TIMESTREAM_TABLE    = os.environ.get('TIMESTREAM_TABLE',    'iot-data')
BATCH_SIZE          = int(os.environ.get('BATCH_SIZE', '100'))
FAILURE_THRESHOLD   = float(os.environ.get('FAILURE_THRESHOLD', '0.5'))

# Fields that are dimensions or meta — never written as measures
DIMENSION_FIELDS = {'deviceId', 'device_id', 'location'}
EXCLUDED_FIELDS  = DIMENSION_FIELDS | {
    'timestamp', 'dimensions', 'eventTime', 'event_time'
}

timestream_write = boto3.client('timestream-write')


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def to_epoch_ms(value: Any) -> str:
    """
    Convert any reasonable timestamp representation to epoch milliseconds string.

    Accepts:
      - int/float already in milliseconds  (13-digit epoch, e.g. 1705052400000)
      - int/float in seconds               (10-digit epoch, e.g. 1705052400)
      - ISO-8601 string                    (e.g. '2024-01-12T10:30:00Z')
    """
    if isinstance(value, (int, float)):
        # Heuristic: ms values are > 1e12, seconds are < 1e12
        if value > 1e12:
            return str(int(value))
        else:
            return str(int(value * 1000))

    if isinstance(value, str):
        # ISO-8601
        if 'T' in value:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return str(int(dt.timestamp() * 1000))
        # Numeric string
        try:
            return to_epoch_ms(float(value))
        except ValueError:
            pass

    # Fallback: use current time
    logger.warning(f"Unrecognised timestamp format '{value}', using now()")
    return str(int(datetime.now(timezone.utc).timestamp() * 1000))


# ---------------------------------------------------------------------------
# Kinesis record processor
# ---------------------------------------------------------------------------

class KinesisRecordProcessor:

    @staticmethod
    def decode(kinesis_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            raw = base64.b64decode(kinesis_record['data']).decode('utf-8')
            return json.loads(raw)
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as exc:
            logger.error(f"Decode failed: {exc}")
            return None

    @staticmethod
    def to_timestream_record(
        data: Dict[str, Any],
        kinesis_arrival_ms: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Transform a decoded IoT payload into Timestream multi-measure record format.
        """
        try:
            device_id = str(data.get('deviceId', data.get('device_id', 'unknown')))
            location  = str(data.get('location', 'unknown'))

            dimensions = [
                {'Name': 'deviceId', 'Value': device_id},
                {'Name': 'location', 'Value': location},
            ]

            # Any extra dimensions the sender added under a 'dimensions' key
            for k, v in data.get('dimensions', {}).items():
                dimensions.append({'Name': str(k), 'Value': str(v)})

            # ----------------------------------------------------------------
            # Timestamp resolution — priority:
            #   1. Payload 'timestamp' field
            #   2. Kinesis approximateArrivalTimestamp
            #   3. now()
            # ----------------------------------------------------------------
            if 'timestamp' in data:
                time_str = to_epoch_ms(data['timestamp'])
            elif kinesis_arrival_ms:
                time_str = kinesis_arrival_ms
            else:
                time_str = str(int(datetime.now(timezone.utc).timestamp() * 1000))

            # ----------------------------------------------------------------
            # Build measures from all remaining numeric / string fields
            # ----------------------------------------------------------------
            measures: List[Dict[str, str]] = []
            for key, value in data.items():
                if key in EXCLUDED_FIELDS or value is None:
                    continue

                if isinstance(value, bool):
                    measures.append({'Name': key, 'Value': str(value).lower(), 'Type': 'BOOLEAN'})
                elif isinstance(value, int):
                    measures.append({'Name': key, 'Value': str(value), 'Type': 'BIGINT'})
                elif isinstance(value, float):
                    measures.append({'Name': key, 'Value': str(value), 'Type': 'DOUBLE'})
                elif isinstance(value, str):
                    measures.append({'Name': key, 'Value': value, 'Type': 'VARCHAR'})
                else:
                    # Nested objects / lists → serialise as VARCHAR
                    measures.append({'Name': key, 'Value': json.dumps(value), 'Type': 'VARCHAR'})

            if not measures:
                logger.warning(f"No measures found in record: {data}")
                return None

            return {
                'Dimensions':      dimensions,
                'MeasureName':     'iot_metrics',
                'MeasureValueType':'MULTI',
                'MeasureValues':   measures,
                'Time':            time_str,
                'TimeUnit':        'MILLISECONDS',
            }

        except Exception as exc:
            logger.error(f"Transform failed: {exc} | data={data}", exc_info=True)
            return None


# ---------------------------------------------------------------------------
# Timestream writer
# ---------------------------------------------------------------------------

class TimestreamWriter:

    def __init__(self, database: str, table: str):
        self.database = database
        self.table    = table

    def write(self, records: List[Dict[str, Any]]) -> Dict[str, int]:
        if not records:
            return {'success': 0, 'failed': 0}

        success = 0
        failed  = 0

        for i in range(0, len(records), BATCH_SIZE):
            batch = records[i : i + BATCH_SIZE]
            try:
                timestream_write.write_records(
                    DatabaseName=self.database,
                    TableName=self.table,
                    Records=batch,
                )
                success += len(batch)
                logger.info(f"Wrote {len(batch)} records to Timestream.")

            except ClientError as exc:
                code = exc.response['Error']['Code']
                if code == 'RejectedRecordsException':
                    rejected = exc.response.get('RejectedRecords', [])
                    failed  += len(rejected)
                    success += len(batch) - len(rejected)
                    for r in rejected[:5]:
                        logger.error(f"Rejected record: {r}")
                else:
                    failed += len(batch)
                    logger.error(f"Timestream write error [{code}]: {exc}", exc_info=True)

            except Exception as exc:
                failed += len(batch)
                logger.error(f"Unexpected Timestream error: {exc}", exc_info=True)

        return {'success': success, 'failed': failed}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    total = len(event['Records'])
    logger.info(f"Received {total} Kinesis records.")

    processor = KinesisRecordProcessor()
    writer    = TimestreamWriter(TIMESTREAM_DATABASE, TIMESTREAM_TABLE)

    timestream_records: List[Dict[str, Any]] = []
    decode_failures    = 0
    transform_failures = 0

    for record in event['Records']:
        kinesis_data = record.get('kinesis', {})

        # Kinesis arrival time → milliseconds string
        arrival = kinesis_data.get('approximateArrivalTimestamp')
        arrival_ms = str(int(arrival * 1000)) if arrival else None

        decoded = processor.decode(kinesis_data)
        if decoded is None:
            decode_failures += 1
            continue

        ts_record = processor.to_timestream_record(decoded, arrival_ms)
        if ts_record:
            timestream_records.append(ts_record)
        else:
            transform_failures += 1

    result = writer.write(timestream_records)

    summary = {
        'total_records':       total,
        'decode_failures':     decode_failures,
        'transform_failures':  transform_failures,
        'timestream_success':  result['success'],
        'timestream_failed':   result['failed'],
    }
    logger.info(f"Done: {json.dumps(summary)}")

    # Raise so Lambda retries the batch if failure rate is too high
    processed = total - decode_failures
    if processed > 0:
        rate = (transform_failures + result['failed']) / processed
        if rate > FAILURE_THRESHOLD:
            raise RuntimeError(f"Failure rate {rate:.1%} exceeds threshold {FAILURE_THRESHOLD:.1%}")

    return {'statusCode': 200, 'body': summary}