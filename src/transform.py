"""
Lambda: Kinesis → InfluxDB (Timestream for InfluxDB)

FIX 3: Replaced boto3 timestream-write (Amazon Timestream API) with influxdb-client
(InfluxDB v2 HTTP API). Timestream for InfluxDB uses the standard InfluxDB wire
protocol, not the AWS Timestream API — the two are completely different services.

Lambda zip must include influxdb-client:
    pip install influxdb-client -t ./package
    cp transform.py ./package/
    cd package && zip -r ../transform.zip .
"""
import json
import base64
import logging
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from influxdb_client.client.exceptions import InfluxDBError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration (set via Lambda env vars in Terraform)
# ---------------------------------------------------------------------------
INFLUXDB_URL      = os.environ['INFLUXDB_URL']         # e.g. https://<id>.timestream-influxdb.us-east-1.amazonaws.com:8086
INFLUXDB_TOKEN    = os.environ['INFLUXDB_TOKEN']        # operator/all-access token from Vault
INFLUXDB_ORG      = os.environ.get('INFLUXDB_ORG',      'iot-organization')
INFLUXDB_BUCKET   = os.environ.get('INFLUXDB_BUCKET',   'iot-data')
FAILURE_THRESHOLD = float(os.environ.get('FAILURE_THRESHOLD', '0.5'))

# Fields treated as tags (dimensions), never as fields/measures
DIMENSION_FIELDS = {'deviceId', 'device_id', 'location'}
EXCLUDED_FIELDS  = DIMENSION_FIELDS | {'timestamp', 'dimensions', 'eventTime', 'event_time'}

# Reuse a single client across invocations (warm Lambda container)
_client    = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
_write_api = _client.write_api(write_options=SYNCHRONOUS)


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def to_epoch_ns(value: Any) -> int:
    """
    Convert any reasonable timestamp to epoch nanoseconds (InfluxDB native unit).

    Accepts:
      - int/float in milliseconds  (13-digit epoch, > 1e12)
      - int/float in seconds       (10-digit epoch, < 1e12)
      - ISO-8601 string            ('2024-01-12T10:30:00Z')
    """
    if isinstance(value, (int, float)):
        if value > 1e12:
            return int(value) * 1_000_000          # ms → ns
        return int(value * 1_000_000_000)           # s  → ns

    if isinstance(value, str):
        if 'T' in value:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return int(dt.timestamp() * 1_000_000_000)
        try:
            return to_epoch_ns(float(value))
        except ValueError:
            pass

    logger.warning(f"Unrecognised timestamp format '{value}', using now()")
    return int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)


# ---------------------------------------------------------------------------
# Kinesis record processing
# ---------------------------------------------------------------------------

def decode_record(kinesis_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        raw = base64.b64decode(kinesis_record['data']).decode('utf-8')
        return json.loads(raw)
    except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as exc:
        logger.error(f"Decode failed: {exc}")
        return None


def to_influxdb_point(
    data: Dict[str, Any],
    arrival_ns: Optional[int] = None,
) -> Optional[Point]:
    """
    Convert a decoded IoT payload into an InfluxDB Point.

    Tags  → deviceId, location, and any extra keys under data['dimensions']
    Fields → every remaining numeric / string / bool value
    Time  → payload 'timestamp' > Kinesis arrival > now()
    """
    try:
        device_id = str(data.get('deviceId', data.get('device_id', 'unknown')))
        location  = str(data.get('location', 'unknown'))

        # Resolve timestamp
        if 'timestamp' in data:
            time_ns = to_epoch_ns(data['timestamp'])
        elif arrival_ns is not None:
            time_ns = arrival_ns
        else:
            time_ns = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

        point = (
            Point('iot_metrics')
            .tag('deviceId', device_id)
            .tag('location', location)
            .time(time_ns, WritePrecision.NANOSECONDS)
        )

        # Extra dimensions the sender may have nested under a 'dimensions' key
        for k, v in data.get('dimensions', {}).items():
            point = point.tag(str(k), str(v))

        # Fields — everything that isn't a tag/meta key
        has_field = False
        for key, value in data.items():
            if key in EXCLUDED_FIELDS or value is None:
                continue

            if isinstance(value, bool):
                point = point.field(key, value)
            elif isinstance(value, int):
                point = point.field(key, value)
            elif isinstance(value, float):
                point = point.field(key, value)
            elif isinstance(value, str):
                point = point.field(key, value)
            else:
                # Nested objects / arrays → serialise as string field
                point = point.field(key, json.dumps(value))

            has_field = True

        if not has_field:
            logger.warning(f"No fields found in record — skipping: {data}")
            return None

        return point

    except Exception as exc:
        logger.error(f"Transform failed: {exc} | data={data}", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    total = len(event['Records'])
    logger.info(f"Received {total} Kinesis records.")

    points: List[Point] = []
    decode_failures    = 0
    transform_failures = 0

    for record in event['Records']:
        kinesis_data = record.get('kinesis', {})

        # Kinesis arrival → nanoseconds
        arrival = kinesis_data.get('approximateArrivalTimestamp')
        arrival_ns = int(arrival * 1_000_000_000) if arrival else None

        decoded = decode_record(kinesis_data)
        if decoded is None:
            decode_failures += 1
            continue

        point = to_influxdb_point(decoded, arrival_ns)
        if point:
            points.append(point)
        else:
            transform_failures += 1

    # Batch write to InfluxDB
    write_failures = 0
    if points:
        try:
            _write_api.write(bucket=INFLUXDB_BUCKET, record=points)
            logger.info(f"Wrote {len(points)} points to InfluxDB bucket '{INFLUXDB_BUCKET}'.")
        except InfluxDBError as exc:
            logger.error(f"InfluxDB write error: {exc}", exc_info=True)
            write_failures = len(points)
        except Exception as exc:
            logger.error(f"Unexpected write error: {exc}", exc_info=True)
            write_failures = len(points)

    summary = {
        'total_records':     total,
        'decode_failures':   decode_failures,
        'transform_failures': transform_failures,
        'influxdb_success':  len(points) - write_failures,
        'influxdb_failed':   write_failures,
    }
    logger.info(f"Done: {json.dumps(summary)}")

    # Re-raise if failure rate exceeds threshold so Kinesis retries the batch
    processed = total - decode_failures
    if processed > 0:
        rate = (transform_failures + write_failures) / processed
        if rate > FAILURE_THRESHOLD:
            raise RuntimeError(
                f"Failure rate {rate:.1%} exceeds threshold {FAILURE_THRESHOLD:.1%}"
            )

    return {'statusCode': 200, 'body': summary}