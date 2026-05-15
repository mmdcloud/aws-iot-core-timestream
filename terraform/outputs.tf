output "device_ip" {
  description = "Private IP of the simulated IoT EC2 instance"
  value       = module.iot_instance.private_ip
}

output "iot_endpoint" {
  description = "AWS IoT Core endpoint for MQTT connections"
  value       = data.aws_iot_endpoint.iot.endpoint_address
}

output "iot_thing_name" {
  description = "IoT Thing name"
  value       = aws_iot_thing.thing.name
}

output "iot_certificate_arn" {
  description = "ARN of the IoT device certificate"
  value       = aws_iot_certificate.cert.arn
}

output "kinesis_stream_arn" {
  description = "ARN of the Kinesis data stream"
  value       = module.kinesis_stream.arn
}

output "influxdb_endpoint" {
  description = "Timestream for InfluxDB endpoint"
  value       = module.influxdb.endpoint
  sensitive   = true
}

output "transform_lambda_arn" {
  description = "ARN of the Kinesis-to-InfluxDB transform Lambda"
  value       = module.transform_function.arn
}

output "dlq_url" {
  description = "URL of the transform Lambda DLQ"
  value       = module.transform_lambda_dlq.url
}

output "destination_bucket" {
  description = "S3 bucket receiving IoT data"
  value       = module.destination_bucket.bucket
}

output "kms_key_arn" {
  description = "ARN of the IoT pipeline KMS key"
  value       = aws_kms_key.iot_kms.arn
}