# Kinesis Stream
resource "aws_kinesis_stream" "stream" {
  name                = var.name
  retention_period    = var.retention_period
  shard_level_metrics = var.shard_level_metrics
  stream_mode_details {
    stream_mode = var.stream_mode
  }
  encryption_type = var.encryption_type
  kms_key_id = var.encryption_type == "KMS" ? var.kms_key_id : null
  tags = {
    Name = var.name
  }
}
