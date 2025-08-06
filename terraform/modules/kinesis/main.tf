# Kinesis Stream
resource "aws_kinesis_stream" "stream" {
  name                = var.name
  retention_period    = var.retention_period
  shard_level_metrics = var.shard_level_metrics
  stream_mode_details {
    stream_mode = var.stream_mode
  }
  tags = {
    Name = var.name
  }
}
