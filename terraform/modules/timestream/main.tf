resource "aws_timestreaminfluxdb_db_instance" "name" {
  
}

resource "aws_timestreamwrite_database" "main" {
  database_name = var.timestream_db_name
  kms_key_id    = aws_kms_key.timestream_key.arn

  tags = merge(
    {
      "Environment" = "production"
      "Name"        = var.timestream_db_name
    },
    var.tags
  )
}

resource "aws_kms_key" "timestream_key" {
  description         = "KMS key for Timestream encryption"
  enable_key_rotation = true

  tags = merge(
    {
      "Environment" = "production"
      "Name"        = "timestream"
    },
    var.tags
  )
}

resource "aws_timestream" "name" {

}

resource "aws_timestreamwrite_table" "main" {
  database_name = aws_timestreamwrite_database.main.database_name
  table_name    = "${var.timestream_db_name}_table"

  retention_properties {
    memory_store_retention_period_in_hours  = 48
    magnetic_store_retention_period_in_days = 365
  }

  tags = merge(
    {
      "Environment" = "production"
      "Name"        = "${var.timestream_db_name}_table"
    },
    var.tags
  )
}