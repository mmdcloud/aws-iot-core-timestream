resource "aws_timestreaminfluxdb_db_instance" "name" {
  publicly_accessible    = var.publicly_accessible
  db_instance_type       = var.db_instance_type
  allocated_storage      = var.allocated_storage
  name                   = var.timestream_db_name
  username               = var.timestream_db_username
  password               = var.timestream_db_password
  vpc_security_group_ids = var.vpc_security_group_ids
  vpc_subnet_ids         = var.vpc_subnet_ids
  bucket                 = var.bucket
  organization           = var.organization
  port = var.port
  tags                   = var.tags
}
