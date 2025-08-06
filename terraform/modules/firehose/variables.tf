variable "name" {}
variable "destination" {}

variable "kinesis_stream_arn" {}
variable "kinesis_stream_role_arn" {}

variable "opensearch_domain_arn" {}
variable "opensearch_role_arn" {}
variable "opensearch_index_name" {}

variable "backup_bucket_arn" {}
variable "s3_role_arn"{}
variable "s3_compression_format"{}

variable "processing_enabled" {}
variable "processing_type" {}
variable "processing_parameter_name" {}
variable "processing_parameter_value" {}