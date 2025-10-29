variable "aws_region" {
  description = "AWS region to deploy the resources"
  type        = string
}

variable "timestream_db_name" {
  description = "Name for the Timestream database"
  type        = string
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
