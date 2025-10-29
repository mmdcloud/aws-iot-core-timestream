variable "region" {
  type    = string
  default = "us-east-1"
}

variable "glue_database_name" {
  type    = string
  default = "iot-glue-database"
}

variable "glue_table_name" {
  type    = string
  default = "iot-glue-table"
}

variable "glue_crawler_name" {
  type    = string
  default = "iot-glue-crawler"
}

variable "public_subnets" {
  type        = list(string)
  description = "Public Subnet CIDR values"
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnets" {
  type        = list(string)
  description = "Private Subnet CIDR values"
  default     = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
}

variable "azs" {
  type        = list(string)
  description = "Availability Zones"
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}