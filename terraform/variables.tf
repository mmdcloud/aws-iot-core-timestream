variable "region" {
  type = string
}

variable "glue_database_name" {
  type = string
}

variable "glue_table_name" {
  type = string
}

variable "glue_crawler_name" {
  type = string
}

variable "public_subnets" {
  type        = list(string)
  description = "Public Subnet CIDR values"
}

variable "private_subnets" {
  type        = list(string)
  description = "Private Subnet CIDR values"
}

variable "azs" {
  type        = list(string)
  description = "Availability Zones"
}