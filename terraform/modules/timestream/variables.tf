variable "db_instance_type" {
  type    = string
  default = ""
}

variable "allocated_storage" {
  type    = string
  default = ""
}

variable "timestream_db_name" {
  type    = string
  default = ""
}

variable "timestream_db_username" {
  type    = string
  default = ""
}

variable "timestream_db_password" {
  type    = string
  default = ""
}

variable "vpc_security_group_ids" {
  type    = list(string)
  default = []
}

variable "vpc_subnet_ids" {
  type    = list(string)
  default = []
}

variable "bucket" {
  type    = string
  default = ""
}

variable "organization" {
  type    = string
  default = ""
}

variable "port" {
  type    = number
  default = ""
}

variable "publicly_accessible" {
  type    = bool
  default = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
