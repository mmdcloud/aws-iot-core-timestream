variable "name" {}
variable "ami_id" {}
variable "instance_type" {}
variable "key_name" {
    type = string
    default = null
}
variable "associate_public_ip_address" {}
variable "user_data" {}
variable "subnet_id" {}
variable "security_groups" {}
variable "instance_profile" {}