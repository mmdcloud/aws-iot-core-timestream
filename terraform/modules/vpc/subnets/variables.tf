variable "map_public_ip_on_launch" {}
variable "name" {}
variable "subnets" {
  type = list(object({
    subnet        = string
    az = string
  }))
}
variable "vpc_id" {}
