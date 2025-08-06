variable "vpc_id" {}
variable "name" {}
variable "ingress" {
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    self        = string
    cidr_blocks = list(string)
    description = string
    security_groups = set(string)
  }))
}
variable "egress" {
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
}
