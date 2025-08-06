# Security Group Creation
resource "aws_security_group" "security_group" {  
  name   = var.name
  vpc_id = var.vpc_id
  dynamic "ingress" {
    for_each = var.ingress
    content {
      from_port   = ingress.value["from_port"]
      to_port     = ingress.value["to_port"]
      protocol    = ingress.value["protocol"]
      self        = ingress.value["self"]
      cidr_blocks = ingress.value["cidr_blocks"]
      description = ingress.value["description"]
      security_groups = ingress.value["security_groups"]
    }
  }
  dynamic "egress" {
    for_each = var.egress
    content {
      from_port   = egress.value["from_port"]
      to_port     = egress.value["to_port"]
      protocol    = egress.value["protocol"]
      cidr_blocks = egress.value["cidr_blocks"]
    }
  }
}