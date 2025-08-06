# Subnets
resource "aws_subnet" "subnet" {
  count                   = length(var.subnets)
  vpc_id                  = var.vpc_id
  map_public_ip_on_launch = var.map_public_ip_on_launch 
  cidr_block              = element(var.subnets[*].subnet, count.index)
  availability_zone       = element(var.subnets[*].az, count.index)
  tags = {
    Name = "${var.name} ${count.index + 1}"
  }
}