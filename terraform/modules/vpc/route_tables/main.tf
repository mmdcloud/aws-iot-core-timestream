# Route Table
resource "aws_route_table" "route_table" {
  vpc_id = var.vpc_id
  dynamic "route" {
    for_each = var.routes
    content {
      cidr_block = route.value["cidr_block"]
      gateway_id = route.value["gateway_id"]
    }
  }
  tags = {
    Name = var.name
  }
}

# Route Table - Subnet Association
resource "aws_route_table_association" "route_table_subnet_association" {
  count = length(var.subnets)
  subnet_id      = var.subnets[count.index].id
  route_table_id = aws_route_table.route_table.id
}
