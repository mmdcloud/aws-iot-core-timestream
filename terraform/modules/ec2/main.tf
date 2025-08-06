# EC2 Instance
resource "aws_instance" "instance" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  key_name                    = var.key_name
  associate_public_ip_address = var.associate_public_ip_address
  user_data                   = var.user_data
  subnet_id = var.subnet_id
  security_groups = var.security_groups
  iam_instance_profile = var.instance_profile
  tags = {
    Name = var.name
  }
}
