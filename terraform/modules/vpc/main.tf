module "vpc" {
  source                  = "terraform-aws-modules/vpc/aws"
  version                 = "~> 5.0"
  name                    = var.vpc_name
  cidr                    = var.vpc_cidr
  azs                     = var.azs
  public_subnets          = var.public_subnets
  private_subnets         = var.private_subnets
  enable_dns_hostnames    = var.enable_dns_hostnames
  enable_dns_support      = var.enable_dns_support
  create_igw              = var.create_igw
  map_public_ip_on_launch = var.map_public_ip_on_launch
  enable_nat_gateway      = var.enable_nat_gateway
  single_nat_gateway      = var.single_nat_gateway
  one_nat_gateway_per_az  = var.one_nat_gateway_per_az
  tags                    = var.tags
}