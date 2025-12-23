resource "random_id" "id" {
  byte_length = 8
}

data "aws_iot_endpoint" "iot" {}

# -----------------------------------------------------------------------------------------
# Certificate Configuration
# -----------------------------------------------------------------------------------------
resource "tls_private_key" "device_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "device_cert" {
  private_key_pem       = tls_private_key.device_key.private_key_pem
  validity_period_hours = 8760
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]
  subject {
    common_name  = "iot-device"
    organization = "iot-org"
  }
}

# -----------------------------------------------------------------------------------------
# VPC Configuration
# -----------------------------------------------------------------------------------------
module "vpc" {
  source                  = "./modules/vpc"
  vpc_name                = "vpc"
  vpc_cidr                = "10.0.0.0/16"
  azs                     = var.azs
  public_subnets          = var.public_subnets
  private_subnets         = var.private_subnets
  enable_dns_hostnames    = true
  enable_dns_support      = true
  create_igw              = true
  map_public_ip_on_launch = true
  enable_nat_gateway      = false
  single_nat_gateway      = false
  one_nat_gateway_per_az  = false
  tags = {
    Project = "iot"
  }
}

# Security Group
module "iot_instance_security_group" {
  source = "./modules/security-groups"
  name   = "iot-instance-security-group"
  vpc_id = module.vpc.vpc_id
  ingress_rules = [
    {
      description = "HTTP Traffic"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      security_groups = []
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "SSH Traffic"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      security_groups = []
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  egress_rules = [
    {
      description = "Allow all outbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  tags = {
    Name = "security-group"
  }
}

module "influxdb_security_group" {
  source = "./modules/security-groups"
  name   = "influxdb-security-group"
  vpc_id = module.vpc.vpc_id
  ingress_rules = [
    {
      description = "InfluxDB Traffic"
      from_port   = 8086
      to_port     = 8086
      protocol    = "tcp"
      security_groups = []
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  egress_rules = [
    {
      description = "Allow all outbound traffic"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  tags = {
    Name = "security-group"
  }
}

# -----------------------------------------------------------------------------------------
# IOT Device Simulated Instance
# -----------------------------------------------------------------------------------------
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# EC2 IAM Instance Profile
module "instance_profile_iam_role" {
  source             = "./modules/iam"
  role_name          = "transform-function-iam-role"
  role_description   = "IAM role for transform lambda function"
  policy_name        = "transform-function-iam-policy"
  policy_description = "IAM policy for transform lambda function"
  assume_role_policy = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "ec2.amazonaws.com"
                },
                "Effect": "Allow",
                "Sid": ""
            }
        ]
    }
    EOF
  policy             = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                  "kinesis:*"
                ],
                "Resource": "${module.kinesis_stream.arn}",
                "Effect": "Allow"
            }
        ]
    }
    EOF
}

resource "aws_iam_instance_profile" "iam_instance_profile" {
  name = "iam-instance-profile"
  role = module.instance_profile_iam_role.name
}

module "iot_instance" {
  source                      = "./modules/ec2"
  name                        = "iot-instance"
  ami_id                      = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  key_name                    = "madmaxkeypair"
  associate_public_ip_address = true
  user_data = base64encode(templatefile("${path.module}/scripts/user_data.sh", {
    ENDPOINT    = "${data.aws_iot_endpoint.iot.endpoint_address}"
    DEVICE_CERT = "${aws_iot_certificate.cert.certificate_pem}"
    PRIVATE_KEY = "${tls_private_key.device_key.private_key_pem}"
  }))
  instance_profile = aws_iam_instance_profile.iam_instance_profile.name
  subnet_id        = module.vpc.public_subnets[0]
  security_groups  = [module.iot_instance_security_group.id]
}

# -----------------------------------------------------------------------------------------
# S3 Configuration
# -----------------------------------------------------------------------------------------
module "destination_bucket" {
  source        = "./modules/s3"
  bucket_name   = "destination-bucket-${random_id.id.hex}"
  objects       = []
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = true
}

module "athena_temp_results_bucket" {
  source        = "./modules/s3"
  bucket_name   = "athena-temp-results-bucket-${random_id.id.hex}"
  objects       = []
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = true
}

module "transform_function_code" {
  source        = "./modules/s3"
  bucket_name   = "transform-function-code-bucket-${random_id.id.hex}"
  objects       = []
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = true
}

# -----------------------------------------------------------------------------------------
# Kinesis module
# -----------------------------------------------------------------------------------------
module "kinesis_stream" {
  source           = "./modules/kinesis"
  name             = "kinesis-stream"
  retention_period = 48
  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
  ]
  stream_mode = "ON_DEMAND"
}

# -----------------------------------------------------------------------------------------
# Lambda Configuration
# -----------------------------------------------------------------------------------------
module "lambda_function_iam_role" {
  source             = "./modules/iam"
  role_name          = "transform-function-iam-role"
  role_description   = "IAM role for transform lambda function"
  policy_name        = "transform-function-iam-policy"
  policy_description = "IAM policy for transform lambda function"
  assume_role_policy = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "lambda.amazonaws.com"
                },
                "Effect": "Allow",
                "Sid": ""
            }
        ]
    }
    EOF
  policy             = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                  "logs:CreateLogGroup",
                  "logs:CreateLogStream",
                  "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:*",
                "Effect": "Allow"
            }
        ]
    }
    EOF
}

module "transform_function" {
  source                  = "./modules/lambda"
  function_name           = "transform-function"
  role_arn                = module.lambda_function_iam_role.arn
  permissions             = []
  env_variables           = {}
  handler                 = "lambda.lambda_handler"
  runtime                 = "python3.12"
  s3_bucket               = module.transform_function_code.bucket
  s3_key                  = "lambda.zip"
  layers                  = []
  code_signing_config_arn = ""
}

# -----------------------------------------------------------------------------------------
# Kinesis Data Firehose
# -----------------------------------------------------------------------------------------
# module "firehose_role" {
#   source             = "./modules/iam"
#   role_name          = "firehose-delivery-role"
#   role_description   = "IAM role for Kinesis Data Firehose"
#   policy_name        = "firehose-delivery-policy"
#   policy_description = "IAM policy for Kinesis Data Firehose"
#   assume_role_policy = <<EOF
#     {
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Action": "sts:AssumeRole",
#                 "Principal": {
#                   "Service": "firehose.amazonaws.com"
#                 },
#                 "Effect": "Allow",
#                 "Sid": ""
#             }
#         ]
#     }
#     EOF
#   policy             = <<EOF
#     {
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Action": [
#                   "s3:PutObject",
#                   "s3:PutObjectAcl",
#                   "s3:ListBucket"
#                 ],
#                 "Resource": [
#                   "${module.destination_bucket.arn}",
#                   "${module.destination_bucket.arn}/*"
#                 ],
#                 "Effect": "Allow"
#             },
#             {
#                 "Action": [
#                   "kinesis:DescribeStream",
#                   "kinesis:GetShardIterator",
#                   "kinesis:GetRecords"
#                 ],
#                 "Resource": [
#                   "${module.kinesis_stream.arn}"
#                 ],
#                 "Effect": "Allow"
#             }
#         ]
#     }
#     EOF
# }

# resource "aws_kinesis_firehose_delivery_stream" "firehose_to_s3" {
#   name        = "firehose-stream"
#   destination = "extended_s3"

#   kinesis_source_configuration {
#     kinesis_stream_arn = module.kinesis_stream.arn    
#     role_arn           = module.firehose_role.arn
#   }

#   extended_s3_configuration {
#     role_arn           = module.firehose_role.arn
#     bucket_arn         = module.destination_bucket.arn
#     compression_format = "UNCOMPRESSED"
#   }
# }

# -----------------------------------------------------------------------------------------
# IOT Core Configuration
# -----------------------------------------------------------------------------------------
resource "aws_iot_thing" "thing" {
  name = "thing"
}

resource "aws_iot_policy" "pubsub" {
  name = "PubSubToAnyTopic"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "iot:Connect",
          "iot:Publish",
          "iot:Receive",
          "iot:Subscribe"
        ],
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iot_certificate" "cert" {
  certificate_pem = tls_self_signed_cert.device_cert.cert_pem
  active          = true
}

resource "aws_iot_thing_principal_attachment" "attach" {
  thing     = aws_iot_thing.thing.name
  principal = aws_iot_certificate.cert.arn
}

resource "aws_iot_policy_attachment" "policy_attach" {
  policy = aws_iot_policy.pubsub.name
  target = aws_iot_certificate.cert.arn
}

# IAM Role that AWS IoT will assume to write to Kinesis
module "iot_kinesis_role" {
  source             = "./modules/iam"
  role_name          = "iot-kinesis-role"
  role_description   = "IAM role for Kinesis Data Firehose"
  policy_name        = "iot-kinesis-policy"
  policy_description = "IAM policy for Kinesis Data Firehose"
  assume_role_policy = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "iot.amazonaws.com"
                },
                "Effect": "Allow",
                "Sid": ""
            }
        ]
    }
    EOF
  policy             = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                  "kinesis:PutRecord",
                  "kinesis:PutRecords"
                ],
                "Resource": [
                  "${module.kinesis_stream.arn}"
                ],
                "Effect": "Allow"
            }
        ]
    }
    EOF
}

# AWS IoT Topic Rule that sends data from a topic to Kinesis Data Stream
resource "aws_iot_topic_rule" "kinesis_rule" {
  name        = "iot_to_kinesis_rule"
  description = "Rule to send IoT data to Kinesis Data Stream"
  enabled     = true
  sql         = "SELECT * FROM 'topic/mqtt'"
  sql_version = "2016-03-23"

  kinesis {
    stream_name   = module.kinesis_stream.name
    partition_key = "deviceId"
    role_arn      = module.iot_kinesis_role.arn
  }
}

# -----------------------------------------------------------------------------------------
# Glue Configuration
# -----------------------------------------------------------------------------------------
resource "aws_iam_role" "glue_crawler_role" {
  name = "glue-crawler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "glue.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "glue_service_policy" {
  role       = aws_iam_role.glue_crawler_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "s3_access_policy" {
  role = aws_iam_role.glue_crawler_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Resource = [
          "${module.destination_bucket.arn}",
          "${module.destination_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_glue_catalog_database" "database" {
  name        = var.glue_database_name
  description = var.glue_database_name
}

resource "aws_glue_catalog_table" "table" {
  name          = var.glue_table_name
  database_name = aws_glue_catalog_database.database.name
}

resource "aws_glue_crawler" "crawler" {
  database_name = aws_glue_catalog_database.database.name
  name          = var.glue_crawler_name
  role          = aws_iam_role.glue_crawler_role.arn

  s3_target {
    path = "s3://${module.destination_bucket.bucket}"
  }
}

# -----------------------------------------------------------------------------------------
# Athena Configuration
# -----------------------------------------------------------------------------------------
resource "aws_athena_workgroup" "workgroup" {
  name        = "workgroup"
  description = "Athena workgroup for querying IoT data"
  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${module.athena_temp_results_bucket.bucket}/"
    }
  }
}

# -----------------------------------------------------------------------------------------
# Timestream Configuration
# -----------------------------------------------------------------------------------------
module "timestream" {
  source                 = "./modules/timestream"
  db_instance_type       = "t3.medium"
  allocated_storage      = "20"
  timestream_db_name     = "iot_timestream_db"
  port                   = 8086
  timestream_db_username = "timestream_user"
  timestream_db_password = "StrongPassword123!"
  vpc_security_group_ids = [module.influxdb_security_group.id]
  vpc_subnet_ids         = module.vpc.private_subnets
  bucket                 = module.destination_bucket.bucket
  organization           = "iot-organization"
  publicly_accessible    = false
  tags = {
    Project     = "iot"
    Environment = "production"
  }
}
