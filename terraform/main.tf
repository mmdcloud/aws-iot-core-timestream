data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------------------
# Registering vault provider
# -----------------------------------------------------------------------------------------
data "vault_generic_secret" "timestream" {
  path = "secret/timestream"
}

resource "random_id" "id" {
  byte_length = 8
}

data "aws_iot_endpoint" "iot" {}

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
  map_public_ip_on_launch = false
  enable_nat_gateway      = true
  single_nat_gateway      = false
  one_nat_gateway_per_az  = true
  tags = {
    Project = "iot"
  }
}

# Security Group
module "lambda_security_group" {
  source        = "./modules/security-groups"
  name          = "lambda-security-group"
  vpc_id        = module.vpc.vpc_id
  ingress_rules = []
  egress_rules = [
    {
      description = "InfluxDB access"
      from_port   = 8086
      to_port     = 8086
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/16"]
    },
    {
      description = "HTTPS for AWS APIs"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  tags = { Name = "lambda-security-group" }
}

module "iot_instance_security_group" {
  source        = "./modules/security-groups"
  name          = "iot-instance-security-group"
  vpc_id        = module.vpc.vpc_id
  ingress_rules = []
  egress_rules = [
    {
      description = "MQTT to IoT Core"
      from_port   = 8883
      to_port     = 8883
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "HTTPS for SSM and AWS APIs"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
  tags = { Name = "iot-instance-security-group" }
}

module "influxdb_security_group" {
  source = "./modules/security-groups"
  name   = "influxdb-security-group"
  vpc_id = module.vpc.vpc_id
  ingress_rules = [
    {
      description     = "InfluxDB Traffic from VPC"
      from_port       = 8086
      to_port         = 8086
      protocol        = "tcp"
      security_groups = [module.lambda_security_group.id]
      cidr_blocks     = []
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
    Name = "influxdb-security-group"
  }
}

# -----------------------------------------------------------------------------------------
# VPC Flow Logs Configuration
# -----------------------------------------------------------------------------------------
module "vpc_flow_logs_role" {
  source             = "./modules/iam"
  role_name          = "vpc-flow-logs-role"
  role_description   = "IAM role for VPC Flow Logs"
  policy_name        = "vpc-flow-logs-policy"
  policy_description = "IAM policy for VPC Flow Logs"
  assume_role_policy = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "vpc-flow-logs.amazonaws.com"
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
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
              ],
              "Resource": [
                "${module.vpc_flow_logs.arn}",
                "${module.vpc_flow_logs.arn}:*"
              ],
              "Effect": "Allow"
          }            
        ]
    }
    EOF
}

module "vpc_flow_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/aws/vpc/flow-logs/iot"
  skip_destroy      = false
  retention_in_days = 90
}

resource "aws_flow_log" "iot_vpc_flow_log" {
  iam_role_arn    = module.vpc_flow_logs_role.arn
  log_destination = module.vpc_flow_log_group.arn
  traffic_type    = "ALL"
  vpc_id          = module.vpc.vpc_id
}

# -----------------------------------------------------------------------------------------
# IOT Device Simulated Instance
# -----------------------------------------------------------------------------------------
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
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
  role_name          = "instance-profile-iam-role"
  role_description   = "IAM role for instance profile"
  policy_name        = "instance-profile-iam-policy"
  policy_description = "IAM policy for instance profile"
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
                "kinesis:PutRecord",
                "kinesis:PutRecords"
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

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = module.instance_profile_iam_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

module "iot_instance" {
  source                      = "./modules/ec2"
  name                        = "iot-instance"
  ami_id                      = data.aws_ami.ubuntu.id
  instance_type               = "t3.small"
  associate_public_ip_address = false
  user_data = base64encode(templatefile("${path.module}/scripts/user_data.sh", {
    ENDPOINT    = data.aws_iot_endpoint.iot.endpoint_address
    DEVICE_CERT = aws_iot_certificate.cert.certificate_pem
    PRIVATE_KEY = aws_iot_certificate.cert.private_key
    MQTT_SCRIPT = replace(
      file("${path.module}/../src/mqtt_publish.py"),
      "$", "$$"
    )
  }))
  instance_profile = aws_iam_instance_profile.iam_instance_profile.name
  subnet_id        = module.vpc.private_subnets[0]
  security_groups  = [module.iot_instance_security_group.id]
}

# -----------------------------------------------------------------------------------------
# S3 Configuration
# -----------------------------------------------------------------------------------------
module "destination_bucket" {
  source      = "./modules/s3"
  bucket_name = "destination-bucket-${random_id.id.hex}"
  objects     = []
  bucket_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::destination-bucket-${random_id.id.hex}",
          "arn:aws:s3:::destination-bucket-${random_id.id.hex}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["https://*.amazonaws.com"] # scoped
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = false # protect your IoT data
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
    },
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = true
}

module "transform_function_code" {
  source      = "./modules/s3"
  bucket_name = "transform-function-code-bucket-${random_id.id.hex}"
  objects = [
    {
      key    = "transform.zip"
      source = "./files/transform.zip"
    }
  ]
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    },
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT"]
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
resource "aws_kms_key" "iot_kms" {
  description             = "KMS key for IoT pipeline encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = {
    Project = "iot"
  }
}

resource "aws_kms_alias" "iot_kms" {
  name          = "alias/iot-pipeline-key"
  target_key_id = aws_kms_key.iot_kms.key_id
}

module "kinesis_stream" {
  source           = "./modules/kinesis"
  name             = "kinesis-stream"
  retention_period = 48
  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
    "IncomingRecords",
    "IteratorAgeMilliseconds"
  ]
  stream_mode     = "ON_DEMAND"
  encryption_type = "KMS"                      # add
  kms_key_id      = aws_kms_key.iot_kms.key_id # add
}

# -----------------------------------------------------------------------------------------
# Lambda Configuration
# -----------------------------------------------------------------------------------------
module "transform_function_logs" {
  source = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name              = "/aws/lambda/transform-function"
  skip_destroy = false
  retention_in_days = 30
}

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
                  "logs:CreateLogStream",
                  "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/transform-function:*",
                "Effect": "Allow"
            },
            {
                "Action": [
                  "kinesis:GetRecords",
                  "kinesis:GetShardIterator",
                  "kinesis:DescribeStream",
                  "kinesis:DescribeStreamSummary",
                  "kinesis:ListShards",
                  "kinesis:ListStreams"
                ],
                "Resource": "${module.kinesis_stream.arn}",
                "Effect": "Allow"
            },
            {
                "Action": [
                  "kms:Decrypt",
                  "kms:GenerateDataKey"
                ],
                "Resource": "${aws_kms_key.iot_kms.arn}",
                "Effect": "Allow"
            },
            {
                "Action": [
                  "timestream:WriteRecords",
                  "timestream:DescribeEndpoints"
                ],
                "Resource": "arn:aws:timestream:${var.region}:*:database/*/table/*",
                "Effect": "Allow"
            },
            {
                "Action": [
                   "timestream:DescribeEndpoints"
                ],
                "Resource": "*",
                "Effect": "Allow"
            },
            {
             "Action": [
                "sqs:SendMessage"
              ],
              "Resource": "${module.transform_lambda_dlq.arn}",
              "Effect": "Allow"
            },
            {
                "Action": [
                  "ec2:CreateNetworkInterface",
                  "ec2:DescribeNetworkInterfaces",
                  "ec2:DeleteNetworkInterface"
                ],
                "Resource": "*",
                "Effect": "Allow"
            },
        ]
    }
    EOF
}

module "transform_function" {
  source        = "./modules/lambda"
  function_name = "transform-function"
  role_arn      = module.lambda_function_iam_role.arn
  permissions   = []
  env_variables = {
    TIMESTREAM_DATABASE = "iot-influxdb"
    TIMESTREAM_TABLE    = "iot-data"
    INFLUXDB_URL      = module.influxdb.endpoint
    INFLUXDB_TOKEN    = tostring(data.vault_generic_secret.timestream.data["token"])
    INFLUXDB_ORG      = "iot-organization"
    INFLUXDB_BUCKET   = "iot-data"
    FAILURE_THRESHOLD = "0.5"
  }
  handler                 = "transform.lambda_handler"
  runtime                 = "python3.12"
  s3_bucket               = module.transform_function_code.bucket
  s3_key                  = "transform.zip"
  layers                  = []
  vpc_subnet_ids         = module.vpc.private_subnets
  code_signing_config_arn = ""

  depends_on = [module.transform_function_code]
}

resource "aws_lambda_event_source_mapping" "kinesis_mapping" {
  event_source_arn                   = module.kinesis_stream.arn
  function_name                      = module.transform_function.arn
  starting_position                  = "LATEST"
  batch_size                         = 100
  maximum_batching_window_in_seconds = 5
  parallelization_factor             = 1
  maximum_retry_attempts             = 3
  maximum_record_age_in_seconds      = 604800
  bisect_batch_on_function_error     = true
  destination_config {
    on_failure {
      destination_arn = module.transform_lambda_dlq.arn
    }
  }
  enabled    = true
  depends_on = [module.transform_function]
}

# -----------------------------------------------------------------------------------------
# Lambda Configuration
# -----------------------------------------------------------------------------------------
module "transform_lambda_dlq" {
  source                     = "./modules/sqs"
  queue_name                 = "transform-lambda-dlq"
  delay_seconds              = 0
  maxReceiveCount            = 3
  max_message_size           = 262144
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 180
  receive_wait_time_seconds  = 20
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = module.transform_lambda_dlq.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = module.transform_function.arn
          }
        }
      }
    ]
  })
  tags = {
    Project = "iot"
  }
}

# -----------------------------------------------------------------------------------------
# IOT Core Configuration
# -----------------------------------------------------------------------------------------
resource "aws_iot_thing" "thing" {
  name = "thing"
}

resource "aws_iot_policy" "pubsub" {
  name = "DeviceScopedPolicy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iot:Connect"
        Resource = "arn:aws:iot:${var.region}:${data.aws_caller_identity.current.account_id}:client/${aws_iot_thing.thing.name}"
      },
      {
        Effect   = "Allow"
        Action   = ["iot:Publish", "iot:Receive"]
        Resource = "arn:aws:iot:${var.region}:${data.aws_caller_identity.current.account_id}:topic/topic/mqtt/${aws_iot_thing.thing.name}/*"
      },
      {
        Effect   = "Allow"
        Action   = "iot:Subscribe"
        Resource = "arn:aws:iot:${var.region}:${data.aws_caller_identity.current.account_id}:topicfilter/topic/mqtt/${aws_iot_thing.thing.name}/*"
      }
    ]
  })
}

resource "aws_iot_certificate" "cert" {
  active = true
  # AWS auto-generates the cert/key — retrieve via outputs
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
            },
            {
                "Action": [
                  "kms:GenerateDataKey",
                  "kms:Decrypt"
                ],
                "Resource": "${aws_kms_key.iot_kms.arn}",
                "Effect": "Allow"
            }
        ]
    }
    EOF
}

module "iot_errors_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/aws/iot/rule/iot_to_kinesis_rule/errors"
  retention_in_days = 90
  skip_destroy      = false
}

module "iot_error_iam_role" {
  source             = "./modules/iam"
  role_name          = "iot-error-iam-role"
  role_description   = "IAM role for IoT error logging"
  policy_name        = "iot-error-iam-policy"
  policy_description = "IAM policy for IoT error logging"
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
                  "logs:CreateLogStream",
                  "logs:DescribeLogStreams",
                  "logs:PutLogEvents"
                ],
                "Resource": [
                  "${module.iot_errors_log_group.arn}",
                  "${module.iot_errors_log_group.arn}:*"
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
  error_action {
    cloudwatch_logs {
      log_group_name = module.iot_errors_log_group.name
      role_arn       = module.iot_error_iam_role.arn
    }
  }
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

  schedule = "cron(0 1 * * ? *)"
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
# Timestream Configuration (InfluxDB)
# -----------------------------------------------------------------------------------------
module "influxdb" {
  source                 = "./modules/timestream"
  db_instance_type       = "db.influx.medium"
  allocated_storage      = "20"
  timestream_db_name     = "iot-influxdb"
  port                   = 8086
  timestream_db_username = tostring(data.vault_generic_secret.timestream.data["username"])
  timestream_db_password = tostring(data.vault_generic_secret.timestream.data["password"])
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

# -----------------------------------------------------------------------------------------
# Cloudwath Alarm Configuration
# -----------------------------------------------------------------------------------------
module "alarm_notifications" {
  source     = "./modules/sns"
  topic_name = "iot-cloudwatch-alarm-notifications"
  subscriptions = [
    {
      protocol = "email"
      endpoint = "madmaxcloudonline@gmail.com"
    }
  ]
}

# -----------------------------------------------------------------------------------------
# CloudWatch Alarms for Monitoring
# -----------------------------------------------------------------------------------------
module "lambda_errors" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "kinesis-to-timestream-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "Alert when Lambda function has more than 10 errors in 5 minutes"
  treat_missing_data  = "notBreaching"
  ok_actions          = [module.alarm_notifications.topic_arn]
  alarm_actions       = [module.alarm_notifications.topic_arn]
  dimensions = {
    FunctionName = module.transform_function.function_name
  }
}

module "lambda_throttles" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "kinesis-to-timestream-lambda-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Alert when Lambda function is throttled"
  treat_missing_data  = "notBreaching"
  ok_actions          = [module.alarm_notifications.topic_arn]
  alarm_actions       = [module.alarm_notifications.topic_arn]
  dimensions = {
    FunctionName = module.transform_function.function_name
  }
}

module "dlq_messages" {
  source              = "./modules/cloudwatch/cloudwatch-alarm"
  alarm_name          = "kinesis-to-timestream-dlq-messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = "300"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "Alert when messages appear in DLQ"
  treat_missing_data  = "notBreaching"
  ok_actions          = [module.alarm_notifications.topic_arn]
  alarm_actions       = [module.alarm_notifications.topic_arn]
  dimensions = {
    QueueName = module.transform_lambda_dlq.name
  }
}
