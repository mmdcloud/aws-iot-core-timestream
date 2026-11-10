# 🚀 IoT Real-Time Data Pipeline on AWS

[![Terraform](https://img.shields.io/badge/Terraform-1.0+-623CE4?logo=terraform)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-Cloud-FF9900?logo=amazon-aws)](https://aws.amazon.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A production-grade, fully automated IoT data ingestion and analytics pipeline built on AWS using Terraform. This infrastructure enables real-time streaming, transformation, and analysis of IoT device data at scale.

## 🏗️ Architecture Overview

```
IoT Devices (Simulated EC2)
    ↓
AWS IoT Core (MQTT)
    ↓
Kinesis Data Streams
    ↓
Lambda (Transformation)
    ↓
├─→ Amazon Timestream (Time-series DB)
└─→ S3 (Data Lake)
    ↓
AWS Glue Crawler
    ↓
AWS Glue Data Catalog
    ↓
Amazon Athena (SQL Analytics)
```

## ✨ Features

- **Fully Managed IoT Infrastructure**: Secure device connectivity via AWS IoT Core with certificate-based authentication
- **Real-Time Data Streaming**: High-throughput data ingestion using Kinesis Data Streams with on-demand scaling
- **Serverless Transformation**: Lambda-based data processing with configurable business logic
- **Time-Series Storage**: Amazon Timestream for efficient storage and querying of time-series IoT data
- **Data Lake Integration**: Automatic archival to S3 for historical analysis and compliance
- **Automated Data Cataloging**: AWS Glue crawlers for schema discovery and metadata management
- **SQL Analytics**: Ad-hoc querying via Amazon Athena with S3-backed storage
- **Infrastructure as Code**: 100% Terraform-managed infrastructure with modular design
- **Production-Ready Security**: VPC isolation, security groups, IAM least-privilege policies, and encrypted data transport

## 📸 Visual Pipeline Walkthrough

Here is the complete end-to-end IoT data pipeline in action:

### 1. Automated Infrastructure Provisioning (Terraform)
Execution of Terraform apply successfully deploying 92 AWS resources (VPC, IoT Core rules, Kinesis Data Streams, Lambda, and Timestream for InfluxDB) with output parameters.

![Terraform Apply Outputs](screenshots/Screenshot%20from%202026-11-10%2015-10-09.png)

---

### 2. S3 Storage Buckets
Automated provisioning of dedicated S3 buckets for IoT cold-storage data lake archival and Lambda deployment artifacts.

![AWS S3 Buckets](screenshots/Screenshot%20from%202026-11-10%2015-12-08.png)

---

### 3. Serverless Stream Transformer (AWS Lambda)
The Python 3.12 event-driven Lambda function (`transform-function`) attached to Kinesis Data Streams for data parsing, transformation, and batch loading.

![AWS Lambda Function](screenshots/Screenshot%20from%202026-11-10%2015-13-22.png)

---

### 4. Real-Time Processing & CloudWatch Monitoring
Live Amazon CloudWatch Logs showing records consumed from Kinesis shards and successfully written to Amazon Timestream for InfluxDB with zero failures.

![CloudWatch Logs](screenshots/Screenshot%20from%202026-11-10%2015-16-45.png)

---

### 5. Timestream for InfluxDB Data Explorer (Telemetry Visualization)
Real-time sensor telemetry (`humidity`, `temperature`, `pressure`, `message_count`) from device `thing` queried and visualized live in the InfluxDB Web UI.

![InfluxDB Data Explorer](screenshots/Screenshot%20from%202026-11-10%2015-09-59.png)

## 📋 Prerequisites

- **Terraform**: >= 1.0.0
- **AWS Account**: With appropriate permissions
- **AWS CLI**: Configured with credentials (`aws configure`)
- **SSH Key Pair**: For EC2 instance access (referenced as `madmaxkeypair`)
- **Python 3.12**: For Lambda function development (if modifying transformation logic)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/iot-data-pipeline.git
cd iot-data-pipeline
```

### 2. Configure Variables

Create a `terraform.tfvars` file:

```hcl
# Network Configuration
azs             = ["us-east-1a", "us-east-1b"]
public_subnets  = ["10.0.1.0/24", "10.0.2.0/24"]
private_subnets = ["10.0.11.0/24", "10.0.12.0/24"]

# Glue Configuration
glue_database_name = "iot_database"
glue_table_name    = "iot_table"
glue_crawler_name  = "iot_crawler"

# AWS Region
aws_region = "us-east-1"
```

### 3. Prepare Lambda Function Code

Package your Lambda transformation function:

```bash
cd lambda
zip -r lambda.zip lambda.py
aws s3 cp lambda.zip s3://transform-function-code-bucket-<random-id>/
cd ..
```

### 4. Initialize and Deploy

```bash
# Initialize Terraform
terraform init

# Review the execution plan
terraform plan

# Deploy infrastructure
terraform apply
```

### 5. Verify Deployment

```bash
# 1. Get IoT endpoint
aws iot describe-endpoint --endpoint-type iot:Data-ATS

# 2. Check Kinesis stream status
aws kinesis describe-stream --stream-name kinesis-stream

# 3. View Timestream for InfluxDB Web UI URL
terraform -chdir=terraform output influxdb_ui_url

# 4. Tail Lambda transformation logs in real-time
aws logs tail /aws/lambda/transform-function --follow
```

## 📁 Project Structure

```
.
├── screenshots/               # Visual proof & pipeline execution screenshots
├── src/                       # Application source code
│   ├── mqtt_publish.py        # EC2 IoT simulated publisher script
│   ├── transform.py           # Lambda Kinesis-to-InfluxDB transformer
│   └── requirements.txt       # Python dependencies
├── terraform/                 # Infrastructure as Code (Terraform)
│   ├── main.tf                # Main pipeline orchestration
│   ├── variables.tf           # Input variable declarations
│   ├── outputs.tf             # Outputs (endpoints, URLs, ARNs)
│   ├── terraform.tfvars       # Environment configurations
│   ├── provider.tf            # AWS & Vault provider setup
│   ├── files/
│   │   └── transform.zip      # Packaged Lambda zip artifact
│   ├── scripts/
│   │   └── user_data.sh       # EC2 IoT provisioning script
│   └── modules/               # Reusable Terraform modules
│       ├── cloudwatch/        # CloudWatch alarms & log groups
│       ├── ec2/               # Simulated IoT publisher EC2 instance
│       ├── firehose/          # Kinesis Data Firehose module
│       ├── iam/               # IAM roles & least-privilege policies
│       ├── kinesis/           # Kinesis Data Streams
│       ├── lambda/            # Serverless transformer function
│       ├── s3/                # Storage buckets & encryption
│       ├── security-groups/   # Security groups & network access
│       ├── sns/               # Notification topics & subscriptions
│       ├── sqs/               # Dead Letter Queues (DLQ)
│       ├── timestream/        # Amazon Timestream for InfluxDB
│       └── vpc/               # Multi-AZ VPC networking
├── LICENSE                    # MIT License
└── README.md                  # Project documentation & visual guide
```

## 🔧 Configuration

### IoT Device Simulation

The EC2 instance automatically configures an MQTT client on boot:

```bash
# User data script provisions:
- AWS IoT SDK for Python
- Device certificates and private keys
- MQTT connection to IoT Core endpoint
- Publishes sample telemetry data to topic/mqtt
```

### Data Transformation

Customize Lambda function (`lambda/lambda.py`):

```python
import json
import base64

def lambda_handler(event, context):
    """
    Transform incoming IoT data before storage
    """
    output = []
    
    for record in event['Records']:
        # Decode Kinesis data
        payload = base64.b64decode(record['kinesis']['data'])
        data = json.loads(payload)
        
        # Apply transformations
        transformed = {
            'timestamp': data['timestamp'],
            'device_id': data['deviceId'],
            'temperature': float(data['temperature']),
            'humidity': float(data['humidity']),
            # Add custom business logic here
        }
        
        output.append({
            'recordId': record['recordId'],
            'result': 'Ok',
            'data': base64.b64encode(
                json.dumps(transformed).encode('utf-8')
            ).decode('utf-8')
        })
    
    return {'records': output}
```

### Kinesis Stream Configuration

Modify stream settings in `modules/kinesis`:

```hcl
# On-demand scaling (default)
stream_mode = "ON_DEMAND"

# Or use provisioned mode for predictable workloads
stream_mode      = "PROVISIONED"
shard_count      = 2
retention_period = 168  # 7 days
```

### Timestream Retention Policies

Configure data lifecycle in `modules/timestream`:

```hcl
memory_store_retention_period_in_hours  = 24    # Hot storage
magnetic_store_retention_period_in_days = 365   # Cold storage
```

## 🔐 Security Considerations

### Certificate Management

- Device certificates are auto-generated using Terraform's `tls` provider
- Certificates embedded in EC2 user data (for demo purposes)
- **Production**: Use AWS Secrets Manager or Parameter Store for certificate distribution

### Network Security

- IoT devices in public subnets with restricted security groups
- Timestream in private subnets (no direct internet access)
- Security group rules follow principle of least privilege

### IAM Policies

All IAM roles follow least-privilege access:

```hcl
# IoT Core → Kinesis
- kinesis:PutRecord, kinesis:PutRecords (scoped to specific stream)

# Lambda → CloudWatch Logs
- logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents

# Glue Crawler → S3
- s3:GetObject, s3:ListBucket (scoped to specific bucket)
```

### Data Encryption

- **In Transit**: TLS 1.2+ for all AWS service communications
- **At Rest**: 
  - S3 buckets with default SSE-S3 encryption
  - Kinesis with AWS-managed keys
  - Timestream with AWS-managed encryption

## 📊 Monitoring and Observability

### CloudWatch Metrics

Key metrics to monitor:

```
IoT Core:
- PublishIn.Success
- RulesExecuted
- Failure (rule execution failures)

Kinesis:
- IncomingRecords
- IncomingBytes
- GetRecords.IteratorAgeMilliseconds
- WriteProvisionedThroughputExceeded

Lambda:
- Invocations
- Errors
- Duration
- Throttles

Timestream:
- SystemErrors
- UserErrors
- SuccessfulRequestLatency
```

### CloudWatch Alarms (Recommended)

```hcl
# Add to main.tf
resource "aws_cloudwatch_metric_alarm" "kinesis_iterator_age" {
  alarm_name          = "kinesis-high-iterator-age"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "GetRecords.IteratorAgeMilliseconds"
  namespace           = "AWS/Kinesis"
  period              = "300"
  statistic           = "Average"
  threshold           = "60000"  # 1 minute
  alarm_description   = "Kinesis consumer is falling behind"
}
```

### Logging

- **IoT Core**: CloudWatch Logs for rule execution
- **Lambda**: Automatic CloudWatch Logs integration
- **VPC Flow Logs**: Enable for network traffic analysis (optional)

## 🧪 Testing

### Send Test Data via IoT Core

```bash
# Publish test message
aws iot-data publish \
  --topic topic/mqtt \
  --cli-binary-format raw-in-base64-out \
  --payload '{"deviceId":"test-001","temperature":23.5,"humidity":65,"timestamp":"2024-12-19T10:30:00Z"}'
```

### Query Timestream Data

```bash
aws timestream-query query \
  --query-string "SELECT * FROM iot_timestream_db.iot_table WHERE time > ago(1h)"
```

### Query Athena

```bash
aws athena start-query-execution \
  --query-string "SELECT * FROM iot_database.iot_table LIMIT 100" \
  --result-configuration OutputLocation=s3://athena-temp-results-bucket-<id>/
```

## 📈 Scaling Considerations

### Kinesis Scaling

- **On-Demand Mode**: Automatically scales to 200 MB/s write, 400 MB/s read per shard
- **Provisioned Mode**: Manual shard management for cost optimization

### Lambda Concurrency

```hcl
# Add reserved concurrency to prevent throttling
reserved_concurrent_executions = 100
```

### Timestream Performance

- Memory store: Sub-second query latency
- Magnetic store: Higher latency but cost-effective
- Use time-based partitioning for optimal query performance

## 💰 Cost Optimization

### Estimated Monthly Costs (us-east-1)

| Service | Usage | Cost |
|---------|-------|------|
| IoT Core | 1M messages/month | $1.00 |
| Kinesis (On-Demand) | 1GB/day ingestion | $35.04 |
| Lambda | 1M invocations | $0.20 |
| Timestream | 1GB writes, 10GB storage | $8.50 |
| S3 | 100GB storage | $2.30 |
| Athena | 10GB scanned | $0.50 |
| **Total** | | **~$47.54/month** |

### Cost Reduction Tips

1. Use Kinesis Provisioned mode for steady workloads
2. Enable S3 Intelligent-Tiering for long-term storage
3. Configure Timestream magnetic store for historical data
4. Set S3 lifecycle policies to Glacier after 90 days
5. Use Athena partitioning to reduce scan size

## 🔄 CI/CD Integration

### GitHub Actions Example

```yaml
name: Terraform Deploy

on:
  push:
    branches: [ main ]

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
        
      - name: Terraform Init
        run: terraform init
        
      - name: Terraform Plan
        run: terraform plan
        
      - name: Terraform Apply
        if: github.ref == 'refs/heads/main'
        run: terraform apply -auto-approve
```

## 🧹 Cleanup

To destroy all resources:

```bash
terraform destroy
```

**Warning**: This will permanently delete:
- All S3 data
- Timestream database and tables
- Kinesis streams
- IoT devices and certificates

## 🐛 Troubleshooting

### Issue: IoT Device Not Publishing

```bash
# Check IoT Core logs
aws logs tail /aws/iot/logs --follow

# Verify certificate is active
aws iot describe-certificate --certificate-id <cert-id>

# Test connectivity
aws iot-data publish --topic test --payload '{"test":true}'
```

### Issue: Lambda Not Processing Records

```bash
# Check Lambda logs
aws logs tail /aws/lambda/transform-function --follow

# Verify event source mapping
aws lambda list-event-source-mappings --function-name transform-function

# Check IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn <role-arn> \
  --action-names kinesis:GetRecords
```

### Issue: High Kinesis Iterator Age

- Increase Lambda batch size
- Add reserved concurrency to Lambda
- Scale out Lambda execution (parallel processing)
- Check for processing errors in CloudWatch Logs

## 📚 Additional Resources

- [AWS IoT Core Documentation](https://docs.aws.amazon.com/iot/)
- [Kinesis Best Practices](https://docs.aws.amazon.com/streams/latest/dev/best-practices.html)
- [Timestream Developer Guide](https://docs.aws.amazon.com/timestream/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Support

For issues and questions:
- Open a GitHub Issue
- Contact: devops@yourcompany.com
- Slack: #iot-platform

## 🗺️ Roadmap

- [ ] Add DynamoDB integration for device state management
- [ ] Implement SageMaker for anomaly detection
- [ ] Add QuickSight dashboards for visualization
- [ ] Support multi-region deployment
- [ ] Add Kinesis Firehose for direct S3 delivery
- [ ] Implement AWS CDK version
- [ ] Add comprehensive end-to-end tests

---

**Built with ❤️ by the DevOps Team**
