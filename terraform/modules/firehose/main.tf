# resource "aws_kinesis_firehose_delivery_stream" "opensearch_stream" {
#   name        = "kinesis-firehose-opensearch-stream"
#   destination = "elasticsearch"

#   kinesis_source_configuration {
#     kinesis_stream_arn = aws_kinesis_stream.source_stream.arn
#     role_arn           = aws_iam_role.firehose_role.arn
#   }

#   opensearch_configuration {
#     domain_arn = aws_opensearch_domain.opensearch.arn
#     role_arn   = aws_iam_role.firehose_role.arn
#     index_name = "data-index"
#     type_name  = "_doc" # Note: In OpenSearch 2.x, this is less relevant but still required

#     s3_configuration {
#       role_arn           = aws_iam_role.firehose_role.arn
#       bucket_arn         = aws_s3_bucket.firehose_backup.arn
#       prefix             = "opensearch-failed/"
#       compression_format = "GZIP"
#     }

#     # Optional settings
#     buffering_interval = 60
#     buffering_size     = 5

#     # S3 backup settings in case delivery to OpenSearch fails
#     s3_backup_mode = "FailedDocumentsOnly"

#     # Optional processing
#     processing_configuration {
#       enabled = true

#       # Example Lambda processor
#       # Uncomment and configure if needed
#       # processors {
#       #   type = "Lambda"
#       #   parameters {
#       #     parameter_name  = "LambdaArn"
#       #     parameter_value = "arn:aws:lambda:us-east-1:${data.aws_caller_identity.current.account_id}:function:data-processor"
#       #   }
#       # }
#     }
#   }
#   depends_on = [
#     aws_iam_role_policy_attachment.firehose_attachment
#   ]
# }

resource "aws_kinesis_firehose_delivery_stream" "firehose_delivery_stream" {
  name        = var.name
  destination = var.destination
  kinesis_source_configuration {
    kinesis_stream_arn = var.kinesis_stream_arn
    role_arn           = var.kinesis_stream_role_arn
  }
  opensearch_configuration {
    domain_arn = var.opensearch_domain_arn
    role_arn   = var.opensearch_role_arn
    index_name = var.opensearch_index_name    
    s3_configuration {
      role_arn           = var.s3_role_arn
      bucket_arn         = var.backup_bucket_arn
      compression_format = var.s3_compression_format
    }

    processing_configuration {
      enabled = var.processing_enabled

      processors {
        type = var.processing_type

        parameters {
          parameter_name  = var.processing_parameter_name
          parameter_value = var.processing_parameter_value
        }
      }
    }
  }
}
