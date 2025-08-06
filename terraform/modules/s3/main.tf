# S3 Bucket
resource "aws_s3_bucket" "bucket" {
  bucket        = var.bucket_name
  force_destroy = var.force_destroy
  tags = {
    Name = var.bucket_name
  }
}

# Creating object
resource "aws_s3_object" "object" {
  count  = length(var.objects)
  bucket = aws_s3_bucket.bucket.id
  source = var.objects[count.index].source
  key    = var.objects[count.index].key
}

# Bucket versioning configuration
resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.bucket.id
  versioning_configuration {
    status = var.versioning_enabled
  }
}