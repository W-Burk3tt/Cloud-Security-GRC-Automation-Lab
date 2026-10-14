provider "aws" {
  access_key                  = "mock_key"
  secret_key                  = "mock_secret"
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    s3  = "http://localhost:4566"
    iam = "http://localhost:4566"
  }
}

# FIX 1: Enforce Strict S3 Encryption and Block Public Access
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "san-antonio-hr-records-2026"
}

resource "aws_s3_bucket_public_access_block" "public_exposure" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  # CHANGED TO TRUE: Total lockout of public data exposure
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_encryption" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# FIX 2: Implement IAM Least Privilege (No Wildcards)
resource "aws_iam_policy" "wildcard_policy" {
  name        = "basic-user-policy"
  description = "A remediated policy allowing only specific S3 read actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_bucket.vulnerable_bucket.arn}",
          "${aws_s3_bucket.vulnerable_bucket.arn}/*"
        ]
      }
    ]
  })
}
