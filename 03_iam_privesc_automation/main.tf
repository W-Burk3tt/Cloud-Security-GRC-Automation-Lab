provider "aws" {
  access_key                  = "mock"
  secret_key                  = "mock"
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    iam = "http://localhost:4566"
    s3  = "http://localhost:4566"
  }
}

resource "aws_iam_role" "support_tier1" {
  name = "Support-Tier1-Role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "://amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "limited_developer_policy" {
  name        = "LimitedDeveloperPolicy"
  description = "Allows viewing configuration blocks and managing local policy updates"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:ListAllMyBuckets",
          "iam:Get*",
          "iam:List*"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "iam:CreatePolicyVersion"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_backdoor" {
  role       = aws_iam_role.support_tier1.name
  policy_arn = aws_iam_policy.limited_developer_policy.arn
}
