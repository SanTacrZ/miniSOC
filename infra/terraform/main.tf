# Terraform baseline con misconfigs intencionales para Cloud Audit
# NIST SC-7, AC-3 — estos FAIL deben ser detectados

# FAIL: open SSH
resource "aws_security_group" "lab_sg" {
  name = "lab-open-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # <- NET-001 critical
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # <- NET-002 medium
  }
}

# FAIL: public bucket
resource "aws_s3_bucket" "public_data" {
  bucket = "minisoc-public-exfil"
  acl    = "public-read"  # <- STO-001 critical
}

resource "aws_s3_bucket_public_access_block" "bad" {
  bucket = aws_s3_bucket.public_data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# FAIL: no encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "missing" {
  # intentionally missing -> STO-002
  count = 0
}

# FAIL: IAM wildcard
resource "aws_iam_policy" "wildcard" {
  name = "WildcardAdmin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
