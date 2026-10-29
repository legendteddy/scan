resource "aws_s3_bucket" "archive" {
  bucket        = "example-archive"
  force_destroy = true

  versioning {
    enabled = true
  }
}

resource "aws_db_instance" "primary" {
  identifier              = "example-primary"
  engine                  = "postgres"
  allocated_storage       = 20
  deletion_protection     = false
  skip_final_snapshot     = true
  backup_retention_period = 0
  storage_encrypted       = true
}

resource "aws_dynamodb_table" "jobs" {
  name         = "jobs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}
