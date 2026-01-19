# AWS FedRAMP 20x Compliance Dashboard

dashboard "aws_compliance_overview" {
  title = "AWS Compliance Overview"

  tags = {
    type = "AWS"
  }

  container {
    card {
      title = "IAM Users"
      width = 3
      query = query.aws_iam_user_count
    }

    card {
      title = "S3 Buckets"
      width = 3
      query = query.aws_s3_bucket_count
    }

    card {
      title = "CloudTrail Trails"
      width = 3
      query = query.aws_cloudtrail_count
    }

    card {
      title = "Security Groups"
      width = 3
      query = query.aws_security_group_count
    }
  }

  container {
    chart {
      title = "IAM Users by MFA Status"
      width = 6
      type  = "donut"
      query = query.aws_iam_mfa_status
    }

    chart {
      title = "S3 Buckets by Encryption"
      width = 6
      type  = "donut"
      query = query.aws_s3_encryption_status
    }
  }

  container {
    table {
      title = "IAM Users"
      width = 12
      query = query.aws_iam_user_list
    }
  }
}

# ============================================================================
# AWS QUERIES
# ============================================================================

query "aws_iam_user_count" {
  sql = <<-EOQ
    select count(*) as value
    from aws_iam_user
  EOQ
}

query "aws_s3_bucket_count" {
  sql = <<-EOQ
    select count(*) as value
    from aws_s3_bucket
  EOQ
}

query "aws_cloudtrail_count" {
  sql = <<-EOQ
    select count(*) as value
    from aws_cloudtrail_trail
  EOQ
}

query "aws_security_group_count" {
  sql = <<-EOQ
    select count(*) as value
    from aws_vpc_security_group
  EOQ
}

query "aws_iam_mfa_status" {
  sql = <<-EOQ
    select
      case
        when mfa_active then 'MFA Enabled'
        else 'MFA Disabled'
      end as status,
      count(*) as count
    from aws_iam_user
    group by mfa_active
  EOQ
}

query "aws_s3_encryption_status" {
  sql = <<-EOQ
    select
      case
        when server_side_encryption_configuration is not null then 'Encrypted'
        else 'Not Encrypted'
      end as status,
      count(*) as count
    from aws_s3_bucket
    group by (server_side_encryption_configuration is not null)
  EOQ
}

query "aws_iam_user_list" {
  sql = <<-EOQ
    select
      name as "User",
      user_id as "User ID",
      case when mfa_active then 'Yes' else 'No' end as "MFA",
      case when password_enabled then 'Yes' else 'No' end as "Console Access",
      create_date as "Created"
    from aws_iam_user
    order by name
  EOQ
}
