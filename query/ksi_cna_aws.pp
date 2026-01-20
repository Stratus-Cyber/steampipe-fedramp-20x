# KSI-CNA: Cloud Native Architecture Queries - AWS

query "ksi_cna_01_aws_check" {
  sql = <<-EOQ
    -- Check default VPC security groups restrict all traffic (cis_v150_5_1)
    select
      arn as resource,
      case
        when vpc_id in (select vpc_id from aws_vpc where is_default)
          and (jsonb_array_length(ip_permissions) > 0 or jsonb_array_length(ip_permissions_egress) > 0) then 'alarm'
        else 'ok'
      end as status,
      case
        when vpc_id in (select vpc_id from aws_vpc where is_default)
          and (jsonb_array_length(ip_permissions) > 0 or jsonb_array_length(ip_permissions_egress) > 0) then group_name || ' default security group has rules configured.'
        else group_name || ' security group is properly configured.'
      end as reason,
      account_id
    from
      aws_vpc_security_group
    where
      group_name = 'default'

    union all

    -- Check no security groups allow unrestricted SSH (cis_v150_5_2)
    select
      arn as resource,
      case
        when ip_permissions @> '[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when ip_permissions @> '[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]' then group_name || ' allows unrestricted SSH access (0.0.0.0/0).'
        else group_name || ' does not allow unrestricted SSH.'
      end as reason,
      account_id
    from
      aws_vpc_security_group

    union all

    -- Check no security groups allow unrestricted RDP (cis_v150_5_3)
    select
      arn as resource,
      case
        when ip_permissions @> '[{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when ip_permissions @> '[{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]' then group_name || ' allows unrestricted RDP access (0.0.0.0/0).'
        else group_name || ' does not allow unrestricted RDP.'
      end as reason,
      account_id
    from
      aws_vpc_security_group

    union all

    -- Check EC2 instances not assigned public IPs (foundational_security_ec2_2)
    select
      arn as resource,
      case
        when public_ip_address is null then 'ok'
        else 'alarm'
      end as status,
      case
        when public_ip_address is null then instance_id || ' does not have a public IP.'
        else instance_id || ' has public IP ' || public_ip_address || '.'
      end as reason,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'

    union all

    -- Check RDS instances not publicly accessible (foundational_security_rds_18)
    select
      arn as resource,
      case
        when not publicly_accessible then 'ok'
        else 'alarm'
      end as status,
      case
        when not publicly_accessible then db_instance_identifier || ' is not publicly accessible.'
        else db_instance_identifier || ' is publicly accessible.'
      end as reason,
      account_id
    from
      aws_rds_db_instance
  EOQ
}

query "ksi_cna_02_aws_check" {
  sql = <<-EOQ
    -- NOTE: S3 bucket public access blocked check (foundational_security_s3_4) removed
    -- Requires s3:GetBucketPublicAccessBlock permission which is not available

    -- Check EC2 EBS volumes encrypted (foundational_security_ec2_7)
    select
      arn as resource,
      case
        when encrypted then 'ok'
        else 'alarm'
      end as status,
      case
        when encrypted then volume_id || ' is encrypted.'
        else volume_id || ' is not encrypted.'
      end as reason,
      account_id
    from
      aws_ebs_volume

    union all

    -- Check RDS instances encrypted (foundational_security_rds_3)
    select
      arn as resource,
      case
        when storage_encrypted then 'ok'
        else 'alarm'
      end as status,
      case
        when storage_encrypted then db_instance_identifier || ' has storage encryption enabled.'
        else db_instance_identifier || ' does not have storage encryption enabled.'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check RDS snapshots encrypted (foundational_security_rds_4)
    select
      arn as resource,
      case
        when encrypted then 'ok'
        else 'alarm'
      end as status,
      case
        when encrypted then db_snapshot_identifier || ' is encrypted.'
        else db_snapshot_identifier || ' is not encrypted.'
      end as reason,
      account_id
    from
      aws_rds_db_snapshot

    union all

    -- Check ElastiCache encryption at rest (foundational_security_elasticache_4)
    select
      arn as resource,
      case
        when at_rest_encryption_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when at_rest_encryption_enabled then replication_group_id || ' has encryption at rest enabled.'
        else replication_group_id || ' does not have encryption at rest enabled.'
      end as reason,
      account_id
    from
      aws_elasticache_replication_group
  EOQ
}

query "ksi_cna_03_aws_check" {
  sql = <<-EOQ
    -- NOTE: S3 bucket versioning check (foundational_security_s3_5) removed
    -- Requires s3:GetBucketVersioning permission which is not available

    -- Check ElastiCache encryption in transit (foundational_security_elasticache_5)
    select
      arn as resource,
      case
        when transit_encryption_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when transit_encryption_enabled then replication_group_id || ' has encryption in transit enabled.'
        else replication_group_id || ' does not have encryption in transit enabled.'
      end as reason,
      account_id
    from
      aws_elasticache_replication_group

    union all

    -- Check ALB uses HTTPS listeners (foundational_security_elb_2)
    select
      arn as resource,
      case
        when scheme = 'internet-facing' then 'info'
        else 'ok'
      end as status,
      case
        when scheme = 'internet-facing' then title || ' is internet-facing (verify HTTPS listeners).'
        else title || ' is internal.'
      end as reason,
      account_id
    from
      aws_ec2_application_load_balancer
  EOQ
}

query "ksi_cna_04_aws_check" {
  sql = <<-EOQ
    -- NOTE: S3 block public access at account level (cis_v150_2_1_5) removed
    -- Requires s3:GetAccountPublicAccessBlock permission which is not available

    -- Check S3 buckets not publicly accessible (foundational_security_s3_1, foundational_security_s3_2)
    select
      arn as resource,
      case
        when bucket_policy_is_public then 'alarm'
        else 'ok'
      end as status,
      case
        when bucket_policy_is_public then name || ' has a public bucket policy.'
        else name || ' bucket policy is not public.'
      end as reason,
      account_id
    from
      aws_s3_bucket

    union all

    -- Check EC2 instances not use default security group (foundational_security_ec2_1)
    select
      arn as resource,
      case
        when security_groups @> '[{"GroupName": "default"}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when security_groups @> '[{"GroupName": "default"}]' then instance_id || ' uses default security group.'
        else instance_id || ' does not use default security group.'
      end as reason,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'

    union all

    -- Check EC2 subnets no auto-assign public IP (foundational_security_ec2_15)
    select
      subnet_arn as resource,
      case
        when map_public_ip_on_launch then 'alarm'
        else 'ok'
      end as status,
      case
        when map_public_ip_on_launch then subnet_id || ' auto-assigns public IP addresses.'
        else subnet_id || ' does not auto-assign public IP addresses.'
      end as reason,
      account_id
    from
      aws_vpc_subnet

    union all

    -- Check RDS instances not publicly accessible (foundational_security_rds_1, foundational_security_rds_2)
    select
      arn as resource,
      case
        when not publicly_accessible then 'ok'
        else 'alarm'
      end as status,
      case
        when not publicly_accessible then db_instance_identifier || ' is not publicly accessible.'
        else db_instance_identifier || ' is publicly accessible.'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check Auto Scaling uses launch template (foundational_security_autoscaling_5)
    -- Note: Using 'name' instead of 'auto_scaling_group_name' for Steampipe compatibility
    select
      autoscaling_group_arn as resource,
      case
        when launch_template_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when launch_template_id is not null then name || ' uses launch template.'
        else name || ' does not use launch template.'
      end as reason,
      account_id
    from
      aws_ec2_autoscaling_group
  EOQ
}
