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
      region,
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
      region,
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
      region,
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
      region,
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
      region,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check WAFv2 web ACL has rules (foundational_security_wafv2_1)
    select
      arn as resource,
      case
        when jsonb_array_length(rules) > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when jsonb_array_length(rules) > 0 then name || ' has ' || jsonb_array_length(rules) || ' rules configured.'
        else name || ' has no rules configured.'
      end as reason,
      region,
      account_id
    from
      aws_wafv2_web_acl
  EOQ
}

query "ksi_cna_02_aws_check" {
  sql = <<-EOQ
    -- Check S3 bucket SSL requests only (cis_v150_2_1_1, cis_v150_2_1_2)
    select
      arn as resource,
      case
        when policy::jsonb @> '{"Statement": [{"Effect": "Deny", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}' then 'ok'
        else 'alarm'
      end as status,
      case
        when policy::jsonb @> '{"Statement": [{"Effect": "Deny", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}' then name || ' requires SSL for all requests.'
        else name || ' does not require SSL for requests.'
      end as reason,
      region,
      account_id
    from
      aws_s3_bucket

    union all

    -- Check S3 bucket public access blocked (foundational_security_s3_4)
    select
      arn as resource,
      case
        when block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets then 'ok'
        else 'alarm'
      end as status,
      case
        when block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets then name || ' has public access blocked.'
        else name || ' does not have all public access settings blocked.'
      end as reason,
      region,
      account_id
    from
      aws_s3_bucket

    union all

    -- Check EC2 EBS default encryption (foundational_security_ec2_3)
    select
      'arn:aws:ec2:' || region || ':' || account_id as resource,
      case
        when default_ebs_encryption_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when default_ebs_encryption_enabled then 'EBS default encryption is enabled in ' || region || '.'
        else 'EBS default encryption is not enabled in ' || region || '.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_regional_settings

    union all

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
      region,
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
      region,
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
      region,
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
      region,
      account_id
    from
      aws_elasticache_replication_group
  EOQ
}

query "ksi_cna_03_aws_check" {
  sql = <<-EOQ
    -- Check S3 bucket versioning enabled (foundational_security_s3_5)
    select
      arn as resource,
      case
        when versioning_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when versioning_enabled then name || ' has versioning enabled.'
        else name || ' does not have versioning enabled.'
      end as reason,
      region,
      account_id
    from
      aws_s3_bucket

    union all

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
      region,
      account_id
    from
      aws_elasticache_replication_group

    union all

    -- Check Classic LB uses HTTPS/SSL (foundational_security_elb_1)
    select
      arn as resource,
      case
        when listener_descriptions @> '[{"Listener": {"Protocol": "HTTPS"}}]'
          or listener_descriptions @> '[{"Listener": {"Protocol": "SSL"}}]' then 'ok'
        else 'alarm'
      end as status,
      case
        when listener_descriptions @> '[{"Listener": {"Protocol": "HTTPS"}}]'
          or listener_descriptions @> '[{"Listener": {"Protocol": "SSL"}}]' then name || ' uses HTTPS/SSL listeners.'
        else name || ' does not use HTTPS/SSL listeners.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_classic_load_balancer

    union all

    -- Check ALB uses HTTPS listeners (foundational_security_elb_2)
    select
      lb.arn as resource,
      case
        when l.protocol = 'HTTPS' then 'ok'
        else 'alarm'
      end as status,
      case
        when l.protocol = 'HTTPS' then lb.title || ' listener uses HTTPS.'
        else lb.title || ' listener uses ' || l.protocol || ' (not HTTPS).'
      end as reason,
      lb.region,
      lb.account_id
    from
      aws_ec2_application_load_balancer as lb
      join aws_ec2_load_balancer_listener as l on lb.arn = l.load_balancer_arn

    union all

    -- Check Classic LB connection draining enabled (foundational_security_elb_3)
    select
      arn as resource,
      case
        when connection_draining_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when connection_draining_enabled then name || ' has connection draining enabled.'
        else name || ' does not have connection draining enabled.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_classic_load_balancer

    union all

    -- Check ALB drop invalid header enabled (foundational_security_elb_8)
    select
      arn as resource,
      case
        when load_balancer_attributes @> '[{"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "true"}]' then 'ok'
        else 'alarm'
      end as status,
      case
        when load_balancer_attributes @> '[{"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "true"}]' then title || ' drops invalid HTTP headers.'
        else title || ' does not drop invalid HTTP headers.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_application_load_balancer
  EOQ
}

query "ksi_cna_04_aws_check" {
  sql = <<-EOQ
    -- Check S3 block public access at account level (cis_v150_2_1_5)
    select
      'arn:aws:s3:::' || account_id as resource,
      case
        when block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets then 'ok'
        else 'alarm'
      end as status,
      case
        when block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets then 'Account-level S3 public access is blocked.'
        else 'Account-level S3 public access is not fully blocked.'
      end as reason,
      account_id
    from
      aws_s3_account_settings

    union all

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
      region,
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
      region,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'

    union all

    -- Check launch configurations have no public IP (foundational_security_ec2_9)
    select
      launch_configuration_arn as resource,
      case
        when associate_public_ip_address then 'alarm'
        else 'ok'
      end as status,
      case
        when associate_public_ip_address then name || ' assigns public IP addresses.'
        else name || ' does not assign public IP addresses.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_launch_configuration

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
      region,
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
      region,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check Auto Scaling uses launch template (foundational_security_autoscaling_5)
    select
      autoscaling_group_arn as resource,
      case
        when launch_template_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when launch_template_id is not null then auto_scaling_group_name || ' uses launch template.'
        else auto_scaling_group_name || ' does not use launch template.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_autoscaling_group
  EOQ
}
