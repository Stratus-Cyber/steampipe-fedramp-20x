# KSI-RPL: Recovery Planning Queries - AWS

query "ksi_rpl_01_aws_check" {
  sql = <<-EOQ
    -- Check RDS automated backups enabled (foundational_security_rds_5)
    select
      arn as resource,
      case
        when backup_retention_period >= 7 then 'ok'
        when backup_retention_period > 0 then 'info'
        else 'alarm'
      end as status,
      case
        when backup_retention_period >= 7 then db_instance_identifier || ' has ' || backup_retention_period || ' day backup retention.'
        when backup_retention_period > 0 then db_instance_identifier || ' has only ' || backup_retention_period || ' day backup retention (recommend 7+).'
        else db_instance_identifier || ' has no automated backups enabled.'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check RDS Multi-AZ enabled (foundational_security_rds_7)
    select
      arn as resource,
      case
        when multi_az then 'ok'
        else 'alarm'
      end as status,
      case
        when multi_az then db_instance_identifier || ' has Multi-AZ enabled for high availability.'
        else db_instance_identifier || ' does not have Multi-AZ enabled.'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check RDS deletion protection (foundational_security_rds_8)
    select
      arn as resource,
      case
        when deletion_protection then 'ok'
        else 'alarm'
      end as status,
      case
        when deletion_protection then db_instance_identifier || ' has deletion protection enabled.'
        else db_instance_identifier || ' does not have deletion protection.'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check ElastiCache automatic backups (foundational_security_elasticache_1)
    select
      arn as resource,
      case
        when snapshot_retention_limit > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when snapshot_retention_limit > 0 then replication_group_id || ' has ' || snapshot_retention_limit || ' day snapshot retention.'
        else replication_group_id || ' has no automatic backups configured.'
      end as reason,
      account_id
    from
      aws_elasticache_replication_group

    union all

    -- Check Auto Scaling group multiple AZs (foundational_security_autoscaling_2)
    -- Note: Using 'name' instead of 'auto_scaling_group_name' for Steampipe compatibility
    select
      autoscaling_group_arn as resource,
      case
        when jsonb_array_length(availability_zones) > 1 then 'ok'
        else 'alarm'
      end as status,
      case
        when jsonb_array_length(availability_zones) > 1 then name || ' spans ' || jsonb_array_length(availability_zones) || ' availability zones.'
        else name || ' is only in ' || jsonb_array_length(availability_zones) || ' availability zone.'
      end as reason,
      account_id
    from
      aws_ec2_autoscaling_group
  EOQ
}
