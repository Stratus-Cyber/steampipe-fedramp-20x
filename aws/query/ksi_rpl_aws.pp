# KSI-RPL: Recovery Planning Queries - AWS

query "ksi_rpl_01_aws_check" {
  sql = <<-EOQ
    -- KSI-RPL-01: Recovery Objectives
    -- Define and maintain RTO/RPO objectives

    -- Check backup vaults have recovery points
    select
      arn as resource,
      case
        when number_of_recovery_points = 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when number_of_recovery_points = 0
          then name || ' has NO recovery points (indicates backup failures or misconfiguration).'
        else name || ' has ' || number_of_recovery_points || ' recovery points available.'
      end as reason,
      account_id
    from
      aws_backup_vault

    union all

    -- Check RDS instances have adequate backup retention (minimum 7 days for RPO)
    select
      arn as resource,
      case
        when backup_retention_period < 7 then 'alarm'
        else 'ok'
      end as status,
      case
        when backup_retention_period < 7
          then db_instance_identifier || ' has only ' || backup_retention_period ||
            ' days backup retention (should meet RPO requirements, recommend 7+ days).'
        else db_instance_identifier || ' has ' || backup_retention_period || ' days backup retention (meets RPO requirements).'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check DynamoDB tables have Point-in-Time Recovery (PITR) enabled
    select
      arn as resource,
      case
        when point_in_time_recovery_description ->> 'PointInTimeRecoveryStatus' = 'ENABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when point_in_time_recovery_description ->> 'PointInTimeRecoveryStatus' = 'ENABLED'
          then name || ' has PITR enabled (meets RPO objectives).'
        else name || ' does NOT have PITR enabled (required to meet RPO objectives).'
      end as reason,
      account_id
    from
      aws_dynamodb_table
  EOQ
}

query "ksi_rpl_03_aws_check" {
  sql = <<-EOQ
    -- KSI-RPL-03: System Backups
    -- Ensure backup coverage and configuration

    -- Check backup plans have rules configured
    select
      arn as resource,
      case
        when backup_plan -> 'Rules' is null or jsonb_array_length(backup_plan -> 'Rules') = 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when backup_plan -> 'Rules' is null or jsonb_array_length(backup_plan -> 'Rules') = 0
          then backup_plan_name || ' has NO backup rules configured (backup plan must have rules defined).'
        else backup_plan_name || ' has ' || jsonb_array_length(backup_plan -> 'Rules') || ' backup rules configured.'
      end as reason,
      account_id
    from
      aws_backup_plan

    union all

    -- Check backup vaults are encrypted
    select
      arn as resource,
      case
        when encryption_key_arn is null then 'alarm'
        else 'ok'
      end as status,
      case
        when encryption_key_arn is null
          then name || ' does NOT have encryption configured (encrypted vaults protect backup data).'
        else name || ' is encrypted with KMS key ' || encryption_key_arn || '.'
      end as reason,
      account_id
    from
      aws_backup_vault

    union all

    -- Check RDS instances have automated backups enabled
    select
      arn as resource,
      case
        when backup_retention_period = 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when backup_retention_period = 0
          then db_instance_identifier || ' has automated backups DISABLED (RDS automated backups should be enabled).'
        else db_instance_identifier || ' has automated backups enabled (' || backup_retention_period || ' days retention).'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check S3 buckets have versioning enabled (provides object recovery capability)
    select
      arn as resource,
      case
        when versioning_status = 'Enabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when versioning_status = 'Enabled'
          then name || ' has versioning enabled (provides object-level backup/recovery capability).'
        else name || ' does NOT have versioning enabled (versioning status: ' || coalesce(versioning_status, 'Suspended') || ').'
      end as reason,
      account_id
    from
      aws_s3_bucket
  EOQ
}
