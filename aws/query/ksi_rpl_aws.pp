# KSI-RPL: Recovery Planning Queries - AWS

query "ksi_rpl_01_aws_check" {
  sql = <<-EOQ
    -- KSI-RPL-01: Recovery Objectives
    -- Define and maintain RTO/RPO objectives

    with exempt_vaults as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_backup_vault
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-RPL-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_vaults as (
      select arn from exempt_vaults
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_rds as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_rds_db_instance
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-RPL-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_rds as (
      select arn from exempt_rds
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_dynamodb as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_dynamodb_table
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-RPL-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_dynamodb as (
      select arn from exempt_dynamodb
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check backup vaults have recovery points
    select
      v.arn as resource,
      case
        when ev.arn is not null then 'alarm'
        when e.arn is not null and ev.arn is null then 'skip'
        when v.number_of_recovery_points = 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when ev.arn is not null
          then v.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then v.name || ' is exempt.'
        when v.number_of_recovery_points = 0
          then v.name || ' has NO recovery points (indicates backup failures or misconfiguration).'
        else v.name || ' has ' || v.number_of_recovery_points || ' recovery points available.'
      end as reason,
      v.account_id
    from
      aws_backup_vault as v
      left join exempt_vaults as e on v.arn = e.arn
      left join expired_vaults as ev on v.arn = ev.arn

    union all

    -- Check RDS instances have adequate backup retention (minimum 7 days for RPO)
    select
      r.arn as resource,
      case
        when er.arn is not null then 'alarm'
        when e.arn is not null and er.arn is null then 'skip'
        when r.backup_retention_period < 7 then 'alarm'
        else 'ok'
      end as status,
      case
        when er.arn is not null
          then r.db_instance_identifier || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then r.db_instance_identifier || ' is exempt.'
        when r.backup_retention_period < 7
          then r.db_instance_identifier || ' has only ' || r.backup_retention_period ||
            ' days backup retention (should meet RPO requirements, recommend 7+ days).'
        else r.db_instance_identifier || ' has ' || r.backup_retention_period || ' days backup retention (meets RPO requirements).'
      end as reason,
      r.account_id
    from
      aws_rds_db_instance as r
      left join exempt_rds as e on r.arn = e.arn
      left join expired_rds as er on r.arn = er.arn

    union all

    -- Check DynamoDB tables have Point-in-Time Recovery (PITR) enabled
    select
      d.arn as resource,
      case
        when ed.arn is not null then 'alarm'
        when e.arn is not null and ed.arn is null then 'skip'
        when d.point_in_time_recovery_description ->> 'PointInTimeRecoveryStatus' = 'ENABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when ed.arn is not null
          then d.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then d.name || ' is exempt.'
        when d.point_in_time_recovery_description ->> 'PointInTimeRecoveryStatus' = 'ENABLED'
          then d.name || ' has PITR enabled (meets RPO objectives).'
        else d.name || ' does NOT have PITR enabled (required to meet RPO objectives).'
      end as reason,
      d.account_id
    from
      aws_dynamodb_table as d
      left join exempt_dynamodb as e on d.arn = e.arn
      left join expired_dynamodb as ed on d.arn = ed.arn
  EOQ
}

query "ksi_rpl_03_aws_check" {
  sql = <<-EOQ
    -- KSI-RPL-03: System Backups
    -- Ensure backup coverage and configuration

    with exempt_plans as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_backup_plan
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-RPL-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_plans as (
      select arn from exempt_plans
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_vaults as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_backup_vault
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-RPL-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_vaults as (
      select arn from exempt_vaults
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_rds as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_rds_db_instance
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-RPL-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_rds as (
      select arn from exempt_rds
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_buckets as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_s3_bucket
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-RPL-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_buckets as (
      select arn from exempt_buckets
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check backup plans have rules configured
    select
      p.arn as resource,
      case
        when ep.arn is not null then 'alarm'
        when e.arn is not null and ep.arn is null then 'skip'
        when p.backup_plan -> 'Rules' is null or jsonb_array_length(p.backup_plan -> 'Rules') = 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when ep.arn is not null
          then p.backup_plan_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then p.backup_plan_name || ' is exempt.'
        when p.backup_plan -> 'Rules' is null or jsonb_array_length(p.backup_plan -> 'Rules') = 0
          then p.backup_plan_name || ' has NO backup rules configured (backup plan must have rules defined).'
        else p.backup_plan_name || ' has ' || jsonb_array_length(p.backup_plan -> 'Rules') || ' backup rules configured.'
      end as reason,
      p.account_id
    from
      aws_backup_plan as p
      left join exempt_plans as e on p.arn = e.arn
      left join expired_plans as ep on p.arn = ep.arn

    union all

    -- Check backup vaults are encrypted
    select
      v.arn as resource,
      case
        when ev.arn is not null then 'alarm'
        when e.arn is not null and ev.arn is null then 'skip'
        when v.encryption_key_arn is null then 'alarm'
        else 'ok'
      end as status,
      case
        when ev.arn is not null
          then v.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then v.name || ' is exempt.'
        when v.encryption_key_arn is null
          then v.name || ' does NOT have encryption configured (encrypted vaults protect backup data).'
        else v.name || ' is encrypted with KMS key ' || v.encryption_key_arn || '.'
      end as reason,
      v.account_id
    from
      aws_backup_vault as v
      left join exempt_vaults as e on v.arn = e.arn
      left join expired_vaults as ev on v.arn = ev.arn

    union all

    -- Check RDS instances have automated backups enabled
    select
      r.arn as resource,
      case
        when er.arn is not null then 'alarm'
        when e.arn is not null and er.arn is null then 'skip'
        when r.backup_retention_period = 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when er.arn is not null
          then r.db_instance_identifier || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then r.db_instance_identifier || ' is exempt.'
        when r.backup_retention_period = 0
          then r.db_instance_identifier || ' has automated backups DISABLED (RDS automated backups should be enabled).'
        else r.db_instance_identifier || ' has automated backups enabled (' || r.backup_retention_period || ' days retention).'
      end as reason,
      r.account_id
    from
      aws_rds_db_instance as r
      left join exempt_rds as e on r.arn = e.arn
      left join expired_rds as er on r.arn = er.arn

    union all

    -- Check S3 buckets have versioning enabled (provides object recovery capability)
    select
      b.arn as resource,
      case
        when eb.arn is not null then 'alarm'
        when e.arn is not null and eb.arn is null then 'skip'
        when b.versioning_status = 'Enabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when eb.arn is not null
          then b.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then b.name || ' is exempt.'
        when b.versioning_status = 'Enabled'
          then b.name || ' has versioning enabled (provides object-level backup/recovery capability).'
        else b.name || ' does NOT have versioning enabled (versioning status: ' || coalesce(b.versioning_status, 'Suspended') || ').'
      end as reason,
      b.account_id
    from
      aws_s3_bucket as b
      left join exempt_buckets as e on b.arn = e.arn
      left join expired_buckets as eb on b.arn = eb.arn
  EOQ
}
