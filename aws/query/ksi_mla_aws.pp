# KSI-MLA: Monitoring, Logging, Auditing Queries - AWS

query "ksi_mla_01_1_aws_check" {
  sql = <<-EOQ
    -- KSI-MLA-01: SIEM / Centralized Logging
        -- Operate centralized, tamper-resistant logging
    
        with exempt_trails as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-01.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:cloudtrail:%'
        ),
        expired_trails as (
          select arn from exempt_trails
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check CloudTrail trails have log integrity validation (tamper-resistant)
        select
          t.arn as resource,
          case
            when et.arn is not null then 'alarm'
            when e.arn is not null and et.arn is null then 'skip'
            when t.log_file_validation_enabled = false then 'alarm'
            else 'ok'
          end as status,
          case
            when et.arn is not null
              then t.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then t.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when t.log_file_validation_enabled = false
              then t.name || ' does NOT have log file validation enabled (logs lack integrity protection).'
            else t.name || ' has log file validation enabled (ensures audit trail integrity).'
          end as reason,
          t.account_id
        from
          aws_cloudtrail_trail as t
          left join exempt_trails as e on t.arn = e.arn
          left join expired_trails as et on t.arn = et.arn
  EOQ
}

query "ksi_mla_01_2_aws_check" {
  sql = <<-EOQ
        with exempt_log_groups as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-01.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:logs:%:log-group:%'
        ),
        expired_log_groups as (
          select arn from exempt_log_groups
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check CloudWatch log groups are encrypted (protect sensitive audit data)
        select
          lg.arn as resource,
          case
            when elg.arn is not null then 'alarm'
            when e.arn is not null and elg.arn is null then 'skip'
            when lg.kms_key_id is null then 'alarm'
            else 'ok'
          end as status,
          case
            when elg.arn is not null
              then lg.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then lg.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when lg.kms_key_id is null
              then lg.name || ' is NOT encrypted (SIEM data should be protected with KMS encryption).'
            else lg.name || ' is encrypted with KMS key ' || lg.kms_key_id || ' (protects sensitive audit data).'
          end as reason,
          lg.account_id
        from
          aws_cloudwatch_log_group as lg
          left join exempt_log_groups as e on lg.arn = e.arn
          left join expired_log_groups as elg on lg.arn = elg.arn
  EOQ
}

query "ksi_mla_01_3_aws_check" {
  sql = <<-EOQ
    -- Check Security Lake status (centralizes security telemetry)
        -- Note: Security Lake is account-level service, no resource-level exemptions
        select
          arn as resource,
          case
            when status = 'COMPLETED' then 'ok'
            else 'info'
          end as status,
          case
            when status = 'COMPLETED'
              then 'Security Lake ' || arn || ' is in COMPLETED status (centralizing security telemetry).'
            else 'Security Lake ' || arn || ' is NOT in COMPLETED status: ' || coalesce(status, 'unknown') || '.'
          end as reason,
          account_id
        from
          aws_securitylake_data_lake
  EOQ
}

query "ksi_mla_01_4_aws_check" {
  sql = <<-EOQ
        with exempt_buckets as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-01.4' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:s3:::%'
        ),
        expired_buckets as (
          select arn from exempt_buckets
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check log buckets have access logging enabled (detect unauthorized access)
        select
          b.arn as resource,
          case
            when eb.arn is not null then 'alarm'
            when e.arn is not null and eb.arn is null then 'skip'
            when (b.name like '%log%' or b.name like '%trail%' or b.name like '%audit%') and b.logging is null then 'alarm'
            else 'ok'
          end as status,
          case
            when eb.arn is not null
              then b.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then b.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when (b.name like '%log%' or b.name like '%trail%' or b.name like '%audit%') and b.logging is null
              then b.name || ' is a log bucket WITHOUT access logging (cannot detect unauthorized access to logs).'
            else b.name || ' has appropriate access logging configuration.'
          end as reason,
          b.account_id
        from
          aws_s3_bucket as b
          left join exempt_buckets as e on b.arn = e.arn
          left join expired_buckets as eb on b.arn = eb.arn
        where
          b.name like '%log%' or b.name like '%trail%' or b.name like '%audit%'
  EOQ
}

query "ksi_mla_02_aws_check" {
  sql = <<-EOQ
    -- KSI-MLA-02: Audit Logging
    -- Retain and review logs regularly

    with exempt_trails as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
        tags->>'${var.exemption_reason_key}' as exemption_reason
      from
        aws_tagging_resource
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-MLA-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
        and arn like 'arn:aws:cloudtrail:%'
    ),
    expired_trails as (
      select arn from exempt_trails
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check CloudTrail trails have comprehensive coverage
    select
      t.arn as resource,
      case
        when et.arn is not null then 'alarm'
        when e.arn is not null and et.arn is null then 'skip'
        when not (t.is_logging = true and t.is_multi_region_trail = true and t.include_global_service_events = true) then 'alarm'
        else 'ok'
      end as status,
      case
        when et.arn is not null
          then t.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
        when e.arn is not null
          then t.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
        when not (t.is_logging = true and t.is_multi_region_trail = true and t.include_global_service_events = true)
          then t.name || ' lacks comprehensive audit coverage: ' ||
            case when not t.is_logging then 'NOT logging ' else '' end ||
            case when not t.is_multi_region_trail then 'NOT multi-region ' else '' end ||
            case when not t.include_global_service_events then 'NO global service events' else '' end
        else t.name || ' has comprehensive audit logging (multi-region with global service events).'
      end as reason,
      t.account_id
    from
      aws_cloudtrail_trail as t
      left join exempt_trails as e on t.arn = e.arn
      left join expired_trails as et on t.arn = et.arn
  EOQ
}

query "ksi_mla_05_1_aws_check" {
  sql = <<-EOQ
    -- KSI-MLA-05: Configuration Evaluation
        -- Continuously evaluate infrastructure configuration
    
        -- Check AWS Config recorders are actively evaluating configurations
    
    -- KSI-MLA-05: Configuration Evaluation
        -- Continuously evaluate infrastructure configuration
    
        -- Check AWS Config recorders are actively evaluating configurations
        select
          'arn:aws:config:' || region || ':' || account_id || ':recorder/' || name as resource,
          case
            when status ->> 'recording' = 'true' then 'ok'
            else 'alarm'
          end as status,
          case
            when status ->> 'recording' = 'true'
              then 'AWS Config recorder ' || name || ' is actively recording (provides continuous configuration evaluation).'
            else 'AWS Config recorder ' || name || ' is NOT actively recording configurations.'
          end as reason,
          account_id
        from
          aws_config_configuration_recorder
  EOQ
}

query "ksi_mla_05_2_aws_check" {
  sql = <<-EOQ
        with exempt_rules as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_config_rule
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-05' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-05.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_rules as (
          select arn from exempt_rules
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Config rules compliance status (aggregate configuration posture view)
        select
          c.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT' then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then c.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then c.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT'
              then 'Config rule ' || c.name || ' is NON_COMPLIANT (configuration drift detected).'
            else 'Config rule ' || c.name || ' is compliant.'
          end as reason,
          c.account_id
        from
          aws_config_rule as c
          left join exempt_rules as e on c.arn = e.arn
          left join expired_rules as er on c.arn = er.arn
  EOQ
}

query "ksi_mla_07_aws_check" {
  sql = <<-EOQ
    -- KSI-MLA-07: Event Type Coverage
    -- Log required event types comprehensively

    with exempt_trails as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
        tags->>'${var.exemption_reason_key}' as exemption_reason
      from
        aws_tagging_resource
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-MLA-07' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
        and arn like 'arn:aws:cloudtrail:%'
    ),
    expired_trails as (
      select arn from exempt_trails
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check CloudTrail trails have complete event coverage
    select
      t.arn as resource,
      case
        when et.arn is not null then 'alarm'
        when e.arn is not null and et.arn is null then 'skip'
        when t.is_multi_region_trail = false or t.include_global_service_events = false then 'alarm'
        else 'ok'
      end as status,
      case
        when et.arn is not null
          then t.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
        when e.arn is not null
          then t.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
        when t.is_multi_region_trail = false or t.include_global_service_events = false
          then t.name || ' has incomplete event coverage: ' ||
            case when t.is_multi_region_trail = false then 'NOT multi-region ' else '' end ||
            case when t.include_global_service_events = false then 'NO global service events' else '' end ||
            ' (event selectors define scope; multi-region and global services required).'
        else t.name || ' has complete event type coverage (multi-region with global service events).'
      end as reason,
      t.account_id
    from
      aws_cloudtrail_trail as t
      left join exempt_trails as e on t.arn = e.arn
      left join expired_trails as et on t.arn = et.arn
  EOQ
}

query "ksi_mla_08_1_aws_check" {
  sql = <<-EOQ
    -- KSI-MLA-08: Log Data Access Control
        -- Restrict access to log data using least privilege
    
        with exempt_buckets as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-08' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-08.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:s3:::%'
        ),
        expired_buckets as (
          select arn from exempt_buckets
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check log buckets don't have overly permissive ACLs
        select
          b.arn as resource,
          case
            when eb.arn is not null then 'alarm'
            when e.arn is not null and eb.arn is null then 'skip'
            when (b.name like '%log%' or b.name like '%trail%' or b.name like '%audit%')
              and (b.acl ->> 'Grants')::jsonb @> '[{"Permission": "FULL_CONTROL"}]' then 'alarm'
            else 'ok'
          end as status,
          case
            when eb.arn is not null
              then b.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then b.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when (b.name like '%log%' or b.name like '%trail%' or b.name like '%audit%')
              and (b.acl ->> 'Grants')::jsonb @> '[{"Permission": "FULL_CONTROL"}]'
              then b.name || ' is a log bucket with overly permissive ACLs (log buckets require strict access controls).'
            else b.name || ' has appropriate access controls.'
          end as reason,
          b.account_id
        from
          aws_s3_bucket as b
          left join exempt_buckets as e on b.arn = e.arn
          left join expired_buckets as eb on b.arn = eb.arn
        where
          b.name like '%log%' or b.name like '%trail%' or b.name like '%audit%'
  EOQ
}

query "ksi_mla_08_2_aws_check" {
  sql = <<-EOQ
        with exempt_log_groups as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-08' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-08.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:logs:%:log-group:%'
        ),
        expired_log_groups as (
          select arn from exempt_log_groups
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check log groups have KMS encryption (protect log data at rest)
        select
          lg.arn as resource,
          case
            when elg.arn is not null then 'alarm'
            when e.arn is not null and elg.arn is null then 'skip'
            when lg.kms_key_id is null then 'alarm'
            else 'ok'
          end as status,
          case
            when elg.arn is not null
              then lg.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then lg.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when lg.kms_key_id is null
              then lg.name || ' does NOT have KMS encryption (log data unprotected at rest).'
            else lg.name || ' has KMS encryption enabled (protects log data at rest).'
          end as reason,
          lg.account_id
        from
          aws_cloudwatch_log_group as lg
          left join exempt_log_groups as e on lg.arn = e.arn
          left join expired_log_groups as elg on lg.arn = elg.arn
  EOQ
}
