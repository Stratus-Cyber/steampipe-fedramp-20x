# KSI-MLA: Monitoring, Logging, Auditing Queries - AWS

query "ksi_mla_01_aws_check" {
  sql = <<-EOQ
    -- KSI-MLA-01: SIEM / Centralized Logging
    -- Operate centralized, tamper-resistant logging

    -- Check CloudTrail trails have log integrity validation (tamper-resistant)
    select
      arn as resource,
      case
        when log_file_validation_enabled = false then 'alarm'
        else 'ok'
      end as status,
      case
        when log_file_validation_enabled = false
          then name || ' does NOT have log file validation enabled (logs lack integrity protection).'
        else name || ' has log file validation enabled (ensures audit trail integrity).'
      end as reason,
      account_id
    from
      aws_cloudtrail_trail

    union all

    -- Check CloudWatch log groups are encrypted (protect sensitive audit data)
    select
      arn as resource,
      case
        when kms_key_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when kms_key_id is null
          then name || ' is NOT encrypted (SIEM data should be protected with KMS encryption).'
        else name || ' is encrypted with KMS key ' || kms_key_id || ' (protects sensitive audit data).'
      end as reason,
      account_id
    from
      aws_cloudwatch_log_group

    union all

    -- Check Security Lake status (centralizes security telemetry)
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

    union all

    -- Check log buckets have access logging enabled (detect unauthorized access)
    select
      arn as resource,
      case
        when (name like '%log%' or name like '%trail%' or name like '%audit%') and logging is null then 'alarm'
        else 'ok'
      end as status,
      case
        when (name like '%log%' or name like '%trail%' or name like '%audit%') and logging is null
          then name || ' is a log bucket WITHOUT access logging (cannot detect unauthorized access to logs).'
        else name || ' has appropriate access logging configuration.'
      end as reason,
      account_id
    from
      aws_s3_bucket
    where
      name like '%log%' or name like '%trail%' or name like '%audit%'
  EOQ
}

query "ksi_mla_02_aws_check" {
  sql = <<-EOQ
    -- KSI-MLA-02: Audit Logging
    -- Retain and review logs regularly

    -- Check CloudTrail trails have comprehensive coverage
    select
      arn as resource,
      case
        when not (is_logging = true and is_multi_region_trail = true and include_global_service_events = true) then 'alarm'
        else 'ok'
      end as status,
      case
        when not (is_logging = true and is_multi_region_trail = true and include_global_service_events = true)
          then name || ' lacks comprehensive audit coverage: ' ||
            case when not is_logging then 'NOT logging ' else '' end ||
            case when not is_multi_region_trail then 'NOT multi-region ' else '' end ||
            case when not include_global_service_events then 'NO global service events' else '' end
        else name || ' has comprehensive audit logging (multi-region with global service events).'
      end as reason,
      account_id
    from
      aws_cloudtrail_trail
  EOQ
}

query "ksi_mla_05_aws_check" {
  sql = <<-EOQ
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

    union all

    -- Check Config rules compliance status (aggregate configuration posture view)
    select
      arn as resource,
      case
        when compliance_status = 'NON_COMPLIANT' then 'alarm'
        else 'ok'
      end as status,
      case
        when compliance_status = 'NON_COMPLIANT'
          then 'Config rule ' || name || ' is NON_COMPLIANT (configuration drift detected).'
        else 'Config rule ' || name || ' is compliant.'
      end as reason,
      account_id
    from
      aws_config_rule
  EOQ
}

query "ksi_mla_07_aws_check" {
  sql = <<-EOQ
    -- KSI-MLA-07: Event Type Coverage
    -- Log required event types comprehensively

    -- Check CloudTrail trails have complete event coverage
    select
      arn as resource,
      case
        when is_multi_region_trail = false or include_global_service_events = false then 'alarm'
        else 'ok'
      end as status,
      case
        when is_multi_region_trail = false or include_global_service_events = false
          then name || ' has incomplete event coverage: ' ||
            case when is_multi_region_trail = false then 'NOT multi-region ' else '' end ||
            case when include_global_service_events = false then 'NO global service events' else '' end ||
            ' (event selectors define scope; multi-region and global services required).'
        else name || ' has complete event type coverage (multi-region with global service events).'
      end as reason,
      account_id
    from
      aws_cloudtrail_trail
  EOQ
}

query "ksi_mla_08_aws_check" {
  sql = <<-EOQ
    -- KSI-MLA-08: Log Data Access Control
    -- Restrict access to log data using least privilege

    -- Check log buckets don't have overly permissive ACLs
    select
      arn as resource,
      case
        when (name like '%log%' or name like '%trail%' or name like '%audit%')
          and (acl ->> 'Grants')::jsonb @> '[{"Permission": "FULL_CONTROL"}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when (name like '%log%' or name like '%trail%' or name like '%audit%')
          and (acl ->> 'Grants')::jsonb @> '[{"Permission": "FULL_CONTROL"}]'
          then name || ' is a log bucket with overly permissive ACLs (log buckets require strict access controls).'
        else name || ' has appropriate access controls.'
      end as reason,
      account_id
    from
      aws_s3_bucket
    where
      name like '%log%' or name like '%trail%' or name like '%audit%'

    union all

    -- Check log groups have KMS encryption (protect log data at rest)
    select
      arn as resource,
      case
        when kms_key_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when kms_key_id is null
          then name || ' does NOT have KMS encryption (log data unprotected at rest).'
        else name || ' has KMS encryption enabled (protects log data at rest).'
      end as reason,
      account_id
    from
      aws_cloudwatch_log_group
  EOQ
}
