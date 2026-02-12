# KSI-INR: Incident Response Queries - AWS

query "ksi_inr_01_1_aws_check" {
  sql = <<-EOQ
    -- KSI-INR-01: Incident Response Procedures
        -- Maintain effective incident response capabilities
    
    -- Check GuardDuty enabled for incident detection
        -- Note: GuardDuty detectors are account-level resources, no resource-level exemptions
        select
          'arn:aws:guardduty:' || region || ':' || account_id || ':detector/' || detector_id as resource,
          case
            when status = 'ENABLED' then 'ok'
            else 'alarm'
          end as status,
          case
            when status = 'ENABLED'
              then 'GuardDuty detector ' || detector_id || ' is enabled (finding_publishing_frequency: ' ||
                finding_publishing_frequency || ', triggers IR procedures).'
            else 'GuardDuty detector ' || detector_id || ' is NOT enabled (access may be denied, verify via AWS Console).'
          end as reason,
          account_id
        from
          aws_guardduty_detector
  EOQ
}

query "ksi_inr_01_2_aws_check" {
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
              and ('KSI-INR-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-INR-01.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:logs:%:log-group:%'
        ),
        expired_log_groups as (
          select arn from exempt_log_groups
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check CloudWatch log groups have sufficient retention for incident investigation
        select
          lg.arn as resource,
          case
            when elg.arn is not null then 'alarm'
            when e.arn is not null and elg.arn is null then 'skip'
            when lg.retention_in_days is null or lg.retention_in_days < 365 then 'alarm'
            else 'ok'
          end as status,
          case
            when elg.arn is not null
              then lg.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then lg.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when lg.retention_in_days is null
              then lg.name || ' has NO retention policy set (logs may be deleted, compromising incident investigation).'
            when lg.retention_in_days < 365
              then lg.name || ' has only ' || lg.retention_in_days || ' days retention (recommend 365+ days for incident investigation).'
            else lg.name || ' has ' || lg.retention_in_days || ' days retention (sufficient for incident investigation).'
          end as reason,
          lg.account_id
        from
          aws_cloudwatch_log_group as lg
          left join exempt_log_groups as e on lg.arn = e.arn
          left join expired_log_groups as elg on lg.arn = elg.arn
  EOQ
}
