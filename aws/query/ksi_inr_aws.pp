# KSI-INR: Incident Response Queries - AWS

query "ksi_inr_01_aws_check" {
  sql = <<-EOQ
    -- KSI-INR-01: Incident Response Procedures
    -- Maintain effective incident response capabilities

    -- Check GuardDuty enabled for incident detection
    -- Note: Access may be denied if GuardDuty is not enabled
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

    union all

    -- Check CloudWatch log groups have sufficient retention for incident investigation
    select
      arn as resource,
      case
        when retention_in_days is null or retention_in_days < 365 then 'alarm'
        else 'ok'
      end as status,
      case
        when retention_in_days is null
          then name || ' has NO retention policy set (logs may be deleted, compromising incident investigation).'
        when retention_in_days < 365
          then name || ' has only ' || retention_in_days || ' days retention (recommend 365+ days for incident investigation).'
        else name || ' has ' || retention_in_days || ' days retention (sufficient for incident investigation).'
      end as reason,
      account_id
    from
      aws_cloudwatch_log_group
  EOQ
}
