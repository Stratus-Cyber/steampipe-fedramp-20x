# KSI-INR: Incident Response Queries - AWS

query "ksi_inr_01_aws_check" {
  sql = <<-EOQ
    -- Check GuardDuty enabled (foundational_security_guardduty_1)
    select
      'arn:aws:guardduty:' || region || ':' || account_id || ':detector/' || detector_id as resource,
      case
        when status = 'ENABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when status = 'ENABLED' then 'GuardDuty is enabled in ' || region || '.'
        else 'GuardDuty is not enabled in ' || region || '.'
      end as reason,
      account_id
    from
      aws_guardduty_detector

    union all

    -- Check SecurityHub enabled (foundational_security_securityhub_1)
    select
      hub_arn as resource,
      case
        when hub_arn is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when hub_arn is not null then 'SecurityHub is enabled in ' || region || '.'
        else 'SecurityHub is not enabled in ' || region || '.'
      end as reason,
      account_id
    from
      aws_securityhub_hub

    union all

    -- Check SNS topic for CloudWatch alarms (basic incident notification)
    select
      topic_arn as resource,
      case
        when subscriptions_confirmed > 0 then 'ok'
        else 'info'
      end as status,
      case
        when subscriptions_confirmed > 0 then title || ' has ' || subscriptions_confirmed || ' confirmed subscriptions.'
        else title || ' has no confirmed subscriptions.'
      end as reason,
      account_id
    from
      aws_sns_topic
    where
      topic_arn like '%alarm%' or topic_arn like '%alert%' or topic_arn like '%notification%'

    union all

    -- Check CloudWatch log groups retention (for incident investigation)
    select
      arn as resource,
      case
        when retention_in_days >= 90 then 'ok'
        when retention_in_days > 0 then 'info'
        else 'alarm'
      end as status,
      case
        when retention_in_days >= 90 then name || ' has ' || retention_in_days || ' days retention.'
        when retention_in_days > 0 then name || ' has only ' || retention_in_days || ' days retention (recommend 90+).'
        else name || ' has no retention policy set.'
      end as reason,
      account_id
    from
      aws_cloudwatch_log_group
  EOQ
}
