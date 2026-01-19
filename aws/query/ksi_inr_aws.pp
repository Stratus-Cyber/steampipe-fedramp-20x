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
      region,
      account_id
    from
      aws_guardduty_detector

    union all

    -- Check Inspector enabled for EC2 (foundational_security_inspector_1)
    select
      'arn:aws:inspector2:' || r.region || ':' || a.account_id || ':inspector2' as resource,
      case
        when r.ec2 ->> 'Status' = 'ENABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when r.ec2 ->> 'Status' = 'ENABLED' then 'Inspector EC2 scanning is enabled in ' || r.region || '.'
        else 'Inspector EC2 scanning is not enabled in ' || r.region || '.'
      end as reason,
      r.region,
      a.account_id
    from
      aws_inspector2_coverage_statistics as r,
      aws_account as a

    union all

    -- Check Inspector enabled for ECR (foundational_security_inspector_2)
    select
      'arn:aws:inspector2:' || r.region || ':' || a.account_id || ':inspector2' as resource,
      case
        when r.ecr ->> 'Status' = 'ENABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when r.ecr ->> 'Status' = 'ENABLED' then 'Inspector ECR scanning is enabled in ' || r.region || '.'
        else 'Inspector ECR scanning is not enabled in ' || r.region || '.'
      end as reason,
      r.region,
      a.account_id
    from
      aws_inspector2_coverage_statistics as r,
      aws_account as a

    union all

    -- Check Inspector enabled for Lambda (foundational_security_inspector_3)
    select
      'arn:aws:inspector2:' || r.region || ':' || a.account_id || ':inspector2' as resource,
      case
        when r.lambda ->> 'Status' = 'ENABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when r.lambda ->> 'Status' = 'ENABLED' then 'Inspector Lambda scanning is enabled in ' || r.region || '.'
        else 'Inspector Lambda scanning is not enabled in ' || r.region || '.'
      end as reason,
      r.region,
      a.account_id
    from
      aws_inspector2_coverage_statistics as r,
      aws_account as a
  EOQ
}
