# KSI-TPR: Third-Party Resources Queries - AWS

query "ksi_tpr_03_aws_check" {
  sql = <<-EOQ
    -- KSI-TPR-03: Supply Chain Risk Management
    -- Identify and mitigate supply chain risks

    -- Check ECR repositories have vulnerability scanning enabled
    select
      arn as resource,
      case
        when image_scanning_configuration ->> 'scanOnPush' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when image_scanning_configuration ->> 'scanOnPush' = 'true'
          then repository_name || ' has vulnerability scanning enabled (identifies vulnerable dependencies).'
        else repository_name || ' does NOT have vulnerability scanning enabled.'
      end as reason,
      account_id
    from
      aws_ecr_repository

    union all

    -- Check Inspector2 coverage for workload vulnerability detection
    -- Note: Access may be denied if Inspector2 is not enabled
    select
      'arn:aws:inspector2:' || region || ':' || account_id || ':resource/' || resource_type as resource,
      case
        when status = 'ACTIVE' then 'ok'
        else 'alarm'
      end as status,
      case
        when status = 'ACTIVE' then resource_type || ' has active Inspector2 coverage for vulnerability detection.'
        else resource_type || ' does NOT have active Inspector2 coverage (status: ' || status || ').'
      end as reason,
      account_id
    from
      aws_inspector2_coverage
  EOQ
}

query "ksi_tpr_04_aws_check" {
  sql = <<-EOQ
    -- KSI-TPR-04: Supply Chain Risk Monitoring
    -- Automatically monitor for upstream vulnerabilities

    -- Check ECR repositories have automated scan-on-push for continuous monitoring
    select
      arn as resource,
      case
        when image_scanning_configuration ->> 'scanOnPush' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when image_scanning_configuration ->> 'scanOnPush' = 'true'
          then repository_name || ' has automated vulnerability scanning (scan-on-push enabled).'
        else repository_name || ' does NOT have automated vulnerability scanning.'
      end as reason,
      account_id
    from
      aws_ecr_repository

    union all

    -- Check Inspector2 provides continuous vulnerability monitoring
    -- Note: Access may be denied if Inspector2 is not enabled
    select
      'arn:aws:inspector2:' || region || ':' || account_id || ':summary' as resource,
      case
        when count(*) filter (where status = 'ACTIVE') > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when count(*) filter (where status = 'ACTIVE') > 0
          then 'Inspector2 is actively monitoring ' || count(*) filter (where status = 'ACTIVE') || ' resource types for vulnerabilities.'
        else 'Inspector2 is NOT actively monitoring resources for vulnerabilities.'
      end as reason,
      max(account_id) as account_id
    from
      aws_inspector2_coverage
    group by
      region, account_id
  EOQ
}
