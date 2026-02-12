# KSI-TPR: Third-Party Resources Queries - AWS

query "ksi_tpr_03_aws_check" {
  sql = <<-EOQ
    -- KSI-TPR-03: Supply Chain Risk Management
    -- Identify and mitigate supply chain risks

    with exempt_ecr as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_tagging_resource
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-TPR-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
        and arn like 'arn:aws:ecr:%:repository/%'
    ),
    expired_ecr as (
      select arn from exempt_ecr
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check ECR repositories have vulnerability scanning enabled
    select
      r.arn as resource,
      case
        when ee.arn is not null then 'alarm'
        when e.arn is not null and ee.arn is null then 'skip'
        when r.image_scanning_configuration ->> 'scanOnPush' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when ee.arn is not null
          then r.repository_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then r.repository_name || ' is exempt.', 'Not specified')
        when r.image_scanning_configuration ->> 'scanOnPush' = 'true'
          then r.repository_name || ' has vulnerability scanning enabled (identifies vulnerable dependencies).'
        else r.repository_name || ' does NOT have vulnerability scanning enabled.'
      end as reason,
      r.account_id
    from
      aws_ecr_repository as r
      left join exempt_ecr as e on r.arn = e.arn
      left join expired_ecr as ee on r.arn = ee.arn

    union all

    -- Check Inspector2 coverage for workload vulnerability detection
    -- Note: Inspector2 is account-level service, no resource-level exemptions
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

    with exempt_ecr as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_tagging_resource
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-TPR-04' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
        and arn like 'arn:aws:ecr:%:repository/%'
    ),
    expired_ecr as (
      select arn from exempt_ecr
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check ECR repositories have automated scan-on-push for continuous monitoring
    select
      r.arn as resource,
      case
        when ee.arn is not null then 'alarm'
        when e.arn is not null and ee.arn is null then 'skip'
        when r.image_scanning_configuration ->> 'scanOnPush' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when ee.arn is not null
          then r.repository_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then r.repository_name || ' is exempt.', 'Not specified')
        when r.image_scanning_configuration ->> 'scanOnPush' = 'true'
          then r.repository_name || ' has automated vulnerability scanning (scan-on-push enabled).'
        else r.repository_name || ' does NOT have automated vulnerability scanning.'
      end as reason,
      r.account_id
    from
      aws_ecr_repository as r
      left join exempt_ecr as e on r.arn = e.arn
      left join expired_ecr as ee on r.arn = ee.arn

    union all

    -- Check Inspector2 provides continuous vulnerability monitoring
    -- Note: Inspector2 is account-level service, no resource-level exemptions
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
