# KSI-AFR: Authorization by FedRAMP Queries - AWS

query "ksi_afr_04_aws_check" {
  sql = <<-EOQ
    -- KSI-AFR-04: Vulnerability Detection and Response
    -- Implement and document vulnerability scanning methodology

    with exempt_ecr as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_tagging_resource
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-AFR-04' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
        and arn like 'arn:aws:ecr:%:repository/%'
    ),
    expired_ecr as (
      select arn from exempt_ecr
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check Inspector2 coverage for all resource types
    -- Note: Inspector2 is account-level service, no resource-level exemptions
    select
      'arn:aws:inspector2:' || region || ':' || account_id || ':resource/' || resource_type as resource,
      case
        when status = 'ACTIVE' then 'ok'
        else 'alarm'
      end as status,
      case
        when status = 'ACTIVE' then resource_type || ' has active Inspector2 coverage.'
        else resource_type || ' does NOT have active Inspector2 coverage (status: ' || status || ').'
      end as reason,
      account_id
    from
      aws_inspector2_coverage

    union all

    -- Check ECR repositories have scan-on-push enabled
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
        when r.image_scanning_configuration ->> 'scanOnPush' = 'true' then r.repository_name || ' has vulnerability scanning enabled (scan-on-push).'
        else r.repository_name || ' does NOT have vulnerability scanning enabled.'
      end as reason,
      r.account_id
    from
      aws_ecr_repository as r
      left join exempt_ecr as e on r.arn = e.arn
      left join expired_ecr as ee on r.arn = ee.arn
  EOQ
}

query "ksi_afr_11_aws_check" {
  sql = <<-EOQ
    -- KSI-AFR-11: Using Cryptographic Modules
    -- Use FIPS-validated cryptographic modules
    -- Note: GovCloud KMS uses FIPS 140-2 validated modules

    with exempt_kms as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_tagging_resource
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-AFR-11' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
        and arn like 'arn:aws:kms:%:key/%'
    ),
    expired_kms as (
      select arn from exempt_kms
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_buckets as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_tagging_resource
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-AFR-11' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
        and arn like 'arn:aws:s3:::%'
    ),
    expired_buckets as (
      select arn from exempt_buckets
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_volumes as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_tagging_resource
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-AFR-11' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
        and arn like 'arn:aws:ec2:%:volume/%'
    ),
    expired_volumes as (
      select arn from exempt_volumes
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check customer-managed KMS keys have rotation enabled
    select
      k.arn as resource,
      case
        when ek.arn is not null then 'alarm'
        when e.arn is not null and ek.arn is null then 'skip'
        when k.key_rotation_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when ek.arn is not null
          then k.id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then k.id || ' is exempt.', 'Not specified')
        when k.key_rotation_enabled then k.id || ' has automatic key rotation enabled.'
        else k.id || ' does NOT have automatic key rotation enabled.'
      end as reason,
      k.account_id
    from
      aws_kms_key as k
      left join exempt_kms as e on k.arn = e.arn
      left join expired_kms as ek on k.arn = ek.arn
    where
      k.key_state = 'Enabled'
      and k.key_manager = 'CUSTOMER'

    union all

    -- Check S3 buckets have default encryption configured
    select
      b.arn as resource,
      case
        when eb.arn is not null then 'alarm'
        when e.arn is not null and eb.arn is null then 'skip'
        when b.server_side_encryption_configuration is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when eb.arn is not null
          then b.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then b.name || ' is exempt.', 'Not specified')
        when b.server_side_encryption_configuration is not null then b.name || ' has default encryption configured.'
        else b.name || ' does NOT have default encryption configured.'
      end as reason,
      b.account_id
    from
      aws_s3_bucket as b
      left join exempt_buckets as e on b.arn = e.arn
      left join expired_buckets as eb on b.arn = eb.arn

    union all

    -- Check EBS volumes are encrypted
    select
      v.arn as resource,
      case
        when ev.arn is not null then 'alarm'
        when e.arn is not null and ev.arn is null then 'skip'
        when v.encrypted then 'ok'
        else 'alarm'
      end as status,
      case
        when ev.arn is not null
          then v.volume_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then v.volume_id || ' is exempt.', 'Not specified')
        when v.encrypted then v.volume_id || ' is encrypted at rest.'
        else v.volume_id || ' is NOT encrypted at rest.'
      end as reason,
      v.account_id
    from
      aws_ebs_volume as v
      left join exempt_volumes as e on v.arn = e.arn
      left join expired_volumes as ev on v.arn = ev.arn
  EOQ
}
