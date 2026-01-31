# KSI-AFR: Authorization by FedRAMP Queries - AWS

query "ksi_afr_04_aws_check" {
  sql = <<-EOQ
    -- KSI-AFR-04: Vulnerability Detection and Response
    -- Implement and document vulnerability scanning methodology

    -- Check Inspector2 coverage for all resource types
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
      arn as resource,
      case
        when image_scanning_configuration ->> 'scanOnPush' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when image_scanning_configuration ->> 'scanOnPush' = 'true' then repository_name || ' has vulnerability scanning enabled (scan-on-push).'
        else repository_name || ' does NOT have vulnerability scanning enabled.'
      end as reason,
      account_id
    from
      aws_ecr_repository
  EOQ
}

query "ksi_afr_11_aws_check" {
  sql = <<-EOQ
    -- KSI-AFR-11: Using Cryptographic Modules
    -- Use FIPS-validated cryptographic modules
    -- Note: GovCloud KMS uses FIPS 140-2 validated modules

    -- Check customer-managed KMS keys have rotation enabled
    select
      arn as resource,
      case
        when key_rotation_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when key_rotation_enabled then id || ' has automatic key rotation enabled.'
        else id || ' does NOT have automatic key rotation enabled.'
      end as reason,
      account_id
    from
      aws_kms_key
    where
      key_state = 'Enabled'
      and key_manager = 'CUSTOMER'

    union all

    -- Check S3 buckets have default encryption configured
    select
      arn as resource,
      case
        when server_side_encryption_configuration is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when server_side_encryption_configuration is not null then name || ' has default encryption configured.'
        else name || ' does NOT have default encryption configured.'
      end as reason,
      account_id
    from
      aws_s3_bucket

    union all

    -- Check EBS volumes are encrypted
    select
      arn as resource,
      case
        when encrypted then 'ok'
        else 'alarm'
      end as status,
      case
        when encrypted then volume_id || ' is encrypted at rest.'
        else volume_id || ' is NOT encrypted at rest.'
      end as reason,
      account_id
    from
      aws_ebs_volume
  EOQ
}
