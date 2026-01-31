# KSI-SVC: Service Configuration Queries - AWS

query "ksi_svc_01_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-01: Continuous Improvement
    -- Continuously improve security based on evaluations

    -- Check Lambda functions for deprecated runtimes (indicates lack of continuous improvement)
    select
      arn as resource,
      case
        when runtime in ('python2.7', 'python3.6', 'nodejs10.x', 'nodejs12.x', 'dotnetcore2.1') then 'alarm'
        else 'ok'
      end as status,
      case
        when runtime in ('python2.7', 'python3.6', 'nodejs10.x', 'nodejs12.x', 'dotnetcore2.1')
          then name || ' uses deprecated runtime ' || runtime || ' (indicates lack of continuous improvement).'
        else name || ' uses supported runtime ' || runtime || '.'
      end as reason,
      account_id
    from
      aws_lambda_function

    union all

    -- Check RDS instances have auto minor version upgrade enabled
    select
      arn as resource,
      case
        when auto_minor_version_upgrade = false then 'alarm'
        else 'ok'
      end as status,
      case
        when auto_minor_version_upgrade = false
          then db_instance_identifier || ' does NOT have auto minor version upgrade enabled (auto version upgrade ensures continuous improvement).'
        else db_instance_identifier || ' has auto minor version upgrade enabled (' || engine || ' ' || engine_version || ').'
      end as reason,
      account_id
    from
      aws_rds_db_instance
  EOQ
}

query "ksi_svc_02_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-02: Network Encryption
    -- Encrypt network traffic in transit

    -- Check ACM certificates expiring within 30 days (risks encryption gaps)
    select
      certificate_arn as resource,
      case
        when status = 'ISSUED' and not_after < now() + interval '30 days' then 'alarm'
        else 'ok'
      end as status,
      case
        when status = 'ISSUED' and not_after < now() + interval '30 days'
          then domain_name || ' certificate expires in ' ||
            extract(day from not_after - now())::int || ' days (expiring certificates risk encryption gaps).'
        else domain_name || ' certificate is valid until ' || not_after::date || '.'
      end as reason,
      account_id
    from
      aws_acm_certificate
    where
      status = 'ISSUED'

    union all

    -- Check for HTTP (unencrypted) load balancer listeners
    select
      load_balancer_arn as resource,
      case
        when protocol = 'HTTP' then 'alarm'
        else 'ok'
      end as status,
      case
        when protocol = 'HTTP'
          then 'Listener on port ' || port || ' uses HTTP (unencrypted, all traffic should use HTTPS).'
        else 'Listener on port ' || port || ' uses ' || protocol || ' (encrypted).'
      end as reason,
      account_id
    from
      aws_ec2_load_balancer_listener

    union all

    -- Check HTTPS/TLS listeners use TLS 1.2+ policy
    select
      load_balancer_arn as resource,
      case
        when protocol in ('HTTPS', 'TLS') and ssl_policy not like '%TLS-1-2%' then 'alarm'
        else 'ok'
      end as status,
      case
        when protocol in ('HTTPS', 'TLS') and ssl_policy not like '%TLS-1-2%'
          then 'Listener on port ' || port || ' uses ' || protocol || ' but SSL policy ' ||
            coalesce(ssl_policy, 'default') || ' does NOT enforce TLS 1.2 minimum.'
        else 'Listener on port ' || port || ' uses ' || protocol || ' with appropriate SSL policy.'
      end as reason,
      account_id
    from
      aws_ec2_load_balancer_listener
    where
      protocol in ('HTTPS', 'TLS')

    union all

    -- Check RDS instances have SSL certificate configured
    select
      arn as resource,
      case
        when ca_cert_identifier is null then 'alarm'
        else 'ok'
      end as status,
      case
        when ca_cert_identifier is null
          then db_instance_identifier || ' does NOT have SSL certificate configured (RDS should have SSL for encrypted connections).'
        else db_instance_identifier || ' has SSL certificate configured: ' || ca_cert_identifier || '.'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check ElastiCache replication groups have transit encryption enabled
    select
      arn as resource,
      case
        when transit_encryption_enabled = false then 'alarm'
        else 'ok'
      end as status,
      case
        when transit_encryption_enabled = false
          then replication_group_id || ' does NOT have transit encryption enabled (required for data in motion).'
        else replication_group_id || ' has transit encryption enabled.'
      end as reason,
      account_id
    from
      aws_elasticache_replication_group
  EOQ
}

query "ksi_svc_04_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-04: Configuration Automation
    -- Manage configuration using automation

    -- Check ASGs use launch templates (not deprecated launch configurations)
    select
      autoscaling_group_arn as resource,
      case
        when launch_template is null and launch_configuration_name is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when launch_template is null and launch_configuration_name is not null
          then autoscaling_group_name || ' uses deprecated launch configuration (launch templates preferred for configuration automation).'
        else autoscaling_group_name || ' uses launch template (supports configuration automation).'
      end as reason,
      account_id
    from
      aws_ec2_autoscaling_group

    union all

    -- Check CloudFormation stacks in failed or rollback state (indicates configuration automation issues)
    select
      id as resource,
      case
        when stack_status like '%FAILED%' or stack_status like '%ROLLBACK%' then 'alarm'
        else 'ok'
      end as status,
      case
        when stack_status like '%FAILED%' or stack_status like '%ROLLBACK%'
          then stack_name || ' is in ' || stack_status || ' state (indicates configuration automation issues).'
        else stack_name || ' is in ' || stack_status || ' state.'
      end as reason,
      account_id
    from
      aws_cloudformation_stack

    union all

    -- Check Config rules for non-compliance (indicates configuration drift)
    select
      arn as resource,
      case
        when compliance_status = 'NON_COMPLIANT' then 'alarm'
        else 'ok'
      end as status,
      case
        when compliance_status = 'NON_COMPLIANT'
          then 'Config rule ' || name || ' is NON_COMPLIANT (Config rules automate configuration validation, drift detected).'
        else 'Config rule ' || name || ' is compliant.'
      end as reason,
      account_id
    from
      aws_config_rule
  EOQ
}

query "ksi_svc_05_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-05: Resource Integrity
    -- Validate integrity of resources using cryptographic methods

    -- Check CloudTrail trails have log file integrity validation
    select
      arn as resource,
      case
        when log_file_validation_enabled = false then 'alarm'
        else 'ok'
      end as status,
      case
        when log_file_validation_enabled = false
          then name || ' does NOT have log file validation enabled (log validation ensures audit trail integrity).'
        else name || ' has log file validation enabled (ensures audit trail integrity).'
      end as reason,
      account_id
    from
      aws_cloudtrail_trail

    union all

    -- Check ECR repositories have scan-on-push for image integrity
    select
      arn as resource,
      case
        when image_scanning_configuration ->> 'scanOnPush' = 'false' then 'alarm'
        else 'ok'
      end as status,
      case
        when image_scanning_configuration ->> 'scanOnPush' = 'false'
          then repository_name || ' does NOT have scan-on-push enabled (image scanning validates container integrity).'
        else repository_name || ' has scan-on-push enabled (validates container integrity).'
      end as reason,
      account_id
    from
      aws_ecr_repository

    union all

    -- Check critical buckets have object lock protection for integrity
    select
      arn as resource,
      case
        when (name like '%backup%' or name like '%archive%' or name like '%audit%' or name like '%log%')
          and object_lock_configuration is null then 'alarm'
        else 'ok'
      end as status,
      case
        when (name like '%backup%' or name like '%archive%' or name like '%audit%' or name like '%log%')
          and object_lock_configuration is null
          then name || ' is a critical data bucket WITHOUT object lock protection (critical data buckets should have object lock for integrity).'
        else name || ' has appropriate integrity protection.'
      end as reason,
      account_id
    from
      aws_s3_bucket
    where
      name like '%backup%' or name like '%archive%' or name like '%audit%' or name like '%log%'
  EOQ
}

query "ksi_svc_06_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-06: Secret Management
    -- Automate secret rotation and protection

    -- Check customer-managed KMS keys have automatic rotation enabled
    select
      arn as resource,
      case
        when key_rotation_enabled = false then 'alarm'
        else 'ok'
      end as status,
      case
        when key_rotation_enabled = false
          then id || ' is a customer-managed key WITHOUT automatic rotation (key rotation required for secret management best practices).'
        else id || ' has automatic key rotation enabled.'
      end as reason,
      account_id
    from
      aws_kms_key
    where
      key_state = 'Enabled'
      and key_manager = 'CUSTOMER'
  EOQ
}

query "ksi_svc_08_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-08: Prevent Residual Risk
    -- Detect and remove orphaned resources with residual data

    -- Check for unattached EBS volumes (may contain residual data)
    select
      arn as resource,
      case
        when state = 'available' then 'alarm'
        else 'ok'
      end as status,
      case
        when state = 'available'
          then volume_id || ' is unattached and may contain residual data (created ' ||
            extract(day from now() - create_time)::int || ' days ago, should be reviewed and deleted).'
        else volume_id || ' is attached to instance.'
      end as reason,
      account_id
    from
      aws_ebs_volume

    union all

    -- Check for unused Elastic IPs (residual infrastructure)
    select
      'arn:aws:ec2:' || region || ':' || account_id || ':eip/' || allocation_id as resource,
      case
        when association_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when association_id is null
          then 'Elastic IP ' || coalesce(public_ip, allocation_id) || ' is unused (residual infrastructure, indicates incomplete cleanup).'
        else 'Elastic IP ' || public_ip || ' is associated with ' || association_id || '.'
      end as reason,
      account_id
    from
      aws_vpc_eip

    union all

    -- Check for old AMIs (> 180 days) that may be stale
    select
      image_id as resource,
      case
        when creation_date < now() - interval '180 days' then 'info'
        else 'ok'
      end as status,
      case
        when creation_date < now() - interval '180 days'
          then name || ' AMI is ' || extract(day from now() - creation_date)::int ||
            ' days old (old AMIs may contain outdated/vulnerable software).'
        else name || ' AMI is recent (' || extract(day from now() - creation_date)::int || ' days old).'
      end as reason,
      account_id
    from
      aws_ec2_ami
    where
      creation_date < now() - interval '180 days'

    union all

    -- Check for orphaned security groups not attached to any network interface
    select
      'arn:aws:ec2:' || region || ':' || account_id || ':security-group/' || sg.group_id as resource,
      'info' as status,
      sg.group_name || ' is an orphaned security group not attached to any ENI (unused security groups should be cleaned up).' as reason,
      sg.account_id
    from
      aws_vpc_security_group sg
      left join aws_ec2_network_interface eni on sg.group_id = any(eni.groups)
    where
      eni.network_interface_id is null
      and sg.group_name != 'default'

    union all

    -- Check for IAM roles unused for 90+ days (stale roles should be removed)
    select
      arn as resource,
      case
        when path not like '/aws-service-role/%'
          and (role_last_used_date is null or role_last_used_date < now() - interval '90 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when path not like '/aws-service-role/%' and role_last_used_date is null
          then name || ' has NEVER been used (stale role, should be reviewed and removed).'
        when path not like '/aws-service-role/%' and role_last_used_date < now() - interval '90 days'
          then name || ' has not been used for ' || extract(day from now() - role_last_used_date)::int ||
            ' days (stale role, should be reviewed and removed).'
        else name || ' is actively used.'
      end as reason,
      account_id
    from
      aws_iam_role
    where
      path not like '/aws-service-role/%'
  EOQ
}

query "ksi_svc_09_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-09: Communication Integrity
    -- Verify inter-service communication authentication

    -- Check certificates are in ISSUED status (must be valid for communication integrity)
    select
      certificate_arn as resource,
      case
        when status = 'ISSUED' then 'ok'
        else 'alarm'
      end as status,
      case
        when status = 'ISSUED'
          then domain_name || ' certificate is issued and valid.'
        else domain_name || ' certificate is NOT in ISSUED status: ' || status || ' (certificates must be valid for communication integrity).'
      end as reason,
      account_id
    from
      aws_acm_certificate

    union all

    -- Check listeners are encrypted (validates perimeter TLS; service-to-service mTLS requires architecture review)
    select
      load_balancer_arn as resource,
      case
        when protocol = 'HTTP' then 'alarm'
        else 'ok'
      end as status,
      case
        when protocol = 'HTTP'
          then 'Listener on port ' || port || ' uses HTTP (unencrypted, lacks communication integrity; validates perimeter TLS; service-to-service mTLS requires architecture review).'
        else 'Listener on port ' || port || ' uses ' || protocol || ' (encrypted).'
      end as reason,
      account_id
    from
      aws_ec2_load_balancer_listener

    union all

    -- Check App Mesh services have backend configuration (enables mTLS for inter-service communication)
    select
      'arn:aws:appmesh:' || region || ':' || account_id || ':mesh/' || mesh_name || '/virtualService/' || virtual_service_name as resource,
      case
        when spec ->> 'backends' is null then 'info'
        else 'ok'
      end as status,
      case
        when spec ->> 'backends' is null
          then virtual_service_name || ' in mesh ' || mesh_name || ' does NOT have backend configuration (App Mesh enables mTLS for inter-service communication if deployed).'
        else virtual_service_name || ' has backend configuration.'
      end as reason,
      account_id
    from
      aws_appmesh_virtual_service
  EOQ
}

query "ksi_svc_10_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-10: Unwanted Data Removal
    -- Enable data lifecycle management and removal capability

    -- Check S3 buckets have lifecycle policies (automate data deletion)
    select
      arn as resource,
      case
        when lifecycle_rules is null then 'alarm'
        else 'ok'
      end as status,
      case
        when lifecycle_rules is null
          then name || ' does NOT have lifecycle policies configured (lifecycle rules automate data deletion).'
        else name || ' has lifecycle policies configured.'
      end as reason,
      account_id
    from
      aws_s3_bucket

    union all

    -- Check DynamoDB tables have TTL configured (enables automatic data removal)
    select
      arn as resource,
      case
        when ttl ->> 'AttributeName' is null then 'alarm'
        else 'ok'
      end as status,
      case
        when ttl ->> 'AttributeName' is null
          then name || ' does NOT have TTL configured (TTL enables automatic data removal).'
        else name || ' has TTL configured on attribute ' || (ttl ->> 'AttributeName') || '.'
      end as reason,
      account_id
    from
      aws_dynamodb_table
  EOQ
}
