# KSI-SVC: Service Configuration Queries - AWS

query "ksi_svc_01_1_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-01: Continuous Improvement
        -- Continuously improve security based on evaluations
    
        with exempt_lambdas as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_lambda_function
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-01.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_lambdas as (
          select arn from exempt_lambdas
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Lambda functions for deprecated runtimes (indicates lack of continuous improvement)
        select
          l.arn as resource,
          case
            when el.arn is not null then 'alarm'
            when e.arn is not null and el.arn is null then 'skip'
            when l.runtime in ('python2.7', 'python3.6', 'nodejs10.x', 'nodejs12.x', 'dotnetcore2.1') then 'alarm'
            else 'ok'
          end as status,
          case
            when el.arn is not null
              then l.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then l.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when l.runtime in ('python2.7', 'python3.6', 'nodejs10.x', 'nodejs12.x', 'dotnetcore2.1')
              then l.name || ' uses deprecated runtime ' || l.runtime || ' (indicates lack of continuous improvement).'
            else l.name || ' uses supported runtime ' || l.runtime || '.'
          end as reason,
          l.account_id
        from
          aws_lambda_function as l
          left join exempt_lambdas as e on l.arn = e.arn
          left join expired_lambdas as el on l.arn = el.arn
  EOQ
}

query "ksi_svc_01_2_aws_check" {
  sql = <<-EOQ
        with exempt_rds as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_rds_db_instance
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-01.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_rds as (
          select arn from exempt_rds
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check RDS instances have auto minor version upgrade enabled
        select
          r.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when r.auto_minor_version_upgrade = false then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then r.db_instance_identifier || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then r.db_instance_identifier || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.auto_minor_version_upgrade = false
              then r.db_instance_identifier || ' does NOT have auto minor version upgrade enabled (auto version upgrade ensures continuous improvement).'
            else r.db_instance_identifier || ' has auto minor version upgrade enabled (' || r.engine || ' ' || r.engine_version || ').'
          end as reason,
          r.account_id
        from
          aws_rds_db_instance as r
          left join exempt_rds as e on r.arn = e.arn
          left join expired_rds as er on r.arn = er.arn
  EOQ
}

query "ksi_svc_02_1_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-02: Network Encryption
        -- Encrypt network traffic in transit
    
        with exempt_certs as (
          select
            certificate_arn as arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_acm_certificate
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-02.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_certs as (
          select arn from exempt_certs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check ACM certificates expiring within 30 days (risks encryption gaps)
        select
          c.certificate_arn as resource,
          case
            when ec.arn is not null then 'alarm'
            when e.arn is not null and ec.arn is null then 'skip'
            when c.status = 'ISSUED' and c.not_after < now() + interval '30 days' then 'alarm'
            else 'ok'
          end as status,
          case
            when ec.arn is not null
              then c.domain_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then c.domain_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when c.status = 'ISSUED' and c.not_after < now() + interval '30 days'
              then c.domain_name || ' certificate expires in ' ||
                extract(day from c.not_after - now())::int || ' days (expiring certificates risk encryption gaps).'
            else c.domain_name || ' certificate is valid until ' || c.not_after::date || '.'
          end as reason,
          c.account_id
        from
          aws_acm_certificate as c
          left join exempt_certs as e on c.certificate_arn = e.arn
          left join expired_certs as ec on c.certificate_arn = ec.arn
        where
          c.status = 'ISSUED'
  EOQ
}

query "ksi_svc_02_2_aws_check" {
  sql = <<-EOQ
        with exempt_albs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ec2_application_load_balancer
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-02.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_albs as (
          select arn from exempt_albs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for HTTP (unencrypted) load balancer listeners
        select
          l.load_balancer_arn as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when l.protocol = 'HTTP' then 'alarm'
            else 'ok'
          end as status,
          case
            when ea.arn is not null
              then 'Listener has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'Listener is exempt.'
            when l.protocol = 'HTTP'
              then 'Listener on port ' || l.port || ' uses HTTP (unencrypted, all traffic should use HTTPS).'
            else 'Listener on port ' || l.port || ' uses ' || l.protocol || ' (encrypted).'
          end as reason,
          l.account_id
        from
          aws_ec2_load_balancer_listener as l
          left join exempt_albs as e on l.load_balancer_arn = e.arn
          left join expired_albs as ea on l.load_balancer_arn = ea.arn
  EOQ
}

query "ksi_svc_02_3_aws_check" {
  sql = <<-EOQ
        with exempt_albs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ec2_application_load_balancer
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-02.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_albs as (
          select arn from exempt_albs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check HTTPS/TLS listeners use TLS 1.2+ policy
        select
          l.load_balancer_arn as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when l.protocol in ('HTTPS', 'TLS') and l.ssl_policy not like '%TLS-1-2%' then 'alarm'
            else 'ok'
          end as status,
          case
            when ea.arn is not null
              then 'Listener has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'Listener is exempt.'
            when l.protocol in ('HTTPS', 'TLS') and l.ssl_policy not like '%TLS-1-2%'
              then 'Listener on port ' || l.port || ' uses ' || l.protocol || ' but SSL policy ' ||
                coalesce(l.ssl_policy, 'default') || ' does NOT enforce TLS 1.2 minimum.'
            else 'Listener on port ' || l.port || ' uses ' || l.protocol || ' with appropriate SSL policy.'
          end as reason,
          l.account_id
        from
          aws_ec2_load_balancer_listener as l
          left join exempt_albs as e on l.load_balancer_arn = e.arn
          left join expired_albs as ea on l.load_balancer_arn = ea.arn
        where
          l.protocol in ('HTTPS', 'TLS')
  EOQ
}

query "ksi_svc_02_4_aws_check" {
  sql = <<-EOQ
        with exempt_rds as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_rds_db_instance
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-02.4' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_rds as (
          select arn from exempt_rds
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check RDS instances have SSL certificate configured
        select
          r.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when r.ca_cert_identifier is null then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then r.db_instance_identifier || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then r.db_instance_identifier || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.ca_cert_identifier is null
              then r.db_instance_identifier || ' does NOT have SSL certificate configured (RDS should have SSL for encrypted connections).'
            else r.db_instance_identifier || ' has SSL certificate configured: ' || r.ca_cert_identifier || '.'
          end as reason,
          r.account_id
        from
          aws_rds_db_instance as r
          left join exempt_rds as e on r.arn = e.arn
          left join expired_rds as er on r.arn = er.arn
  EOQ
}

query "ksi_svc_02_5_aws_check" {
  sql = <<-EOQ
        with exempt_elasticache as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_elasticache_replication_group
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-02.5' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_elasticache as (
          select arn from exempt_elasticache
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check ElastiCache replication groups have transit encryption enabled
        select
          ec.arn as resource,
          case
            when ee.arn is not null then 'alarm'
            when e.arn is not null and ee.arn is null then 'skip'
            when ec.transit_encryption_enabled = false then 'alarm'
            else 'ok'
          end as status,
          case
            when ee.arn is not null
              then ec.replication_group_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then ec.replication_group_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when ec.transit_encryption_enabled = false
              then ec.replication_group_id || ' does NOT have transit encryption enabled (required for data in motion).'
            else ec.replication_group_id || ' has transit encryption enabled.'
          end as reason,
          ec.account_id
        from
          aws_elasticache_replication_group as ec
          left join exempt_elasticache as e on ec.arn = e.arn
          left join expired_elasticache as ee on ec.arn = ee.arn
  EOQ
}

query "ksi_svc_04_1_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-04: Configuration Automation
        -- Manage configuration using automation
    
        with exempt_asgs as (
          select
            autoscaling_group_arn as arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ec2_autoscaling_group
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-04' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-04.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_asgs as (
          select arn from exempt_asgs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check ASGs use launch templates (not deprecated launch configurations)
        select
          a.autoscaling_group_arn as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when a.launch_template is null and a.launch_configuration_name is not null then 'alarm'
            else 'ok'
          end as status,
          case
            when ea.arn is not null
              then a.autoscaling_group_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then a.autoscaling_group_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when a.launch_template is null and a.launch_configuration_name is not null
              then a.autoscaling_group_name || ' uses deprecated launch configuration (launch templates preferred for configuration automation).'
            else a.autoscaling_group_name || ' uses launch template (supports configuration automation).'
          end as reason,
          a.account_id
        from
          aws_ec2_autoscaling_group as a
          left join exempt_asgs as e on a.autoscaling_group_arn = e.arn
          left join expired_asgs as ea on a.autoscaling_group_arn = ea.arn
  EOQ
}

query "ksi_svc_04_2_aws_check" {
  sql = <<-EOQ
        with exempt_stacks as (
          select
            id as arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_cloudformation_stack
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-04' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-04.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_stacks as (
          select arn from exempt_stacks
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check CloudFormation stacks in failed or rollback state (indicates configuration automation issues)
        select
          s.id as resource,
          case
            when es.arn is not null then 'alarm'
            when e.arn is not null and es.arn is null then 'skip'
            when s.stack_status like '%FAILED%' or s.stack_status like '%ROLLBACK%' then 'alarm'
            else 'ok'
          end as status,
          case
            when es.arn is not null
              then s.stack_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then s.stack_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when s.stack_status like '%FAILED%' or s.stack_status like '%ROLLBACK%'
              then s.stack_name || ' is in ' || s.stack_status || ' state (indicates configuration automation issues).'
            else s.stack_name || ' is in ' || s.stack_status || ' state.'
          end as reason,
          s.account_id
        from
          aws_cloudformation_stack as s
          left join exempt_stacks as e on s.id = e.arn
          left join expired_stacks as es on s.id = es.arn
  EOQ
}

query "ksi_svc_04_3_aws_check" {
  sql = <<-EOQ
        with exempt_rules as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_config_rule
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-04' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-04.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_rules as (
          select arn from exempt_rules
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Config rules for non-compliance (indicates configuration drift)
        select
          r.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when r.compliance_status = 'NON_COMPLIANT' then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then 'Config rule ' || r.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'Config rule ' || r.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.compliance_status = 'NON_COMPLIANT'
              then 'Config rule ' || r.name || ' is NON_COMPLIANT (Config rules automate configuration validation, drift detected).'
            else 'Config rule ' || r.name || ' is compliant.'
          end as reason,
          r.account_id
        from
          aws_config_rule as r
          left join exempt_rules as e on r.arn = e.arn
          left join expired_rules as er on r.arn = er.arn
  EOQ
}

query "ksi_svc_05_1_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-05: Resource Integrity
        -- Validate integrity of resources using cryptographic methods
    
        with exempt_trails as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_cloudtrail_trail
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-05' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-05.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_trails as (
          select arn from exempt_trails
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check CloudTrail trails have log file integrity validation
        select
          t.arn as resource,
          case
            when et.arn is not null then 'alarm'
            when e.arn is not null and et.arn is null then 'skip'
            when t.log_file_validation_enabled = false then 'alarm'
            else 'ok'
          end as status,
          case
            when et.arn is not null
              then t.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then t.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when t.log_file_validation_enabled = false
              then t.name || ' does NOT have log file validation enabled (log validation ensures audit trail integrity).'
            else t.name || ' has log file validation enabled (ensures audit trail integrity).'
          end as reason,
          t.account_id
        from
          aws_cloudtrail_trail as t
          left join exempt_trails as e on t.arn = e.arn
          left join expired_trails as et on t.arn = et.arn
  EOQ
}

query "ksi_svc_05_2_aws_check" {
  sql = <<-EOQ
        with exempt_ecr as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ecr_repository
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-05' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-05.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_ecr as (
          select arn from exempt_ecr
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check ECR repositories have scan-on-push for image integrity
        select
          r.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when r.image_scanning_configuration ->> 'scanOnPush' = 'false' then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then r.repository_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then r.repository_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.image_scanning_configuration ->> 'scanOnPush' = 'false'
              then r.repository_name || ' does NOT have scan-on-push enabled (image scanning validates container integrity).'
            else r.repository_name || ' has scan-on-push enabled (validates container integrity).'
          end as reason,
          r.account_id
        from
          aws_ecr_repository as r
          left join exempt_ecr as e on r.arn = e.arn
          left join expired_ecr as er on r.arn = er.arn
  EOQ
}

query "ksi_svc_05_3_aws_check" {
  sql = <<-EOQ
        with exempt_buckets as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_s3_bucket
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-05' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-05.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_buckets as (
          select arn from exempt_buckets
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check critical buckets have object lock protection for integrity
        select
          b.arn as resource,
          case
            when eb.arn is not null then 'alarm'
            when e.arn is not null and eb.arn is null then 'skip'
            when (b.name like '%backup%' or b.name like '%archive%' or b.name like '%audit%' or b.name like '%log%')
              and b.object_lock_configuration is null then 'alarm'
            else 'ok'
          end as status,
          case
            when eb.arn is not null
              then b.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then b.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when (b.name like '%backup%' or b.name like '%archive%' or b.name like '%audit%' or b.name like '%log%')
              and b.object_lock_configuration is null
              then b.name || ' is a critical data bucket WITHOUT object lock protection (critical data buckets should have object lock for integrity).'
            else b.name || ' has appropriate integrity protection.'
          end as reason,
          b.account_id
        from
          aws_s3_bucket as b
          left join exempt_buckets as e on b.arn = e.arn
          left join expired_buckets as eb on b.arn = eb.arn
        where
          b.name like '%backup%' or b.name like '%archive%' or b.name like '%audit%' or b.name like '%log%'
  EOQ
}

query "ksi_svc_06_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-06: Secret Management
    -- Automate secret rotation and protection

    with exempt_kms as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
        tags->>'${var.exemption_reason_key}' as exemption_reason
      from
        aws_kms_key
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-SVC-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_kms as (
      select arn from exempt_kms
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check customer-managed KMS keys have automatic rotation enabled
    select
      k.arn as resource,
      case
        when ek.arn is not null then 'alarm'
        when e.arn is not null and ek.arn is null then 'skip'
        when k.key_rotation_enabled = false then 'alarm'
        else 'ok'
      end as status,
      case
        when ek.arn is not null
          then k.id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
        when e.arn is not null
          then k.id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
        when k.key_rotation_enabled = false
          then k.id || ' is a customer-managed key WITHOUT automatic rotation (key rotation required for secret management best practices).'
        else k.id || ' has automatic key rotation enabled.'
      end as reason,
      k.account_id
    from
      aws_kms_key as k
      left join exempt_kms as e on k.arn = e.arn
      left join expired_kms as ek on k.arn = ek.arn
    where
      k.key_state = 'Enabled'
      and k.key_manager = 'CUSTOMER'
  EOQ
}

query "ksi_svc_08_1_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-08: Prevent Residual Risk
        -- Detect and remove orphaned resources with residual data
    
        with exempt_volumes as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ebs_volume
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-08' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-08.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_volumes as (
          select arn from exempt_volumes
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for unattached EBS volumes (may contain residual data)
        select
          v.arn as resource,
          case
            when ev.arn is not null then 'alarm'
            when e.arn is not null and ev.arn is null then 'skip'
            when v.state = 'available' then 'alarm'
            else 'ok'
          end as status,
          case
            when ev.arn is not null
              then v.volume_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then v.volume_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when v.state = 'available'
              then v.volume_id || ' is unattached and may contain residual data (created ' ||
                extract(day from now() - v.create_time)::int || ' days ago, should be reviewed and deleted).'
            else v.volume_id || ' is attached to instance.'
          end as reason,
          v.account_id
        from
          aws_ebs_volume as v
          left join exempt_volumes as e on v.arn = e.arn
          left join expired_volumes as ev on v.arn = ev.arn
  EOQ
}

query "ksi_svc_08_2_aws_check" {
  sql = <<-EOQ
        with exempt_eips as (
          select
            'arn:aws:ec2:' || region || ':' || account_id || ':eip/' || allocation_id as arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_vpc_eip
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-08' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-08.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_eips as (
          select arn from exempt_eips
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for unused Elastic IPs (residual infrastructure)
        select
          'arn:aws:ec2:' || eip.region || ':' || eip.account_id || ':eip/' || eip.allocation_id as resource,
          case
            when ee.arn is not null then 'alarm'
            when e.arn is not null and ee.arn is null then 'skip'
            when eip.association_id is null then 'alarm'
            else 'ok'
          end as status,
          case
            when ee.arn is not null
              then 'Elastic IP ' || coalesce(eip.public_ip, eip.allocation_id) || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'Elastic IP ' || coalesce(eip.public_ip, eip.allocation_id) || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when eip.association_id is null
              then 'Elastic IP ' || coalesce(eip.public_ip, eip.allocation_id) || ' is unused (residual infrastructure, indicates incomplete cleanup).'
            else 'Elastic IP ' || eip.public_ip || ' is associated with ' || eip.association_id || '.'
          end as reason,
          eip.account_id
        from
          aws_vpc_eip as eip
          left join exempt_eips as e on 'arn:aws:ec2:' || eip.region || ':' || eip.account_id || ':eip/' || eip.allocation_id = e.arn
          left join expired_eips as ee on 'arn:aws:ec2:' || eip.region || ':' || eip.account_id || ':eip/' || eip.allocation_id = ee.arn
  EOQ
}

query "ksi_svc_08_3_aws_check" {
  sql = <<-EOQ
        with exempt_amis as (
          select
            image_id as arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ec2_ami
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-08' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-08.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_amis as (
          select arn from exempt_amis
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for old AMIs (> 180 days) that may be stale
        select
          ami.image_id as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when ami.creation_date < now() - interval '180 days' then 'info'
            else 'ok'
          end as status,
          case
            when ea.arn is not null
              then ami.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then ami.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when ami.creation_date < now() - interval '180 days'
              then ami.name || ' AMI is ' || extract(day from now() - ami.creation_date)::int ||
                ' days old (old AMIs may contain outdated/vulnerable software).'
            else ami.name || ' AMI is recent (' || extract(day from now() - ami.creation_date)::int || ' days old).'
          end as reason,
          ami.account_id
        from
          aws_ec2_ami as ami
          left join exempt_amis as e on ami.image_id = e.arn
          left join expired_amis as ea on ami.image_id = ea.arn
        where
          ami.creation_date < now() - interval '180 days'
  EOQ
}

query "ksi_svc_08_4_aws_check" {
  sql = <<-EOQ
        with exempt_sgs as (
          select
            'arn:aws:ec2:' || region || ':' || account_id || ':security-group/' || group_id as arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_vpc_security_group
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-08' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-08.4' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_sgs as (
          select arn from exempt_sgs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for orphaned security groups not attached to any network interface
        select
          'arn:aws:ec2:' || sg.region || ':' || sg.account_id || ':security-group/' || sg.group_id as resource,
          case
            when es.arn is not null then 'alarm'
            when e.arn is not null and es.arn is null then 'skip'
            else 'info'
          end as status,
          case
            when es.arn is not null
              then sg.group_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then sg.group_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            else sg.group_name || ' is an orphaned security group not attached to any ENI (unused security groups should be cleaned up).'
          end as reason,
          sg.account_id
        from
          aws_vpc_security_group sg
          left join aws_ec2_network_interface eni on sg.group_id = any(eni.groups)
          left join exempt_sgs as e on 'arn:aws:ec2:' || sg.region || ':' || sg.account_id || ':security-group/' || sg.group_id = e.arn
          left join expired_sgs as es on 'arn:aws:ec2:' || sg.region || ':' || sg.account_id || ':security-group/' || sg.group_id = es.arn
        where
          eni.network_interface_id is null
          and sg.group_name != 'default'
  EOQ
}

query "ksi_svc_08_5_aws_check" {
  sql = <<-EOQ
        with exempt_roles as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_iam_role
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-08' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-08.5' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_roles as (
          select arn from exempt_roles
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for IAM roles unused for 90+ days (stale roles should be removed)
        select
          r.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when r.path not like '/aws-service-role/%'
              and (r.role_last_used_date is null or r.role_last_used_date < now() - interval '90 days') then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then r.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then r.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.path not like '/aws-service-role/%' and r.role_last_used_date is null
              then r.name || ' has NEVER been used (stale role, should be reviewed and removed).'
            when r.path not like '/aws-service-role/%' and r.role_last_used_date < now() - interval '90 days'
              then r.name || ' has not been used for ' || extract(day from now() - r.role_last_used_date)::int ||
                ' days (stale role, should be reviewed and removed).'
            else r.name || ' is actively used.'
          end as reason,
          r.account_id
        from
          aws_iam_role as r
          left join exempt_roles as e on r.arn = e.arn
          left join expired_roles as er on r.arn = er.arn
        where
          r.path not like '/aws-service-role/%'
  EOQ
}

query "ksi_svc_09_1_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-09: Communication Integrity
        -- Verify inter-service communication authentication
    
        with exempt_certs as (
          select
            certificate_arn as arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_acm_certificate
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-09' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-09.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_certs as (
          select arn from exempt_certs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check certificates are in ISSUED status (must be valid for communication integrity)
        select
          c.certificate_arn as resource,
          case
            when ec.arn is not null then 'alarm'
            when e.arn is not null and ec.arn is null then 'skip'
            when c.status = 'ISSUED' then 'ok'
            else 'alarm'
          end as status,
          case
            when ec.arn is not null
              then c.domain_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then c.domain_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when c.status = 'ISSUED'
              then c.domain_name || ' certificate is issued and valid.'
            else c.domain_name || ' certificate is NOT in ISSUED status: ' || c.status || ' (certificates must be valid for communication integrity).'
          end as reason,
          c.account_id
        from
          aws_acm_certificate as c
          left join exempt_certs as e on c.certificate_arn = e.arn
          left join expired_certs as ec on c.certificate_arn = ec.arn
  EOQ
}

query "ksi_svc_09_2_aws_check" {
  sql = <<-EOQ
        with exempt_albs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ec2_application_load_balancer
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-09' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-09.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_albs as (
          select arn from exempt_albs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check listeners are encrypted (validates perimeter TLS; service-to-service mTLS requires architecture review)
        select
          l.load_balancer_arn as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when l.protocol = 'HTTP' then 'alarm'
            else 'ok'
          end as status,
          case
            when ea.arn is not null
              then 'Listener has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'Listener is exempt.'
            when l.protocol = 'HTTP'
              then 'Listener on port ' || l.port || ' uses HTTP (unencrypted, lacks communication integrity; validates perimeter TLS; service-to-service mTLS requires architecture review).'
            else 'Listener on port ' || l.port || ' uses ' || l.protocol || ' (encrypted).'
          end as reason,
          l.account_id
        from
          aws_ec2_load_balancer_listener as l
          left join exempt_albs as e on l.load_balancer_arn = e.arn
          left join expired_albs as ea on l.load_balancer_arn = ea.arn
  EOQ
}

query "ksi_svc_09_3_aws_check" {
  sql = <<-EOQ
        with exempt_mesh as (
          select
            'arn:aws:appmesh:' || region || ':' || account_id || ':mesh/' || mesh_name || '/virtualService/' || virtual_service_name as arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_appmesh_virtual_service
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-09' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-09.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_mesh as (
          select arn from exempt_mesh
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check App Mesh services have backend configuration (enables mTLS for inter-service communication)
        select
          'arn:aws:appmesh:' || m.region || ':' || m.account_id || ':mesh/' || m.mesh_name || '/virtualService/' || m.virtual_service_name as resource,
          case
            when em.arn is not null then 'alarm'
            when e.arn is not null and em.arn is null then 'skip'
            when m.spec ->> 'backends' is null then 'info'
            else 'ok'
          end as status,
          case
            when em.arn is not null
              then m.virtual_service_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then m.virtual_service_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when m.spec ->> 'backends' is null
              then m.virtual_service_name || ' in mesh ' || m.mesh_name || ' does NOT have backend configuration (App Mesh enables mTLS for inter-service communication if deployed).'
            else m.virtual_service_name || ' has backend configuration.'
          end as reason,
          m.account_id
        from
          aws_appmesh_virtual_service as m
          left join exempt_mesh as e on 'arn:aws:appmesh:' || m.region || ':' || m.account_id || ':mesh/' || m.mesh_name || '/virtualService/' || m.virtual_service_name = e.arn
          left join expired_mesh as em on 'arn:aws:appmesh:' || m.region || ':' || m.account_id || ':mesh/' || m.mesh_name || '/virtualService/' || m.virtual_service_name = em.arn
  EOQ
}

query "ksi_svc_10_1_aws_check" {
  sql = <<-EOQ
    -- KSI-SVC-10: Unwanted Data Removal
        -- Enable data lifecycle management and removal capability
    
        with exempt_buckets as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_s3_bucket
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-10' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-10.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_buckets as (
          select arn from exempt_buckets
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check S3 buckets have lifecycle policies (automate data deletion)
        select
          b.arn as resource,
          case
            when eb.arn is not null then 'alarm'
            when e.arn is not null and eb.arn is null then 'skip'
            when b.lifecycle_rules is null then 'alarm'
            else 'ok'
          end as status,
          case
            when eb.arn is not null
              then b.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then b.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when b.lifecycle_rules is null
              then b.name || ' does NOT have lifecycle policies configured (lifecycle rules automate data deletion).'
            else b.name || ' has lifecycle policies configured.'
          end as reason,
          b.account_id
        from
          aws_s3_bucket as b
          left join exempt_buckets as e on b.arn = e.arn
          left join expired_buckets as eb on b.arn = eb.arn
  EOQ
}

query "ksi_svc_10_2_aws_check" {
  sql = <<-EOQ
        with exempt_dynamodb as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_dynamodb_table
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-10' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-10.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_dynamodb as (
          select arn from exempt_dynamodb
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check DynamoDB tables have TTL configured (enables automatic data removal)
        select
          d.arn as resource,
          case
            when ed.arn is not null then 'alarm'
            when e.arn is not null and ed.arn is null then 'skip'
            when d.ttl ->> 'AttributeName' is null then 'alarm'
            else 'ok'
          end as status,
          case
            when ed.arn is not null
              then d.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then d.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when d.ttl ->> 'AttributeName' is null
              then d.name || ' does NOT have TTL configured (TTL enables automatic data removal).'
            else d.name || ' has TTL configured on attribute ' || (d.ttl ->> 'AttributeName') || '.'
          end as reason,
          d.account_id
        from
          aws_dynamodb_table as d
          left join exempt_dynamodb as e on d.arn = e.arn
          left join expired_dynamodb as ed on d.arn = ed.arn
  EOQ
}
