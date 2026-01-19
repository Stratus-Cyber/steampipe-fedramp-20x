# KSI-MLA: Monitoring, Logging, Auditing Queries - AWS


query "ksi_mla_01_aws_check" {
  sql = <<-EOQ
    -- Check CloudTrail is enabled in all regions (cis_v150_3_1)
    select
      arn as resource,
      case
        when is_logging and is_multi_region_trail then 'ok'
        when is_logging then 'info'
        else 'alarm'
      end as status,
      case
        when is_logging and is_multi_region_trail then name || ' is logging in all regions.'
        when is_logging then name || ' is logging but not multi-region.'
        else name || ' is not logging.'
      end as reason,
      account_id
    from
      aws_cloudtrail_trail

    union all

    -- Check CloudTrail log file validation enabled (cis_v150_3_2)
    select
      arn as resource,
      case
        when log_file_validation_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when log_file_validation_enabled then name || ' has log file validation enabled.'
        else name || ' does not have log file validation enabled.'
      end as reason,
      account_id
    from
      aws_cloudtrail_trail
    where
      is_multi_region_trail

    union all

    -- Check CloudTrail logs encrypted with KMS (cis_v150_3_4)
    select
      arn as resource,
      case
        when kms_key_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when kms_key_id is not null then name || ' logs are encrypted with KMS.'
        else name || ' logs are not encrypted with KMS.'
      end as reason,
      account_id
    from
      aws_cloudtrail_trail
    where
      is_multi_region_trail

    union all

    -- Check CloudTrail CloudWatch logs integration (cis_v150_3_5)
    select
      arn as resource,
      case
        when log_group_arn is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when log_group_arn is not null then name || ' sends logs to CloudWatch.'
        else name || ' does not send logs to CloudWatch.'
      end as reason,
      account_id
    from
      aws_cloudtrail_trail
    where
      is_multi_region_trail

    union all

    -- Check VPC Flow Logs enabled (foundational_security_vpc_1, ec2_6)
    select
      v.arn as resource,
      case
        when f.flow_log_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when f.flow_log_id is not null then v.vpc_id || ' has flow logs enabled.'
        else v.vpc_id || ' does not have flow logs enabled.'
      end as reason,
      v.account_id
    from
      aws_vpc as v
      left join aws_vpc_flow_log as f on v.vpc_id = f.resource_id

    union all

    -- Check RDS enhanced monitoring enabled (foundational_security_rds_9)
    select
      arn as resource,
      case
        when enhanced_monitoring_resource_arn is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when enhanced_monitoring_resource_arn is not null then db_instance_identifier || ' has enhanced monitoring enabled.'
        else db_instance_identifier || ' does not have enhanced monitoring enabled.'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check AWS Config enabled (foundational_security_config_1)
    select
      'arn:aws:config:' || region || ':' || account_id as resource,
      case
        when status_recording then 'ok'
        else 'alarm'
      end as status,
      case
        when status_recording then 'AWS Config is recording in ' || region || '.'
        else 'AWS Config is not recording in ' || region || '.'
      end as reason,
      account_id
    from
      aws_config_configuration_recorder
  EOQ
}
