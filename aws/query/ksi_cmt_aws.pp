# KSI-CMT: Change Management Queries - AWS

query "ksi_cmt_01_aws_check" {
  sql = <<-EOQ
    -- KSI-CMT-01: Log and Monitor Changes
    -- Capture and monitor all changes to cloud infrastructure

    -- Check CloudTrail trails have comprehensive logging configuration
    select
      arn as resource,
      case
        when is_logging and log_file_validation_enabled and is_multi_region_trail then 'ok'
        else 'alarm'
      end as status,
      case
        when is_logging and log_file_validation_enabled and is_multi_region_trail
          then name || ' has comprehensive change logging enabled (multi-region, validation, logging active).'
        else name || ' lacks comprehensive change logging: ' ||
          case when not is_logging then 'NOT logging ' else '' end ||
          case when not log_file_validation_enabled then 'NO validation ' else '' end ||
          case when not is_multi_region_trail then 'NOT multi-region' else '' end
      end as reason,
      account_id
    from
      aws_cloudtrail_trail

    union all

    -- Check AWS Config is actively recording configuration changes
    select
      'arn:aws:config:' || region || ':' || account_id || ':recorder/' || name as resource,
      case
        when status ->> 'recording' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when status ->> 'recording' = 'true' then 'AWS Config recorder ' || name || ' is actively recording configuration changes.'
        else 'AWS Config recorder ' || name || ' is NOT actively recording configuration changes.'
      end as reason,
      account_id
    from
      aws_config_configuration_recorder
  EOQ
}

query "ksi_cmt_02_aws_check" {
  sql = <<-EOQ
    -- KSI-CMT-02: Redeployment (Immutable Infrastructure)
    -- Use immutable patterns - redeploy rather than modify in place

    -- Check launch templates have been updated (version > 1 indicates redeploy pattern)
    select
      'arn:aws:ec2:' || region || ':' || account_id || ':launch-template/' || launch_template_id as resource,
      case
        when default_version_number >= 2 then 'ok'
        else 'info'
      end as status,
      case
        when default_version_number >= 2 then launch_template_name || ' has been updated (version ' || default_version_number || '), indicating redeploy pattern.'
        else launch_template_name || ' has never been updated (version 1 only), may not follow immutable pattern.'
      end as reason,
      account_id
    from
      aws_ec2_launch_template

    union all

    -- Check Auto Scaling Groups use launch templates (not deprecated launch configs)
    select
      autoscaling_group_arn as resource,
      case
        when launch_template is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when launch_template is not null then autoscaling_group_name || ' uses launch template (supports immutable deployments).'
        else autoscaling_group_name || ' does NOT use launch template (using deprecated launch configuration).'
      end as reason,
      account_id
    from
      aws_ec2_autoscaling_group

    union all

    -- Check for long-running instances that may violate immutable infrastructure pattern
    -- Excludes instances explicitly tagged as static/persistent
    select
      arn as resource,
      case
        when date_part('day', now() - launch_time) <= 30 then 'ok'
        when tags ->> 'Lifecycle' = 'static' then 'ok'
        else 'info'
      end as status,
      case
        when date_part('day', now() - launch_time) <= 30
          then instance_id || ' is ' || date_part('day', now() - launch_time)::int || ' days old (within immutable pattern).'
        when tags ->> 'Lifecycle' = 'static'
          then instance_id || ' is ' || date_part('day', now() - launch_time)::int || ' days old but tagged as static/persistent.'
        else instance_id || ' is ' || date_part('day', now() - launch_time)::int || ' days old (exceeds 30 days, review if follows immutable pattern).'
      end as reason,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'
  EOQ
}

query "ksi_cmt_03_aws_check" {
  sql = <<-EOQ
    -- KSI-CMT-03: Automated Testing and Validation
    -- Automate testing throughout deployment process

    -- Check CodePipelines have sufficient stages (build, test, deploy minimum)
    select
      arn as resource,
      case
        when stages is null then 'alarm'
        when jsonb_array_length(stages) >= 3 then 'ok'
        else 'info'
      end as status,
      case
        when stages is null then name || ' has no stages defined.'
        when jsonb_array_length(stages) >= 3 then name || ' has ' || jsonb_array_length(stages) || ' stages (indicates comprehensive pipeline).'
        else name || ' has only ' || jsonb_array_length(stages) || ' stages (recommend build/test/deploy minimum).'
      end as reason,
      account_id
    from
      aws_codepipeline_pipeline

    union all

    -- Check CodeBuild projects for privileged mode (security review needed)
    select
      arn as resource,
      case
        when environment ->> 'privilegedMode' = 'true' then 'info'
        else 'ok'
      end as status,
      case
        when environment ->> 'privilegedMode' = 'true'
          then name || ' has privileged mode enabled (requires security review of build process).'
        else name || ' does not use privileged mode.'
      end as reason,
      account_id
    from
      aws_codebuild_project
  EOQ
}
