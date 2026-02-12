# KSI-CMT: Change Management Queries - AWS

query "ksi_cmt_01_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CMT-01: Log and Monitor Changes
        -- Capture and monitor all changes to cloud infrastructure
    
        with exempt_trails as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_cloudtrail_trail
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CMT-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CMT-01.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_trails as (
          select arn from exempt_trails
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check CloudTrail trails have comprehensive logging configuration
        select
          t.arn as resource,
          case
            when et.arn is not null then 'alarm'
            when e.arn is not null and et.arn is null then 'skip'
            when t.is_logging and t.log_file_validation_enabled and t.is_multi_region_trail then 'ok'
            else 'alarm'
          end as status,
          case
            when et.arn is not null
              then t.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then t.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when t.is_logging and t.log_file_validation_enabled and t.is_multi_region_trail
              then t.name || ' has comprehensive change logging enabled (multi-region, validation, logging active).'
            else t.name || ' lacks comprehensive change logging: ' ||
              case when not t.is_logging then 'NOT logging ' else '' end ||
              case when not t.log_file_validation_enabled then 'NO validation ' else '' end ||
              case when not t.is_multi_region_trail then 'NOT multi-region' else '' end
          end as reason,
          t.account_id
        from
          aws_cloudtrail_trail as t
          left join exempt_trails as e on t.arn = e.arn
          left join expired_trails as et on t.arn = et.arn
  EOQ
}

query "ksi_cmt_01_2_aws_check" {
  sql = <<-EOQ
    -- Check AWS Config is actively recording configuration changes
        -- Note: Config recorders are account-level, no exemptions
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

query "ksi_cmt_02_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CMT-02: Redeployment (Immutable Infrastructure)
        -- Use immutable patterns - redeploy rather than modify in place
    
        with exempt_templates as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ec2_launch_template
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CMT-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CMT-02.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_templates as (
          select arn from exempt_templates
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check launch templates have been updated (version > 1 indicates redeploy pattern)
        select
          'arn:aws:ec2:' || lt.region || ':' || lt.account_id || ':launch-template/' || lt.launch_template_id as resource,
          case
            when et.arn is not null then 'alarm'
            when e.arn is not null and et.arn is null then 'skip'
            when lt.default_version_number >= 2 then 'ok'
            else 'info'
          end as status,
          case
            when et.arn is not null
              then lt.launch_template_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then lt.launch_template_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when lt.default_version_number >= 2 then lt.launch_template_name || ' has been updated (version ' || lt.default_version_number || '), indicating redeploy pattern.'
            else lt.launch_template_name || ' has never been updated (version 1 only), may not follow immutable pattern.'
          end as reason,
          lt.account_id
        from
          aws_ec2_launch_template as lt
          left join exempt_templates as e on 'arn:aws:ec2:' || lt.region || ':' || lt.account_id || ':launch-template/' || lt.launch_template_id = e.arn
          left join expired_templates as et on 'arn:aws:ec2:' || lt.region || ':' || lt.account_id || ':launch-template/' || lt.launch_template_id = et.arn
  EOQ
}

query "ksi_cmt_02_2_aws_check" {
  sql = <<-EOQ
        with exempt_asgs as (
          select
            autoscaling_group_arn as arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ec2_autoscaling_group
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CMT-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CMT-02.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_asgs as (
          select arn from exempt_asgs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Auto Scaling Groups use launch templates (not deprecated launch configs)
        select
          a.autoscaling_group_arn as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when a.launch_template is not null then 'ok'
            else 'alarm'
          end as status,
          case
            when ea.arn is not null
              then a.autoscaling_group_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then a.autoscaling_group_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when a.launch_template is not null then a.autoscaling_group_name || ' uses launch template (supports immutable deployments).'
            else a.autoscaling_group_name || ' does NOT use launch template (using deprecated launch configuration).'
          end as reason,
          a.account_id
        from
          aws_ec2_autoscaling_group as a
          left join exempt_asgs as e on a.autoscaling_group_arn = e.arn
          left join expired_asgs as ea on a.autoscaling_group_arn = ea.arn
  EOQ
}

query "ksi_cmt_02_3_aws_check" {
  sql = <<-EOQ
        with exempt_instances as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_ec2_instance
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CMT-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CMT-02.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_instances as (
          select arn from exempt_instances
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for long-running instances that may violate immutable infrastructure pattern
        -- Excludes instances explicitly tagged as static/persistent
        select
          i.arn as resource,
          case
            when ei.arn is not null then 'alarm'
            when e.arn is not null and ei.arn is null then 'skip'
            when date_part('day', now() - i.launch_time) <= 30 then 'ok'
            when i.tags ->> 'Lifecycle' = 'static' then 'ok'
            else 'info'
          end as status,
          case
            when ei.arn is not null
              then i.instance_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then i.instance_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when date_part('day', now() - i.launch_time) <= 30
              then i.instance_id || ' is ' || date_part('day', now() - i.launch_time)::int || ' days old (within immutable pattern).'
            when i.tags ->> 'Lifecycle' = 'static'
              then i.instance_id || ' is ' || date_part('day', now() - i.launch_time)::int || ' days old but tagged as static/persistent.'
            else i.instance_id || ' is ' || date_part('day', now() - i.launch_time)::int || ' days old (exceeds 30 days, review if follows immutable pattern).'
          end as reason,
          i.account_id
        from
          aws_ec2_instance as i
          left join exempt_instances as e on i.arn = e.arn
          left join expired_instances as ei on i.arn = ei.arn
        where
          i.instance_state = 'running'
  EOQ
}

query "ksi_cmt_03_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CMT-03: Automated Testing and Validation
        -- Automate testing throughout deployment process
    
        with exempt_pipelines as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_codepipeline_pipeline
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CMT-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CMT-03.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_pipelines as (
          select arn from exempt_pipelines
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check CodePipelines have sufficient stages (build, test, deploy minimum)
        select
          p.arn as resource,
          case
            when ep.arn is not null then 'alarm'
            when e.arn is not null and ep.arn is null then 'skip'
            when p.stages is null then 'alarm'
            when jsonb_array_length(p.stages) >= 3 then 'ok'
            else 'info'
          end as status,
          case
            when ep.arn is not null
              then p.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then p.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when p.stages is null then p.name || ' has no stages defined.'
            when jsonb_array_length(p.stages) >= 3 then p.name || ' has ' || jsonb_array_length(p.stages) || ' stages (indicates comprehensive pipeline).'
            else p.name || ' has only ' || jsonb_array_length(p.stages) || ' stages (recommend build/test/deploy minimum).'
          end as reason,
          p.account_id
        from
          aws_codepipeline_pipeline as p
          left join exempt_pipelines as e on p.arn = e.arn
          left join expired_pipelines as ep on p.arn = ep.arn
  EOQ
}

query "ksi_cmt_03_2_aws_check" {
  sql = <<-EOQ
        with exempt_builds as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_codebuild_project
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CMT-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CMT-03.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_builds as (
          select arn from exempt_builds
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check CodeBuild projects for privileged mode (security review needed)
        select
          b.arn as resource,
          case
            when eb.arn is not null then 'alarm'
            when e.arn is not null and eb.arn is null then 'skip'
            when b.environment ->> 'privilegedMode' = 'true' then 'info'
            else 'ok'
          end as status,
          case
            when eb.arn is not null
              then b.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then b.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when b.environment ->> 'privilegedMode' = 'true'
              then b.name || ' has privileged mode enabled (requires security review of build process).'
            else b.name || ' does not use privileged mode.'
          end as reason,
          b.account_id
        from
          aws_codebuild_project as b
          left join exempt_builds as e on b.arn = e.arn
          left join expired_builds as eb on b.arn = eb.arn
  EOQ
}
