# KSI-PIY: Policy and Inventory Queries - AWS

query "ksi_piy_01_1_aws_check" {
  sql = <<-EOQ
    -- KSI-PIY-01: Automated Inventory
        -- Generate real-time resource inventory automatically
    
    -- Check AWS Config provides automated inventory
        -- Note: Config recorders are account-level resources, no resource-level exemptions
        select
          'arn:aws:config:' || region || ':' || account_id || ':recorder/' || name as resource,
          case
            when status ->> 'recording' = 'true' then 'ok'
            else 'alarm'
          end as status,
          case
            when status ->> 'recording' = 'true'
              then 'AWS Config recorder ' || name || ' is actively recording (provides real-time resource inventory).'
            else 'AWS Config recorder ' || name || ' is NOT recording (automated inventory unavailable).'
          end as reason,
          account_id
        from
          aws_config_configuration_recorder
  EOQ
}

query "ksi_piy_01_2_aws_check" {
  sql = <<-EOQ
        with exempt_instances as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-PIY-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-PIY-01.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:instance/%'
        ),
        expired_instances as (
          select arn from exempt_instances
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check EC2 instances have required inventory tags (Name and Environment minimum)
        select
          i.arn as resource,
          case
            when ei.arn is not null then 'alarm'
            when e.arn is not null and ei.arn is null then 'skip'
            when i.tags ->> 'Name' is null or i.tags ->> 'Environment' is null then 'alarm'
            else 'ok'
          end as status,
          case
            when ei.arn is not null
              then i.instance_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then i.instance_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when i.tags ->> 'Name' is null or i.tags ->> 'Environment' is null
              then i.instance_id || ' is missing required inventory tags: ' ||
                case when i.tags ->> 'Name' is null then 'Name ' else '' end ||
                case when i.tags ->> 'Environment' is null then 'Environment' else '' end ||
                ' (all resources should have Name and Environment tags for inventory tracking).'
            else i.instance_id || ' has required inventory tags.'
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

query "ksi_piy_01_3_aws_check" {
  sql = <<-EOQ
        with exempt_buckets as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-PIY-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-PIY-01.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:s3:::%'
        ),
        expired_buckets as (
          select arn from exempt_buckets
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check S3 buckets have required inventory tags
        select
          b.arn as resource,
          case
            when eb.arn is not null then 'alarm'
            when e.arn is not null and eb.arn is null then 'skip'
            when b.tags ->> 'Name' is null or b.tags ->> 'Environment' is null then 'alarm'
            else 'ok'
          end as status,
          case
            when eb.arn is not null
              then b.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then b.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when b.tags ->> 'Name' is null or b.tags ->> 'Environment' is null
              then b.name || ' is missing required inventory tags: ' ||
                case when b.tags ->> 'Name' is null then 'Name ' else '' end ||
                case when b.tags ->> 'Environment' is null then 'Environment' else '' end ||
                ' (all resources should have Name and Environment tags for inventory tracking).'
            else b.name || ' has required inventory tags.'
          end as reason,
          b.account_id
        from
          aws_s3_bucket as b
          left join exempt_buckets as e on b.arn = e.arn
          left join expired_buckets as eb on b.arn = eb.arn
  EOQ
}
