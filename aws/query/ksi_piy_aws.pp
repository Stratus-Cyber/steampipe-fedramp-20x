# KSI-PIY: Policy and Inventory Queries - AWS

query "ksi_piy_01_aws_check" {
  sql = <<-EOQ
    -- KSI-PIY-01: Automated Inventory
    -- Generate real-time resource inventory automatically

    -- Check AWS Config provides automated inventory
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

    union all

    -- Check EC2 instances have required inventory tags (Name and Environment minimum)
    select
      arn as resource,
      case
        when tags ->> 'Name' is null or tags ->> 'Environment' is null then 'alarm'
        else 'ok'
      end as status,
      case
        when tags ->> 'Name' is null or tags ->> 'Environment' is null
          then instance_id || ' is missing required inventory tags: ' ||
            case when tags ->> 'Name' is null then 'Name ' else '' end ||
            case when tags ->> 'Environment' is null then 'Environment' else '' end ||
            ' (all resources should have Name and Environment tags for inventory tracking).'
        else instance_id || ' has required inventory tags.'
      end as reason,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'

    union all

    -- Check S3 buckets have required inventory tags
    select
      arn as resource,
      case
        when tags ->> 'Name' is null or tags ->> 'Environment' is null then 'alarm'
        else 'ok'
      end as status,
      case
        when tags ->> 'Name' is null or tags ->> 'Environment' is null
          then name || ' is missing required inventory tags: ' ||
            case when tags ->> 'Name' is null then 'Name ' else '' end ||
            case when tags ->> 'Environment' is null then 'Environment' else '' end ||
            ' (all resources should have Name and Environment tags for inventory tracking).'
        else name || ' has required inventory tags.'
      end as reason,
      account_id
    from
      aws_s3_bucket
  EOQ
}
