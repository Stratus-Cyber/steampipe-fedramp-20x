# KSI-SVC: Service Configuration Queries - AWS

query "ksi_svc_01_aws_check" {
  sql = <<-EOQ
    -- Check EC2 instances using IMDSv2 (foundational_security_ec2_8)
    select
      arn as resource,
      case
        when metadata_options ->> 'HttpTokens' = 'required' then 'ok'
        else 'alarm'
      end as status,
      case
        when metadata_options ->> 'HttpTokens' = 'required' then instance_id || ' requires IMDSv2.'
        else instance_id || ' does not require IMDSv2 (allows IMDSv1).'
      end as reason,
      region,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'

    union all

    -- Check EC2 instances not using multiple ENIs (foundational_security_ec2_22)
    select
      arn as resource,
      case
        when jsonb_array_length(network_interfaces) <= 1 then 'ok'
        else 'info'
      end as status,
      case
        when jsonb_array_length(network_interfaces) <= 1 then instance_id || ' has ' || jsonb_array_length(network_interfaces) || ' network interface.'
        else instance_id || ' has ' || jsonb_array_length(network_interfaces) || ' network interfaces (review if needed).'
      end as reason,
      region,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'

    union all

    -- Check RDS automatic minor version upgrade (foundational_security_rds_13)
    select
      arn as resource,
      case
        when auto_minor_version_upgrade then 'ok'
        else 'alarm'
      end as status,
      case
        when auto_minor_version_upgrade then db_instance_identifier || ' has automatic minor version upgrade enabled.'
        else db_instance_identifier || ' does not have automatic minor version upgrade enabled.'
      end as reason,
      region,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check ElastiCache Redis auto minor version upgrade (foundational_security_elasticache_2)
    select
      arn as resource,
      case
        when auto_minor_version_upgrade then 'ok'
        else 'alarm'
      end as status,
      case
        when auto_minor_version_upgrade then cache_cluster_id || ' has automatic minor version upgrade enabled.'
        else cache_cluster_id || ' does not have automatic minor version upgrade enabled.'
      end as reason,
      region,
      account_id
    from
      aws_elasticache_cluster

    union all

    -- Check Auto Scaling launch templates (foundational_security_autoscaling_3)
    -- Note: Using 'name' instead of 'auto_scaling_group_name' for Steampipe compatibility
    select
      autoscaling_group_arn as resource,
      case
        when launch_template_id is not null then 'ok'
        when mixed_instances_policy_launch_template_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when launch_template_id is not null then name || ' uses a launch template.'
        when mixed_instances_policy_launch_template_id is not null then name || ' uses a launch template via mixed instances policy.'
        else name || ' does not use a launch template.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_autoscaling_group

    union all

    -- Check ELB desync mitigation mode (foundational_security_elb_12)
    select
      arn as resource,
      case
        when load_balancer_attributes @> '[{"Key": "routing.http.desync_mitigation_mode", "Value": "defensive"}]'
          or load_balancer_attributes @> '[{"Key": "routing.http.desync_mitigation_mode", "Value": "strictest"}]' then 'ok'
        else 'alarm'
      end as status,
      case
        when load_balancer_attributes @> '[{"Key": "routing.http.desync_mitigation_mode", "Value": "defensive"}]'
          or load_balancer_attributes @> '[{"Key": "routing.http.desync_mitigation_mode", "Value": "strictest"}]' then title || ' has desync mitigation enabled.'
        else title || ' does not have defensive or strictest desync mitigation mode.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_application_load_balancer
  EOQ
}

query "ksi_svc_06_aws_check" {
  sql = <<-EOQ
    -- Check IAM access key rotation (cis_v150_1_14)
    select
      u.arn as resource,
      case
        when k.access_key_id is null then 'ok'
        when k.create_date <= (current_date - interval '90 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when k.access_key_id is null then u.name || ' has no access keys.'
        when k.create_date <= (current_date - interval '90 days') then u.name || ' access key ' || k.access_key_id || ' is ' || extract(day from now() - k.create_date)::int || ' days old (over 90 days).'
        else u.name || ' access key ' || k.access_key_id || ' is within 90-day rotation period.'
      end as reason,
      u.account_id
    from
      aws_iam_user as u
      left join aws_iam_access_key as k on u.name = k.user_name

    union all

    -- Check root account access key absence (cis_v150_1_4)
    select
      'arn:aws:iam::' || account_id || ':root' as resource,
      case
        when account_access_keys_present = 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when account_access_keys_present = 0 then 'Root account has no access keys.'
        else 'Root account has ' || account_access_keys_present || ' access key(s) present.'
      end as reason,
      account_id
    from
      aws_iam_account_summary
  EOQ
}
