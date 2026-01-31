# KSI-CMT: Change Management Queries - Azure

query "ksi_cmt_01_azure_check" {
  sql = <<-EOQ
    -- KSI-CMT-01: Log and Monitor Changes
    -- Capture and monitor all changes to cloud infrastructure

    -- Check Activity Log diagnostic settings capture all administrative operations
    select
      id as resource,
      case
        when logs @> '[{"category": "Administrative", "enabled": true}]'::jsonb
          and logs @> '[{"category": "Security", "enabled": true}]'::jsonb then 'ok'
        else 'alarm'
      end as status,
      case
        when logs @> '[{"category": "Administrative", "enabled": true}]'::jsonb
          and logs @> '[{"category": "Security", "enabled": true}]'::jsonb
          then name || ' has comprehensive change logging enabled (Administrative and Security categories).'
        else name || ' lacks comprehensive change logging.'
      end as reason,
      subscription_id
    from
      azure_diagnostic_setting
    where
      resource_uri = '/subscriptions/' || subscription_id

    union all

    -- Check Azure Policy compliance state (configuration tracking)
    select
      id as resource,
      case
        when compliance_state = 'Compliant' then 'ok'
        else 'alarm'
      end as status,
      case
        when compliance_state = 'Compliant'
          then policy_assignment_name || ' is compliant (configuration changes monitored).'
        else policy_assignment_name || ' is NOT compliant: ' || compliance_state || '.'
      end as reason,
      subscription_id
    from
      azure_policy_state
    where
      policy_definition_action = 'audit'
  EOQ
}

query "ksi_cmt_02_azure_check" {
  sql = <<-EOQ
    -- KSI-CMT-02: Redeployment (Immutable Infrastructure)
    -- Use immutable patterns - redeploy rather than modify in place

    -- Check VM Scale Sets use immutable upgrade policy
    select
      id as resource,
      case
        when upgrade_policy_mode in ('Automatic', 'Rolling') then 'ok'
        else 'info'
      end as status,
      case
        when upgrade_policy_mode in ('Automatic', 'Rolling')
          then name || ' uses ' || upgrade_policy_mode || ' upgrade policy (supports immutable deployments).'
        else name || ' uses Manual upgrade policy (may not follow immutable pattern).'
      end as reason,
      subscription_id
    from
      azure_compute_virtual_machine_scale_set

    union all

    -- Check for long-running VMs that may violate immutable infrastructure pattern
    select
      id as resource,
      case
        when date_part('day', now() - time_created) <= 30 then 'ok'
        when tags ->> 'Lifecycle' = 'static' then 'ok'
        else 'info'
      end as status,
      case
        when date_part('day', now() - time_created) <= 30
          then name || ' is ' || date_part('day', now() - time_created)::int || ' days old (within immutable pattern).'
        when tags ->> 'Lifecycle' = 'static'
          then name || ' is ' || date_part('day', now() - time_created)::int || ' days old but tagged as static/persistent.'
        else name || ' is ' || date_part('day', now() - time_created)::int || ' days old (exceeds 30 days, review if follows immutable pattern).'
      end as reason,
      subscription_id
    from
      azure_compute_virtual_machine
    where
      power_state = 'running'
  EOQ
}

query "ksi_cmt_03_azure_check" {
  sql = <<-EOQ
    -- KSI-CMT-03: Automated Testing and Validation
    -- Automate testing throughout deployment process

    -- Check Azure DevOps pipelines exist for automation
    -- Note: This requires Azure DevOps plugin - checking for ARM template deployments as proxy
    select
      id as resource,
      case
        when provisioning_state = 'Succeeded' then 'ok'
        when provisioning_state = 'Failed' then 'alarm'
        else 'info'
      end as status,
      case
        when provisioning_state = 'Succeeded'
          then deployment_name || ' deployment succeeded (indicates automated deployment).'
        when provisioning_state = 'Failed'
          then deployment_name || ' deployment failed (review automation pipeline).'
        else deployment_name || ' deployment is in ' || provisioning_state || ' state.'
      end as reason,
      subscription_id
    from
      azure_resource_group_deployment
  EOQ
}
