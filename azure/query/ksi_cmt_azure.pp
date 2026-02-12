# KSI-CMT: Change Management Queries - Azure

query "ksi_cmt_01_1_azure_check" {
  sql = <<-EOQ
    -- KSI-CMT-01: Log and Monitor Changes
        -- Capture and monitor all changes to cloud infrastructure
    
        -- Check Activity Log diagnostic settings capture all administrative operations
    
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
  EOQ
}

query "ksi_cmt_01_2_azure_check" {
  sql = <<-EOQ
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

query "ksi_cmt_02_1_azure_check" {
  sql = <<-EOQ
        with exempt_1 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            azure_compute_virtual_machine_scale_set
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CMT-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CMT-02.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_1 as (
          select exempt_id from exempt_1
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- KSI-CMT-02: Redeployment (Immutable Infrastructure)
        -- Use immutable patterns - redeploy rather than modify in place
    
        -- Check VM Scale Sets use immutable upgrade policy
        select
          id as resource,
          case
            when exp_1.exempt_id is not null then 'alarm'
            when e_1.exempt_id is not null and exp_1.exempt_id is null then 'skip'
            when upgrade_policy_mode in ('Automatic', 'Rolling') then 'ok'
            else 'info'
          end as status,
          case
            when exp_1.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_1.exemption_expiry || ').' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
            when e_1.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
            when upgrade_policy_mode in ('Automatic', 'Rolling')
              then name || ' uses ' || upgrade_policy_mode || ' upgrade policy (supports immutable deployments).'
            else name || ' uses Manual upgrade policy (may not follow immutable pattern).'
          end as reason,
          subscription_id
        from
          azure_compute_virtual_machine_scale_set
          left join exempt_1 as e_1 on azure_compute_virtual_machine_scale_set.id = e_1.exempt_id
          left join expired_1 as exp_1 on azure_compute_virtual_machine_scale_set.id = exp_1.exempt_id
  EOQ
}

query "ksi_cmt_02_2_azure_check" {
  sql = <<-EOQ
        with exempt_2 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            azure_compute_virtual_machine
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CMT-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CMT-02.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_2 as (
          select exempt_id from exempt_2
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for long-running VMs that may violate immutable infrastructure pattern
        select
          id as resource,
          case
            when exp_2.exempt_id is not null then 'alarm'
            when e_2.exempt_id is not null and exp_2.exempt_id is null then 'skip'
            when date_part('day', now() - time_created) <= 30 then 'ok'
            when tags ->> 'Lifecycle' = 'static' then 'ok'
            else 'info'
          end as status,
          case
            when exp_2.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_2.exemption_expiry || ').' || coalesce(' Reason: ' || e_2.exemption_reason || '.', '')
            when e_2.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_2.exemption_reason || '.', '')
            when date_part('day', now() - time_created) <= 30
              then name || ' is ' || date_part('day', now() - time_created)::int || ' days old (within immutable pattern).'
            when tags ->> 'Lifecycle' = 'static'
              then name || ' is ' || date_part('day', now() - time_created)::int || ' days old but tagged as static/persistent.'
            else name || ' is ' || date_part('day', now() - time_created)::int || ' days old (exceeds 30 days, review if follows immutable pattern).'
          end as reason,
          subscription_id
        from
          azure_compute_virtual_machine
          left join exempt_2 as e_2 on azure_compute_virtual_machine.id = e_2.exempt_id
          left join expired_2 as exp_2 on azure_compute_virtual_machine.id = exp_2.exempt_id
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
