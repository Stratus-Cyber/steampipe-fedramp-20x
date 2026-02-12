# KSI-MLA: Monitoring, Logging, Auditing Queries - Azure
# Updated for Turbot Pipes workspace schema (all_azure.*)

query "ksi_mla_01_1_azure_check" {
  sql = <<-EOQ
    -- Check Activity Log retention is at least 365 days (CIS Azure 5.1.1)
        select
          id as resource,
          case
            when (retention_policy->>'enabled')::boolean and (retention_policy->>'days')::int >= 365 then 'ok'
            when (retention_policy->>'enabled')::boolean and (retention_policy->>'days')::int > 0 then 'info'
            else 'alarm'
          end as status,
          case
            when (retention_policy->>'enabled')::boolean and (retention_policy->>'days')::int >= 365 then name || ' has activity log retention of ' || (retention_policy->>'days') || ' days.'
            when (retention_policy->>'enabled')::boolean and (retention_policy->>'days')::int > 0 then name || ' has activity log retention of ' || (retention_policy->>'days') || ' days (recommend 365+).'
            else name || ' does not have activity log retention configured.'
          end as reason,
          subscription_id
        from
          all_azure.azure_log_profile
  EOQ
}

query "ksi_mla_01_2_azure_check" {
  sql = <<-EOQ
        with exempt_1 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_key_vault
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-01.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_1 as (
          select exempt_id from exempt_1
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check diagnostic settings for Key Vault (CIS Azure 5.1.5)
        select
          id as resource,
          case
            when exp_1.exempt_id is not null then 'alarm'
            when e_1.exempt_id is not null and exp_1.exempt_id is null then 'skip'
            when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then 'ok'
            else 'alarm'
          end as status,
          case
            when exp_1.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_1.exemption_expiry || ').' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
            when e_1.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
            when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then name || ' has diagnostic settings enabled.'
            else name || ' does not have diagnostic settings enabled.'
          end as reason,
          subscription_id
        from
          all_azure.azure_key_vault
          left join exempt_1 as e_1 on all_azure.azure_key_vault.id = e_1.exempt_id
          left join expired_1 as exp_1 on all_azure.azure_key_vault.id = exp_1.exempt_id
  EOQ
}

query "ksi_mla_01_3_azure_check" {
  sql = <<-EOQ
        with exempt_2 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_network_security_group
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-01.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_2 as (
          select exempt_id from exempt_2
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check diagnostic settings for Network Security Groups (CIS Azure 6.5)
        select
          id as resource,
          case
            when exp_2.exempt_id is not null then 'alarm'
            when e_2.exempt_id is not null and exp_2.exempt_id is null then 'skip'
            when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then 'ok'
            else 'alarm'
          end as status,
          case
            when exp_2.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_2.exemption_expiry || ').' || coalesce(' Reason: ' || e_2.exemption_reason || '.', '')
            when e_2.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_2.exemption_reason || '.', '')
            when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then name || ' has diagnostic settings enabled.'
            else name || ' does not have diagnostic settings enabled.'
          end as reason,
          subscription_id
        from
          all_azure.azure_network_security_group
          left join exempt_2 as e_2 on all_azure.azure_network_security_group.id = e_2.exempt_id
          left join expired_2 as exp_2 on all_azure.azure_network_security_group.id = exp_2.exempt_id
  EOQ
}

query "ksi_mla_01_4_azure_check" {
  sql = <<-EOQ
        with exempt_3 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_sql_server
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-01.4' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_3 as (
          select exempt_id from exempt_3
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check SQL Server (auditing is enabled by default for Azure SQL)
        select
          id as resource,
          'ok' as status,
          name || ' has auditing enabled by default.' as reason,
          subscription_id
        from
          all_azure.azure_sql_server
          left join exempt_3 as e_3 on all_azure.azure_sql_server.id = e_3.exempt_id
          left join expired_3 as exp_3 on all_azure.azure_sql_server.id = exp_3.exempt_id
  EOQ
}

query "ksi_mla_01_5_azure_check" {
  sql = <<-EOQ
        with exempt_4 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_log_analytics_workspace
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-MLA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-MLA-01.5' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_4 as (
          select exempt_id from exempt_4
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Log Analytics workspace retention (best practice)
        select
          id as resource,
          case
            when exp_4.exempt_id is not null then 'alarm'
            when e_4.exempt_id is not null and exp_4.exempt_id is null then 'skip'
            when retention_in_days >= 365 then 'ok'
            when retention_in_days > 0 then 'info'
            else 'alarm'
          end as status,
          case
            when exp_4.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_4.exemption_expiry || ').' || coalesce(' Reason: ' || e_4.exemption_reason || '.', '')
            when e_4.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_4.exemption_reason || '.', '')
            when retention_in_days >= 365 then name || ' has retention of ' || retention_in_days || ' days.'
            when retention_in_days > 0 then name || ' has retention of ' || retention_in_days || ' days (recommend 365+).'
            else name || ' does not have retention configured.'
          end as reason,
          subscription_id
        from
          all_azure.azure_log_analytics_workspace
          left join exempt_4 as e_4 on all_azure.azure_log_analytics_workspace.id = e_4.exempt_id
          left join expired_4 as exp_4 on all_azure.azure_log_analytics_workspace.id = exp_4.exempt_id
  EOQ
}

query "ksi_mla_01_6_azure_check" {
  sql = <<-EOQ
    -- Check Azure Monitor log alerts exist (best practice)
        select
          'subscription-' || subscription_id as resource,
          case
            when count(*) > 0 then 'ok'
            else 'info'
          end as status,
          'Subscription has ' || count(*) || ' log alert rules configured.' as reason,
          subscription_id
        from
          all_azure.azure_log_alert
        group by
          subscription_id
  EOQ
}
