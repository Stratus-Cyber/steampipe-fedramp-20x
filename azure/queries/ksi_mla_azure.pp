# KSI-MLA: Monitoring, Logging, Auditing Queries - Azure

query "ksi_mla_01_azure_check" {
  sql = <<-EOQ
    -- Check Activity Log profile exists with proper retention
    select
      id as resource,
      case
        when retention_policy ->> 'enabled' = 'true' and (retention_policy ->> 'days')::int >= 365 then 'ok'
        when retention_policy ->> 'enabled' = 'true' then 'info'
        else 'alarm'
      end as status,
      case
        when retention_policy ->> 'enabled' = 'true' and (retention_policy ->> 'days')::int >= 365 then name || ' has ' || (retention_policy ->> 'days') || ' day retention.'
        when retention_policy ->> 'enabled' = 'true' then name || ' has ' || (retention_policy ->> 'days') || ' day retention (recommend 365+).'
        else name || ' does not have retention policy enabled.'
      end as reason,
      subscription_id
    from
      azure_log_profile

    union all

    -- Check Log Analytics workspace exists
    select
      id as resource,
      case
        when retention_in_days >= 90 then 'ok'
        when retention_in_days >= 30 then 'info'
        else 'alarm'
      end as status,
      case
        when retention_in_days >= 90 then name || ' has ' || retention_in_days || ' day retention.'
        when retention_in_days >= 30 then name || ' has ' || retention_in_days || ' day retention (recommend 90+).'
        else name || ' has only ' || retention_in_days || ' day retention.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_log_analytics_workspace

    union all

    -- Check SQL database auditing enabled
    select
      id as resource,
      case
        when database_blob_auditing_policy ->> 'state' = 'Enabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when database_blob_auditing_policy ->> 'state' = 'Enabled' then name || ' has blob auditing enabled.'
        else name || ' does not have blob auditing enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_sql_database

    union all

    -- Check storage account logging enabled
    select
      id as resource,
      case
        when blob_service_logging ->> 'read' = 'true' 
          and blob_service_logging ->> 'write' = 'true'
          and blob_service_logging ->> 'delete' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when blob_service_logging ->> 'read' = 'true' 
          and blob_service_logging ->> 'write' = 'true'
          and blob_service_logging ->> 'delete' = 'true' then name || ' has complete blob logging enabled.'
        else name || ' does not have complete blob logging enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account

    union all

    -- Check Network Watcher flow logs enabled
    select
      nsg.id as resource,
      case
        when fl.id is not null and fl.enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when fl.id is not null and fl.enabled then nsg.name || ' has flow logs enabled.'
        else nsg.name || ' does not have flow logs enabled.'
      end as reason,
      nsg.resource_group,
      nsg.subscription_id
    from
      azure_network_security_group as nsg
      left join azure_network_watcher_flow_log as fl on nsg.id = fl.target_resource_id

    union all

    -- Check Key Vault logging enabled
    select
      id as resource,
      case
        when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then name || ' has diagnostic settings configured.'
        else name || ' does not have diagnostic settings configured.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_key_vault

    union all

    -- Check App Service HTTP logging enabled
    select
      id as resource,
      case
        when diagnostic_logs_configuration -> 'httpLogs' -> 'fileSystem' ->> 'enabled' = 'true'
          or diagnostic_logs_configuration -> 'httpLogs' -> 'azureBlobStorage' ->> 'enabled' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when diagnostic_logs_configuration -> 'httpLogs' -> 'fileSystem' ->> 'enabled' = 'true'
          or diagnostic_logs_configuration -> 'httpLogs' -> 'azureBlobStorage' ->> 'enabled' = 'true' then name || ' has HTTP logging enabled.'
        else name || ' does not have HTTP logging enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_app_service_web_app
  EOQ
}
