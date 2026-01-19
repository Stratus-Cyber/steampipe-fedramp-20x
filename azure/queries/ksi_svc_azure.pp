# KSI-SVC: Service Configuration Queries - Azure

query "ksi_svc_01_azure_check" {
  sql = <<-EOQ
    -- Check VMs have automatic OS updates enabled
    select
      id as resource,
      case
        when os_profile_windows_config ->> 'enableAutomaticUpdates' = 'true' 
          or os_profile_linux_config is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when os_profile_windows_config ->> 'enableAutomaticUpdates' = 'true' then name || ' has automatic OS updates enabled.'
        when os_profile_linux_config is not null then name || ' is Linux (update policy managed separately).'
        else name || ' does not have automatic OS updates enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_compute_virtual_machine

    union all

    -- Check SQL database TDE enabled
    select
      id as resource,
      case
        when transparent_data_encryption ->> 'status' = 'Enabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when transparent_data_encryption ->> 'status' = 'Enabled' then name || ' has TDE enabled.'
        else name || ' does not have TDE enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_sql_database

    union all

    -- Check storage account secure transfer required
    select
      id as resource,
      case
        when enable_https_traffic_only then 'ok'
        else 'alarm'
      end as status,
      case
        when enable_https_traffic_only then name || ' requires secure transfer (HTTPS).'
        else name || ' does not require secure transfer.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account

    union all

    -- Check App Service uses latest TLS
    select
      id as resource,
      case
        when configuration ->> 'minTlsVersion' = '1.2' then 'ok'
        else 'alarm'
      end as status,
      case
        when configuration ->> 'minTlsVersion' = '1.2' then name || ' uses TLS 1.2.'
        else name || ' does not require TLS 1.2 (uses ' || coalesce(configuration ->> 'minTlsVersion', 'unknown') || ').'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_app_service_web_app

    union all

    -- Check VMs have endpoint protection
    select
      id as resource,
      case
        when extensions @> '[{"properties": {"type": "IaaSAntimalware"}}]'
          or extensions @> '[{"properties": {"type": "EndpointSecurity"}}]'
          or extensions @> '[{"properties": {"type": "MicrosoftMonitoringAgent"}}]' then 'ok'
        else 'alarm'
      end as status,
      case
        when extensions @> '[{"properties": {"type": "IaaSAntimalware"}}]' then name || ' has IaaS Antimalware extension.'
        when extensions @> '[{"properties": {"type": "EndpointSecurity"}}]' then name || ' has Endpoint Security extension.'
        when extensions @> '[{"properties": {"type": "MicrosoftMonitoringAgent"}}]' then name || ' has Microsoft Monitoring Agent.'
        else name || ' does not have endpoint protection extension.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_compute_virtual_machine
  EOQ
}

query "ksi_svc_06_azure_check" {
  sql = <<-EOQ
    -- Check Key Vault keys have expiration set
    select
      id as resource,
      case
        when enabled and expires_at is not null then 'ok'
        when not enabled then 'info'
        else 'alarm'
      end as status,
      case
        when enabled and expires_at is not null then name || ' has expiration set (' || expires_at::date || ').'
        when not enabled then name || ' is disabled.'
        else name || ' does not have an expiration date set.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_key_vault_key

    union all

    -- Check Key Vault secrets have expiration set
    select
      id as resource,
      case
        when enabled and expires_at is not null then 'ok'
        when not enabled then 'info'
        else 'alarm'
      end as status,
      case
        when enabled and expires_at is not null then name || ' has expiration set (' || expires_at::date || ').'
        when not enabled then name || ' is disabled.'
        else name || ' does not have an expiration date set.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_key_vault_secret

    union all

    -- Check Key Vault has soft delete enabled
    select
      id as resource,
      case
        when soft_delete_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when soft_delete_enabled then name || ' has soft delete enabled.'
        else name || ' does not have soft delete enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_key_vault

    union all

    -- Check Key Vault has purge protection enabled
    select
      id as resource,
      case
        when purge_protection_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when purge_protection_enabled then name || ' has purge protection enabled.'
        else name || ' does not have purge protection enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_key_vault
  EOQ
}
