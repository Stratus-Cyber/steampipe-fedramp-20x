# KSI-CNA: Cloud Native Architecture Queries - Azure

query "ksi_cna_01_azure_check" {
  sql = <<-EOQ
    -- Check NSG has no unrestricted SSH access
    select
      id as resource,
      case
        when security_rules @> '[{"properties": {"access": "Allow", "direction": "Inbound", "destinationPortRange": "22", "sourceAddressPrefix": "*"}}]' then 'alarm'
        when security_rules @> '[{"properties": {"access": "Allow", "direction": "Inbound", "destinationPortRange": "22", "sourceAddressPrefix": "0.0.0.0/0"}}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when security_rules @> '[{"properties": {"access": "Allow", "direction": "Inbound", "destinationPortRange": "22", "sourceAddressPrefix": "*"}}]' then name || ' allows unrestricted SSH access.'
        when security_rules @> '[{"properties": {"access": "Allow", "direction": "Inbound", "destinationPortRange": "22", "sourceAddressPrefix": "0.0.0.0/0"}}]' then name || ' allows SSH from 0.0.0.0/0.'
        else name || ' restricts SSH access.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_network_security_group

    union all

    -- Check NSG has no unrestricted RDP access
    select
      id as resource,
      case
        when security_rules @> '[{"properties": {"access": "Allow", "direction": "Inbound", "destinationPortRange": "3389", "sourceAddressPrefix": "*"}}]' then 'alarm'
        when security_rules @> '[{"properties": {"access": "Allow", "direction": "Inbound", "destinationPortRange": "3389", "sourceAddressPrefix": "0.0.0.0/0"}}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when security_rules @> '[{"properties": {"access": "Allow", "direction": "Inbound", "destinationPortRange": "3389", "sourceAddressPrefix": "*"}}]' then name || ' allows unrestricted RDP access.'
        when security_rules @> '[{"properties": {"access": "Allow", "direction": "Inbound", "destinationPortRange": "3389", "sourceAddressPrefix": "0.0.0.0/0"}}]' then name || ' allows RDP from 0.0.0.0/0.'
        else name || ' restricts RDP access.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_network_security_group

    union all

    -- Check SQL Server firewall does not allow all Azure services
    select
      id as resource,
      case
        when firewall_rules @> '[{"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when firewall_rules @> '[{"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}]' then name || ' allows all Azure services (0.0.0.0 rule).'
        else name || ' has restricted firewall rules.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_sql_server

    union all

    -- Check storage account restricts network access
    select
      id as resource,
      case
        when network_rule_default_action = 'Deny' then 'ok'
        else 'alarm'
      end as status,
      case
        when network_rule_default_action = 'Deny' then name || ' has network access restricted.'
        else name || ' allows network access by default.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account
  EOQ
}

query "ksi_cna_02_azure_check" {
  sql = <<-EOQ
    -- Check storage account encrypted with customer-managed key
    select
      id as resource,
      case
        when encryption_key_source = 'Microsoft.Keyvault' then 'ok'
        when encryption_key_source = 'Microsoft.Storage' then 'info'
        else 'alarm'
      end as status,
      case
        when encryption_key_source = 'Microsoft.Keyvault' then name || ' uses customer-managed key encryption.'
        when encryption_key_source = 'Microsoft.Storage' then name || ' uses Microsoft-managed key encryption.'
        else name || ' encryption status unknown.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account

    union all

    -- Check VM disk encryption enabled
    select
      v.id as resource,
      case
        when d.encryption_type is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when d.encryption_type is not null then v.name || ' OS disk is encrypted.'
        else v.name || ' OS disk may not be encrypted.'
      end as reason,
      v.resource_group,
      v.subscription_id
    from
      azure_compute_virtual_machine as v
      left join azure_compute_disk as d on v.os_disk_name = d.name

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
  EOQ
}

query "ksi_cna_03_azure_check" {
  sql = <<-EOQ
    -- Check VNet has NSG associated
    select
      s.id as resource,
      case
        when s.network_security_group_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when s.network_security_group_id is not null then s.name || ' subnet has NSG associated.'
        else s.name || ' subnet does not have NSG associated.'
      end as reason,
      s.resource_group,
      s.subscription_id
    from
      azure_subnet as s
    where
      s.name not in ('GatewaySubnet', 'AzureFirewallSubnet', 'AzureBastionSubnet')

    union all

    -- Check App Service uses HTTPS only
    select
      id as resource,
      case
        when https_only then 'ok'
        else 'alarm'
      end as status,
      case
        when https_only then name || ' requires HTTPS.'
        else name || ' does not require HTTPS.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_app_service_web_app

    union all

    -- Check Application Gateway uses WAF
    select
      id as resource,
      case
        when web_application_firewall_configuration is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when web_application_firewall_configuration is not null then name || ' has WAF configured.'
        else name || ' does not have WAF configured.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_application_gateway

    union all

    -- Check SQL Server private endpoint configured
    select
      id as resource,
      case
        when private_endpoint_connections is not null and jsonb_array_length(private_endpoint_connections) > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when private_endpoint_connections is not null and jsonb_array_length(private_endpoint_connections) > 0 then name || ' has private endpoint configured.'
        else name || ' does not have private endpoint configured.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_sql_server
  EOQ
}

query "ksi_cna_04_azure_check" {
  sql = <<-EOQ
    -- Check storage account public access disabled
    select
      id as resource,
      case
        when allow_blob_public_access = false then 'ok'
        else 'alarm'
      end as status,
      case
        when allow_blob_public_access = false then name || ' has public blob access disabled.'
        else name || ' allows public blob access.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account

    union all

    -- Check SQL Server public network access disabled
    select
      id as resource,
      case
        when public_network_access = 'Disabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when public_network_access = 'Disabled' then name || ' has public network access disabled.'
        else name || ' has public network access enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_sql_server

    union all

    -- Check VM not using public IP
    select
      id as resource,
      case
        when public_ips is null or jsonb_array_length(public_ips) = 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when public_ips is null or jsonb_array_length(public_ips) = 0 then name || ' does not have a public IP.'
        else name || ' has ' || jsonb_array_length(public_ips) || ' public IP(s).'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_compute_virtual_machine

    union all

    -- Check App Service not accessible from internet directly
    select
      id as resource,
      case
        when vnet_connection is not null then 'ok'
        else 'info'
      end as status,
      case
        when vnet_connection is not null then name || ' is integrated with VNet.'
        else name || ' is not VNet integrated (may be publicly accessible).'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_app_service_web_app
  EOQ
}
