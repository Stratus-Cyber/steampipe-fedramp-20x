# KSI-RPL: Recovery Planning Queries - Azure
# Updated for Turbot Pipes workspace schema (all_azure.*)

query "ksi_rpl_01_azure_check" {
  sql = <<-EOQ
    with exempt_1 as (
      select
        id as exempt_id,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        all_azure.azure_sql_database
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-RPL-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
        expired_1 as (
      select exempt_id from exempt_1
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
        exempt_2 as (
      select
        id as exempt_id,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        all_azure.azure_storage_account
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-RPL-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
        expired_2 as (
      select exempt_id from exempt_2
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check SQL Database (backup retention configured by default)
    select
      id as resource,
      'ok' as status,
      name || ' has backup retention configured by default.' as reason,
      subscription_id
    from
      all_azure.azure_sql_database
      left join exempt_1 as e_1 on all_azure.azure_sql_database.id = e_1.exempt_id
      left join expired_1 as exp_1 on all_azure.azure_sql_database.id = exp_1.exempt_id
    where
      name != 'master'


    union all


    -- Check Storage Account replication for disaster recovery (best practice)
    select
      id as resource,
      case
        when exp_2.exempt_id is not null then 'alarm'
        when e_2.exempt_id is not null and exp_2.exempt_id is null then 'skip'
        when sku_name in ('Standard_GRS', 'Standard_RAGRS', 'Standard_GZRS', 'Standard_RAGZRS') then 'ok'
        when sku_name in ('Standard_LRS', 'Standard_ZRS') then 'info'
        else 'info'
      end as status,
      case
        when exp_2.exempt_id is not null
          then name || ' has EXPIRED exemption (expired: ' || e_2.exemption_expiry || ').'
        when e_2.exempt_id is not null
          then name || ' is exempt.'
        when sku_name in ('Standard_GRS', 'Standard_RAGRS', 'Standard_GZRS', 'Standard_RAGZRS') then name || ' uses geo-redundant storage (' || sku_name || ') for disaster recovery.'
        when sku_name in ('Standard_LRS', 'Standard_ZRS') then name || ' uses local/zone redundancy (' || sku_name || ') - consider geo-redundancy for RPO/RTO.'
        else name || ' replication type: ' || coalesce(sku_name, 'unknown') || '.'
      end as reason,
      subscription_id
    from
      all_azure.azure_storage_account
      left join exempt_2 as e_2 on all_azure.azure_storage_account.id = e_2.exempt_id
      left join expired_2 as exp_2 on all_azure.azure_storage_account.id = exp_2.exempt_id


    union all


    -- Check Azure Site Recovery configured for VMs (best practice)
    select
      'subscription-' || subscription_id as resource,
      case
        when count(*) > 0 then 'ok'
        else 'info'
      end as status,
      'Subscription has ' || count(*) || ' Azure Site Recovery vaults for disaster recovery.' as reason,
      subscription_id
    from
      all_azure.azure_recovery_services_vault
    group by
      subscription_id
  EOQ
}
