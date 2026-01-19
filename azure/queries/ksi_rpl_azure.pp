# KSI-RPL: Recovery Planning Queries - Azure

query "ksi_rpl_01_azure_check" {
  sql = <<-EOQ
    -- Check SQL database long-term retention policy
    select
      d.id as resource,
      case
        when p.weekly_retention != 'PT0S' or p.monthly_retention != 'PT0S' or p.yearly_retention != 'PT0S' then 'ok'
        else 'alarm'
      end as status,
      case
        when p.weekly_retention != 'PT0S' or p.monthly_retention != 'PT0S' or p.yearly_retention != 'PT0S' then d.name || ' has long-term backup retention configured.'
        else d.name || ' does not have long-term backup retention configured.'
      end as reason,
      d.resource_group,
      d.subscription_id
    from
      azure_sql_database as d
      left join azure_sql_database_long_term_retention_policy as p on d.id = p.database_id

    union all

    -- Check VMs in availability sets or zones
    select
      id as resource,
      case
        when availability_set_id is not null or zones is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when availability_set_id is not null then name || ' is in an availability set.'
        when zones is not null then name || ' is in availability zone(s): ' || zones::text || '.'
        else name || ' is not in an availability set or zone for HA.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_compute_virtual_machine

    union all

    -- Check storage account geo-redundant replication
    select
      id as resource,
      case
        when sku_tier = 'Standard' and (sku_name like '%GRS%' or sku_name like '%GZRS%' or sku_name like '%RAGRS%' or sku_name like '%RAGZRS%') then 'ok'
        else 'alarm'
      end as status,
      case
        when sku_tier = 'Standard' and (sku_name like '%GRS%' or sku_name like '%GZRS%' or sku_name like '%RAGRS%' or sku_name like '%RAGZRS%') then name || ' has geo-redundant replication (' || sku_name || ').'
        else name || ' does not have geo-redundant replication (' || sku_name || ').'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account

    union all

    -- Check SQL database backup retention period
    select
      id as resource,
      case
        when retention_days >= 7 then 'ok'
        when retention_days > 0 then 'info'
        else 'alarm'
      end as status,
      case
        when retention_days >= 7 then name || ' has ' || retention_days || ' day point-in-time retention.'
        when retention_days > 0 then name || ' has only ' || retention_days || ' day retention (recommend 7+).'
        else name || ' has no point-in-time retention configured.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_sql_database

    union all

    -- Check Azure Recovery Services vault exists
    select
      id as resource,
      'ok' as status,
      name || ' Recovery Services vault is configured for backup.' as reason,
      resource_group,
      subscription_id
    from
      azure_recovery_services_vault
  EOQ
}
