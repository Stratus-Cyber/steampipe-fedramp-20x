# KSI-PIY: Policy and Inventory Queries - Azure

query "ksi_piy_01_azure_check" {
  sql = <<-EOQ
    -- Check SQL database tag inventory
    select
      id as resource,
      case
        when tags is null or tags = '{}' then 'alarm'
        else 'ok'
      end as status,
      case
        when tags is null or tags = '{}' then name || ' has no tags for inventory tracking.'
        else name || ' is properly tagged for inventory.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_sql_database

    union all

    -- Check VM tag inventory
    select
      id as resource,
      case
        when tags is null or tags = '{}' then 'alarm'
        else 'ok'
      end as status,
      case
        when tags is null or tags = '{}' then name || ' has no tags for inventory tracking.'
        else name || ' is properly tagged for inventory.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_compute_virtual_machine

    union all

    -- Check storage account tag inventory
    select
      id as resource,
      case
        when tags is null or tags = '{}' then 'alarm'
        else 'ok'
      end as status,
      case
        when tags is null or tags = '{}' then name || ' has no tags for inventory tracking.'
        else name || ' is properly tagged for inventory.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account
  EOQ
}
