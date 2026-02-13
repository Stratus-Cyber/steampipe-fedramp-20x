# KSI-PIY: Policy and Inventory Queries - Azure
# Updated for Turbot Pipes workspace schema (azure.*)

query "ksi_piy_01_1_azure_check" {
  sql = <<-EOQ
    -- Check Azure Resource Graph can query resources (inventory capability)
    
    -- Check Azure Resource Graph can query resources (inventory capability)
        select
          'subscription-' || subscription_id as resource,
          case
            when count(*) > 0 then 'ok'
            else 'info'
          end as status,
          'Subscription has ' || count(*) || ' resources inventoried via Azure Resource Graph.' as reason,
          subscription_id
        from
          azure.azure_resource
        group by
          subscription_id
  EOQ
}

query "ksi_piy_01_2_azure_check" {
  sql = <<-EOQ
    -- Check Azure Policy assignments for governance (CIS Azure 2.1-2.12)
        select
          'subscription-' || subscription_id as resource,
          case
            when count(*) >= 5 then 'ok'
            when count(*) > 0 then 'info'
            else 'alarm'
          end as status,
          'Subscription has ' || count(*) || ' Azure Policy assignments for governance and inventory control.' as reason,
          subscription_id
        from
          azure.azure_policy_assignment
        group by
          subscription_id
  EOQ
}

query "ksi_piy_01_3_azure_check" {
  sql = <<-EOQ
    -- Check subscriptions have management groups for organizational inventory (best practice)
        select
          id as resource,
          case
            when display_name is not null then 'ok'
            else 'info'
          end as status,
          case
            when display_name is not null then 'Management group ' || display_name || ' provides organizational inventory structure.'
            else 'No management group structure detected (consider for large deployments).'
          end as reason,
          tenant_id
        from
          azure.azure_management_group
        limit 10
  EOQ
}
