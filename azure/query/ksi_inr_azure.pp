# KSI-INR: Incident Response Queries - Azure
# Updated for Turbot Pipes workspace schema (all_azure.*)
# Note: Security Center contacts API not available in Azure Government

query "ksi_inr_01_1_azure_check" {
  sql = <<-EOQ
    -- Check Azure Defender enabled for services (best practice)
    
    -- Check Azure Defender enabled for services (best practice)
        select
          coalesce(id, 'subscription-' || subscription_id) as resource,
          case
            when pricing_tier = 'Standard' then 'ok'
            else 'info'
          end as status,
          case
            when pricing_tier = 'Standard' then 'Azure Defender is enabled for ' || name || '.'
            else 'Azure Defender is not enabled for ' || name || ' (consider enabling).'
          end as reason,
          subscription_id
        from
          all_azure.azure_security_center_subscription_pricing
  EOQ
}

query "ksi_inr_01_2_azure_check" {
  sql = <<-EOQ
    -- Check activity log alerts for administrative operations (CIS Azure 5.2.1-5.2.9)
        select
          'subscription-' || subscription_id as resource,
          case
            when count(*) >= 9 then 'ok'
            when count(*) > 0 then 'info'
            else 'alarm'
          end as status,
          'Subscription has ' || count(*) || ' activity log alert rules for administrative operations (recommend at least 9 for CIS compliance).' as reason,
          subscription_id
        from
          all_azure.azure_log_alert
        where
          enabled = true
        group by
          subscription_id
  EOQ
}
