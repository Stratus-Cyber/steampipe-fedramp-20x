# KSI-INR: Incident Response Queries - Azure

query "ksi_inr_01_azure_check" {
  sql = <<-EOQ
    -- Check Security Center is enabled (Standard tier)
    select
      id as resource,
      case
        when pricing_tier = 'Standard' then 'ok'
        else 'alarm'
      end as status,
      case
        when pricing_tier = 'Standard' then name || ' has Security Center Standard tier enabled.'
        else name || ' is using ' || pricing_tier || ' tier (recommend Standard).'
      end as reason,
      subscription_id
    from
      azure_security_center_subscription_pricing

    union all

    -- Check Azure Defender (Security Center) alerts configured
    select
      id as resource,
      case
        when properties ->> 'severity' in ('High', 'Medium') then 'info'
        else 'ok'
      end as status,
      case
        when properties ->> 'severity' in ('High', 'Medium') then 'Security alert: ' || title || ' (Severity: ' || (properties ->> 'severity') || ').'
        else 'Security alert: ' || title || '.'
      end as reason,
      subscription_id
    from
      azure_security_center_alert

    union all

    -- Check Activity Log alerts exist for security operations
    select
      id as resource,
      case
        when enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when enabled then name || ' activity log alert is enabled.'
        else name || ' activity log alert is not enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_log_alert

    union all

    -- Check Network Watcher is enabled for incident analysis
    select
      id as resource,
      case
        when provisioning_state = 'Succeeded' then 'ok'
        else 'alarm'
      end as status,
      case
        when provisioning_state = 'Succeeded' then name || ' Network Watcher is provisioned in ' || region || '.'
        else name || ' Network Watcher provisioning state: ' || provisioning_state || '.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_network_watcher
  EOQ
}
