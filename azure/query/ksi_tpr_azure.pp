# KSI-TPR: Third-Party Resources Queries - Azure

query "ksi_tpr_03_azure_check" {
  sql = <<-EOQ
    -- KSI-TPR-03: Supply Chain Risk Management
    -- Identify and mitigate supply chain risks

    -- Check Azure Container Registry has vulnerability scanning enabled (requires Premium SKU)
    select
      id as resource,
      case
        when sku_tier = 'Premium' then 'ok'
        else 'alarm'
      end as status,
      case
        when sku_tier = 'Premium'
          then name || ' supports vulnerability scanning (Premium SKU, integrates with Microsoft Defender).'
        else name || ' does NOT support comprehensive vulnerability scanning (requires Premium SKU).'
      end as reason,
      subscription_id
    from
      azure_container_registry

    union all

    -- Check Microsoft Defender for Containers is enabled
    select
      id as resource,
      case
        when pricing_tier = 'Standard' and name = 'ContainerRegistry' then 'ok'
        else 'alarm'
      end as status,
      case
        when pricing_tier = 'Standard' and name = 'ContainerRegistry'
          then 'Microsoft Defender for Container Registry is enabled (provides vulnerability detection).'
        else 'Microsoft Defender for Container Registry is NOT enabled.'
      end as reason,
      subscription_id
    from
      azure_security_center_subscription_pricing
    where
      name in ('ContainerRegistry', 'Containers', 'KubernetesService')
  EOQ
}

query "ksi_tpr_04_azure_check" {
  sql = <<-EOQ
    -- KSI-TPR-04: Supply Chain Risk Monitoring
    -- Automatically monitor for upstream vulnerabilities

    -- Check Microsoft Defender for Cloud is enabled for continuous monitoring
    select
      id as resource,
      case
        when pricing_tier = 'Standard' then 'ok'
        else 'alarm'
      end as status,
      case
        when pricing_tier = 'Standard'
          then name || ' has Microsoft Defender enabled (provides continuous vulnerability monitoring).'
        else name || ' does NOT have Microsoft Defender enabled.'
      end as reason,
      subscription_id
    from
      azure_security_center_subscription_pricing
    where
      name in ('VirtualMachines', 'AppServices', 'ContainerRegistry', 'KubernetesService')

    union all

    -- Check Azure Policy for supply chain security policies
    select
      id as resource,
      case
        when enforcement_mode = 'Default' then 'ok'
        else 'info'
      end as status,
      case
        when enforcement_mode = 'Default'
          then display_name || ' is enforcing supply chain security policies.'
        else display_name || ' enforcement mode is ' || enforcement_mode || '.'
      end as reason,
      subscription_id
    from
      azure_policy_assignment
    where
      display_name like '%container%' or display_name like '%vulnerability%' or display_name like '%security%'
  EOQ
}
