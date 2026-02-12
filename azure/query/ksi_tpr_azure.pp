# KSI-TPR: Third-Party Resources Queries - Azure

query "ksi_tpr_03_azure_check" {
  sql = <<-EOQ
    with exempt_1 as (
      select
        id as exempt_id,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        azure_container_registry
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-TPR-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
        expired_1 as (
      select exempt_id from exempt_1
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- KSI-TPR-03: Supply Chain Risk Management
    -- Identify and mitigate supply chain risks

    -- Check Azure Container Registry has vulnerability scanning enabled (requires Premium SKU)
    select
      id as resource,
      case
        when exp_1.exempt_id is not null then 'alarm'
        when e_1.exempt_id is not null and exp_1.exempt_id is null then 'skip'
        when sku_tier = 'Premium' then 'ok'
        else 'alarm'
      end as status,
      case
        when exp_1.exempt_id is not null
          then name || ' has EXPIRED exemption (expired: ' || e_1.exemption_expiry || ').'
        when e_1.exempt_id is not null
          then name || ' is exempt.'
        when sku_tier = 'Premium'
          then name || ' supports vulnerability scanning (Premium SKU, integrates with Microsoft Defender).'
        else name || ' does NOT support comprehensive vulnerability scanning (requires Premium SKU).'
      end as reason,
      subscription_id
    from
      azure_container_registry
      left join exempt_1 as e_1 on azure_container_registry.id = e_1.exempt_id
      left join expired_1 as exp_1 on azure_container_registry.id = exp_1.exempt_id


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
