# KSI-AFR: Authorization by FedRAMP Queries - Azure

query "ksi_afr_04_azure_check" {
  sql = <<-EOQ
    -- KSI-AFR-04: Vulnerability Detection and Response
    -- Implement and document vulnerability scanning methodology

    -- Check Microsoft Defender for Cloud (formerly Security Center) is enabled
    select
      id as resource,
      case
        when pricing_tier = 'Standard' then 'ok'
        else 'alarm'
      end as status,
      case
        when pricing_tier = 'Standard'
          then name || ' has Microsoft Defender enabled (provides vulnerability scanning).'
        else name || ' does NOT have Microsoft Defender enabled (vulnerability scanning unavailable).'
      end as reason,
      subscription_id
    from
      azure_security_center_subscription_pricing
    where
      name in ('VirtualMachines', 'AppServices', 'SqlServers', 'ContainerRegistry', 'KubernetesService')

    union all

    -- Check Azure Container Registry has vulnerability scanning enabled
    select
      id as resource,
      case
        when sku_tier in ('Premium', 'Standard') then 'ok'
        else 'alarm'
      end as status,
      case
        when sku_tier in ('Premium', 'Standard')
          then name || ' supports vulnerability scanning (Premium/Standard SKU).'
        else name || ' does NOT support vulnerability scanning (requires Premium or Standard SKU).'
      end as reason,
      subscription_id
    from
      azure_container_registry
  EOQ
}

query "ksi_afr_11_azure_check" {
  sql = <<-EOQ
    -- KSI-AFR-11: Using Cryptographic Modules
    -- Use FIPS-validated cryptographic modules
    -- Note: Azure uses FIPS 140-2 validated cryptographic modules

    -- Check Azure Key Vault keys have rotation policy enabled
    select
      id as resource,
      case
        when rotation_policy is not null then 'ok'
        else 'info'
      end as status,
      case
        when rotation_policy is not null
          then name || ' has key rotation policy configured.'
        else name || ' does NOT have automatic key rotation configured (manual rotation required).'
      end as reason,
      subscription_id
    from
      azure_key_vault_key
    where
      enabled = true

    union all

    -- Check Storage Accounts have encryption enabled
    select
      id as resource,
      case
        when encryption_services_blob_enabled and encryption_services_file_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when encryption_services_blob_enabled and encryption_services_file_enabled
          then name || ' has storage encryption enabled for blobs and files.'
        else name || ' does NOT have full storage encryption enabled.'
      end as reason,
      subscription_id
    from
      azure_storage_account

    union all

    -- Check Managed Disks are encrypted
    select
      id as resource,
      case
        when encryption_type is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when encryption_type is not null
          then name || ' is encrypted (type: ' || encryption_type || ').'
        else name || ' is NOT encrypted at rest.'
      end as reason,
      subscription_id
    from
      azure_compute_disk
  EOQ
}
