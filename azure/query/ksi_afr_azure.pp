# KSI-AFR: Authorization by FedRAMP Queries - Azure

query "ksi_afr_04_1_azure_check" {
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
  EOQ
}

query "ksi_afr_04_2_azure_check" {
  sql = <<-EOQ
        with exempt_1 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            azure_container_registry
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-AFR-04' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-AFR-04.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_1 as (
          select exempt_id from exempt_1
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Azure Container Registry has vulnerability scanning enabled
        select
          id as resource,
          case
            when exp_1.exempt_id is not null then 'alarm'
            when e_1.exempt_id is not null and exp_1.exempt_id is null then 'skip'
            when sku_tier in ('Premium', 'Standard') then 'ok'
            else 'alarm'
          end as status,
          case
            when exp_1.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_1.exemption_expiry || ').' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
            when e_1.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
            when sku_tier in ('Premium', 'Standard')
              then name || ' supports vulnerability scanning (Premium/Standard SKU).'
            else name || ' does NOT support vulnerability scanning (requires Premium or Standard SKU).'
          end as reason,
          subscription_id
        from
          azure_container_registry
          left join exempt_1 as e_1 on azure_container_registry.id = e_1.exempt_id
          left join expired_1 as exp_1 on azure_container_registry.id = exp_1.exempt_id
  EOQ
}

query "ksi_afr_11_1_azure_check" {
  sql = <<-EOQ
        with exempt_1 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            azure_key_vault_key
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-AFR-11' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-AFR-11.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_1 as (
          select exempt_id from exempt_1
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- KSI-AFR-11: Using Cryptographic Modules
        -- Use FIPS-validated cryptographic modules
        -- Note: Azure uses FIPS 140-2 validated cryptographic modules
    
        -- Check Azure Key Vault keys have rotation policy enabled
        select
          id as resource,
          case
            when exp_1.exempt_id is not null then 'alarm'
            when e_1.exempt_id is not null and exp_1.exempt_id is null then 'skip'
            when rotation_policy is not null then 'ok'
            else 'info'
          end as status,
          case
            when exp_1.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_1.exemption_expiry || ').' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
            when e_1.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
            when rotation_policy is not null
              then name || ' has key rotation policy configured.'
            else name || ' does NOT have automatic key rotation configured (manual rotation required).'
          end as reason,
          subscription_id
        from
          azure_key_vault_key
          left join exempt_1 as e_1 on azure_key_vault_key.id = e_1.exempt_id
          left join expired_1 as exp_1 on azure_key_vault_key.id = exp_1.exempt_id
        where
          enabled = true
  EOQ
}

query "ksi_afr_11_2_azure_check" {
  sql = <<-EOQ
        with exempt_2 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            azure_storage_account
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-AFR-11' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-AFR-11.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_2 as (
          select exempt_id from exempt_2
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Storage Accounts have encryption enabled
        select
          id as resource,
          case
            when exp_2.exempt_id is not null then 'alarm'
            when e_2.exempt_id is not null and exp_2.exempt_id is null then 'skip'
            when encryption_services_blob_enabled and encryption_services_file_enabled then 'ok'
            else 'alarm'
          end as status,
          case
            when exp_2.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_2.exemption_expiry || ').' || coalesce(' Reason: ' || e_2.exemption_reason || '.', '')
            when e_2.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_2.exemption_reason || '.', '')
            when encryption_services_blob_enabled and encryption_services_file_enabled
              then name || ' has storage encryption enabled for blobs and files.'
            else name || ' does NOT have full storage encryption enabled.'
          end as reason,
          subscription_id
        from
          azure_storage_account
          left join exempt_2 as e_2 on azure_storage_account.id = e_2.exempt_id
          left join expired_2 as exp_2 on azure_storage_account.id = exp_2.exempt_id
  EOQ
}

query "ksi_afr_11_3_azure_check" {
  sql = <<-EOQ
        with exempt_3 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            azure_compute_disk
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-AFR-11' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-AFR-11.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_3 as (
          select exempt_id from exempt_3
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Managed Disks are encrypted
        select
          id as resource,
          case
            when exp_3.exempt_id is not null then 'alarm'
            when e_3.exempt_id is not null and exp_3.exempt_id is null then 'skip'
            when encryption_type is not null then 'ok'
            else 'alarm'
          end as status,
          case
            when exp_3.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_3.exemption_expiry || ').' || coalesce(' Reason: ' || e_3.exemption_reason || '.', '')
            when e_3.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_3.exemption_reason || '.', '')
            when encryption_type is not null
              then name || ' is encrypted (type: ' || encryption_type || ').'
            else name || ' is NOT encrypted at rest.'
          end as reason,
          subscription_id
        from
          azure_compute_disk
          left join exempt_3 as e_3 on azure_compute_disk.id = e_3.exempt_id
          left join expired_3 as exp_3 on azure_compute_disk.id = exp_3.exempt_id
  EOQ
}
