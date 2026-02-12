# KSI-SVC: Service Configuration Queries - Azure
# Updated for Turbot Pipes workspace schema (all_azure.*)

query "ksi_svc_01_azure_check" {
  sql = <<-EOQ
    with exempt_1 as (
      select
        id as exempt_id,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
        tags->>'${var.exemption_reason_key}' as exemption_reason
      from
        all_azure.azure_kubernetes_cluster
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-SVC-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
        expired_1 as (
      select exempt_id from exempt_1
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check AKS version is current (best practice for security improvements)
    select
      id as resource,
      case
        when exp_1.exempt_id is not null then 'alarm'
        when e_1.exempt_id is not null and exp_1.exempt_id is null then 'skip'
        when kubernetes_version < '1.25' then 'alarm'
        when kubernetes_version < '1.27' then 'info'
        else 'ok'
      end as status,
      case
        when exp_1.exempt_id is not null
          then name || ' has EXPIRED exemption (expired: ' || e_1.exemption_expiry || ').' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
        when e_1.exempt_id is not null
          then name || ' is exempt.' || coalesce(' Reason: ' || e_1.exemption_reason || '.', '')
        when kubernetes_version < '1.25' then name || ' runs outdated Kubernetes ' || kubernetes_version || ' (upgrade for security improvements).'
        when kubernetes_version < '1.27' then name || ' runs Kubernetes ' || kubernetes_version || ' (consider upgrading).'
        else name || ' runs current Kubernetes ' || kubernetes_version || '.'
      end as reason,
      subscription_id
    from
      all_azure.azure_kubernetes_cluster
      left join exempt_1 as e_1 on all_azure.azure_kubernetes_cluster.id = e_1.exempt_id
      left join expired_1 as exp_1 on all_azure.azure_kubernetes_cluster.id = exp_1.exempt_id
  EOQ
}

query "ksi_svc_06_1_azure_check" {
  sql = <<-EOQ
        with exempt_1 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_key_vault_key
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-06.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_1 as (
          select exempt_id from exempt_1
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Key Vault key rotation policy configured (best practice)
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
            when rotation_policy is not null then name || ' has key rotation policy configured.'
            else name || ' does not have key rotation policy (consider automatic rotation).'
          end as reason,
          subscription_id
        from
          all_azure.azure_key_vault_key
          left join exempt_1 as e_1 on all_azure.azure_key_vault_key.id = e_1.exempt_id
          left join expired_1 as exp_1 on all_azure.azure_key_vault_key.id = exp_1.exempt_id
  EOQ
}

query "ksi_svc_06_2_azure_check" {
  sql = <<-EOQ
        with exempt_2 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_key_vault_key
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-06.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_2 as (
          select exempt_id from exempt_2
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Key Vault keys have expiration dates (CIS Azure 8.1)
        select
          id as resource,
          case
            when exp_2.exempt_id is not null then 'alarm'
            when e_2.exempt_id is not null and exp_2.exempt_id is null then 'skip'
            when expires_at is not null and expires_at > current_timestamp then 'ok'
            when expires_at is null then 'alarm'
            else 'alarm'
          end as status,
          case
            when exp_2.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_2.exemption_expiry || ').' || coalesce(' Reason: ' || e_2.exemption_reason || '.', '')
            when e_2.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_2.exemption_reason || '.', '')
            when expires_at is not null and expires_at > current_timestamp then name || ' has valid expiration date: ' || expires_at::date || '.'
            when expires_at is null then name || ' does not have an expiration date (should rotate regularly).'
            else name || ' has expired (rotate immediately).'
          end as reason,
          subscription_id
        from
          all_azure.azure_key_vault_key
          left join exempt_2 as e_2 on all_azure.azure_key_vault_key.id = e_2.exempt_id
          left join expired_2 as exp_2 on all_azure.azure_key_vault_key.id = exp_2.exempt_id
  EOQ
}

query "ksi_svc_06_3_azure_check" {
  sql = <<-EOQ
        with exempt_3 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_key_vault_secret
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-06.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_3 as (
          select exempt_id from exempt_3
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Key Vault secrets have expiration dates (CIS Azure 8.2)
        select
          id as resource,
          case
            when exp_3.exempt_id is not null then 'alarm'
            when e_3.exempt_id is not null and exp_3.exempt_id is null then 'skip'
            when expires_at is not null and expires_at > current_timestamp then 'ok'
            when expires_at is null then 'alarm'
            else 'alarm'
          end as status,
          case
            when exp_3.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_3.exemption_expiry || ').' || coalesce(' Reason: ' || e_3.exemption_reason || '.', '')
            when e_3.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_3.exemption_reason || '.', '')
            when expires_at is not null and expires_at > current_timestamp then name || ' has valid expiration date: ' || expires_at::date || '.'
            when expires_at is null then name || ' does not have an expiration date (should rotate regularly).'
            else name || ' has expired (rotate immediately).'
          end as reason,
          subscription_id
        from
          all_azure.azure_key_vault_secret
          left join exempt_3 as e_3 on all_azure.azure_key_vault_secret.id = e_3.exempt_id
          left join expired_3 as exp_3 on all_azure.azure_key_vault_secret.id = exp_3.exempt_id
  EOQ
}

query "ksi_svc_06_4_azure_check" {
  sql = <<-EOQ
        with exempt_4 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_key_vault_certificate
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-06.4' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_4 as (
          select exempt_id from exempt_4
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Key Vault certificates expiration (best practice)
        select
          id as resource,
          case
            when exp_4.exempt_id is not null then 'alarm'
            when e_4.exempt_id is not null and exp_4.exempt_id is null then 'skip'
            when expires > (current_timestamp + interval '30 days') then 'ok'
            when expires > current_timestamp then 'info'
            else 'alarm'
          end as status,
          case
            when exp_4.exempt_id is not null
              then name || ' has EXPIRED exemption (expired: ' || e_4.exemption_expiry || ').' || coalesce(' Reason: ' || e_4.exemption_reason || '.', '')
            when e_4.exempt_id is not null
              then name || ' is exempt.' || coalesce(' Reason: ' || e_4.exemption_reason || '.', '')
            when expires > (current_timestamp + interval '30 days') then name || ' certificate is valid until ' || expires::date || '.'
            when expires > current_timestamp then name || ' certificate expires soon on ' || expires::date || ' (rotate).'
            else name || ' certificate has expired (rotate immediately).'
          end as reason,
          subscription_id
        from
          all_azure.azure_key_vault_certificate
          left join exempt_4 as e_4 on all_azure.azure_key_vault_certificate.id = e_4.exempt_id
          left join expired_4 as exp_4 on all_azure.azure_key_vault_certificate.id = exp_4.exempt_id
  EOQ
}

query "ksi_svc_06_5_azure_check" {
  sql = <<-EOQ
        with exempt_5 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_application_gateway
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-06.5' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_5 as (
          select exempt_id from exempt_5
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Application Gateway SSL certificates (best practice)
        select
          id as resource,
          case
            when exp_5.exempt_id is not null then 'alarm'
            when e_5.exempt_id is not null and exp_5.exempt_id is null then 'skip'
            when ssl_certificates is not null and jsonb_array_length(ssl_certificates) > 0 then 'info'
            else 'ok'
          end as status,
          name || ' has ' || coalesce(jsonb_array_length(ssl_certificates), 0) || ' SSL certificates configured (verify expiration dates).' as reason,
          subscription_id
        from
          all_azure.azure_application_gateway
          left join exempt_5 as e_5 on all_azure.azure_application_gateway.id = e_5.exempt_id
          left join expired_5 as exp_5 on all_azure.azure_application_gateway.id = exp_5.exempt_id
  EOQ
}

query "ksi_svc_06_6_azure_check" {
  sql = <<-EOQ
        with exempt_6 as (
          select
            id as exempt_id,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            all_azure.azure_storage_account
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-SVC-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-SVC-06.6' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_6 as (
          select exempt_id from exempt_6
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Storage Account access keys rotation (best practice)
        select
          id as resource,
          'info' as status,
          name || ' uses storage account keys (rotate regularly - consider using SAS tokens or Azure AD).' as reason,
          subscription_id
        from
          all_azure.azure_storage_account
          left join exempt_6 as e_6 on all_azure.azure_storage_account.id = e_6.exempt_id
          left join expired_6 as exp_6 on all_azure.azure_storage_account.id = exp_6.exempt_id
        where
          primary_blob_endpoint is not null
        limit 10
  EOQ
}
