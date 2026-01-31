# KSI-IAM: Identity and Access Management Queries - Azure
# Updated for Turbot Pipes workspace schema (all_azure.* and azuread.*)

query "ksi_iam_01_azure_check" {
  sql = <<-EOQ
    -- Check MFA registration status for Azure AD users
    select
      id as resource,
      case
        when is_mfa_registered then 'ok'
        else 'alarm'
      end as status,
      case
        when is_mfa_registered then user_display_name || ' has MFA registered.'
        else user_display_name || ' does not have MFA registered.'
      end as reason,
      tenant_id
    from
      azuread.azuread_user_registration_details_report
    where
      user_type = 'member'

    union all

    -- Check conditional access policies require MFA
    select
      id as resource,
      case
        when state = 'enabled'
          and built_in_controls ? 'mfa' then 'ok'
        when state = 'disabled' then 'info'
        else 'alarm'
      end as status,
      case
        when state = 'enabled'
          and built_in_controls ? 'mfa' then display_name || ' requires MFA.'
        when state = 'disabled' then display_name || ' is disabled.'
        else display_name || ' does not require MFA.'
      end as reason,
      tenant_id
    from
      azuread.azuread_conditional_access_policy
  EOQ
}

query "ksi_iam_02_azure_check" {
  sql = <<-EOQ
    -- Check Key Vault key expiration dates set (CIS Azure 8.1)
    select
      id as resource,
      case
        when expires_at is not null and expires_at > current_timestamp then 'ok'
        when expires_at is null then 'alarm'
        else 'alarm'
      end as status,
      case
        when expires_at is not null and expires_at > current_timestamp then name || ' has valid expiration date.'
        when expires_at is null then name || ' does not have an expiration date set.'
        else name || ' has expired.'
      end as reason,
      subscription_id
    from
      all_azure.azure_key_vault_key

    union all

    -- Check Key Vault secret expiration dates set (CIS Azure 8.2)
    select
      id as resource,
      case
        when expires_at is not null and expires_at > current_timestamp then 'ok'
        when expires_at is null then 'alarm'
        else 'alarm'
      end as status,
      case
        when expires_at is not null and expires_at > current_timestamp then name || ' has valid expiration date.'
        when expires_at is null then name || ' does not have an expiration date set.'
        else name || ' has expired.'
      end as reason,
      subscription_id
    from
      all_azure.azure_key_vault_secret

    union all

    -- Check storage account requires secure transfer (CIS Azure 3.1)
    select
      id as resource,
      case
        when enable_https_traffic_only then 'ok'
        else 'alarm'
      end as status,
      case
        when enable_https_traffic_only then name || ' requires secure transfer (HTTPS).'
        else name || ' does not require secure transfer.'
      end as reason,
      subscription_id
    from
      all_azure.azure_storage_account
  EOQ
}

query "ksi_iam_03_azure_check" {
  sql = <<-EOQ
    -- Check service principals with password credentials
    select
      id as resource,
      case
        when password_credentials is null or jsonb_array_length(password_credentials) = 0 then 'ok'
        when jsonb_array_length(password_credentials) > 0 then 'info'
        else 'ok'
      end as status,
      case
        when password_credentials is null or jsonb_array_length(password_credentials) = 0 then display_name || ' uses certificate-based authentication only.'
        when jsonb_array_length(password_credentials) > 0 then display_name || ' uses password credentials (consider certificates).'
        else display_name || ' authentication method verified.'
      end as reason,
      tenant_id
    from
      azuread.azuread_service_principal
    where
      account_enabled = true

    union all

    -- Check managed identities used for Azure resources (best practice)
    select
      id as resource,
      case
        when identity is not null and identity ->> 'type' in ('SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned') then 'ok'
        else 'info'
      end as status,
      case
        when identity is not null and identity ->> 'type' in ('SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned') then name || ' uses managed identity.'
        else name || ' does not use managed identity (consider enabling).'
      end as reason,
      subscription_id
    from
      all_azure.azure_compute_virtual_machine

    union all

    -- Check SQL Server uses Azure AD authentication (CIS Azure 4.1.1)
    select
      id as resource,
      case
        when administrator_login_password is null then 'ok'
        else 'info'
      end as status,
      case
        when administrator_login_password is null then name || ' may be using Azure AD authentication.'
        else name || ' uses SQL authentication (consider Azure AD).'
      end as reason,
      subscription_id
    from
      all_azure.azure_sql_server

    union all

    -- Check App Service uses managed identity (CIS Azure 9.1)
    select
      id as resource,
      case
        when identity is not null and identity ->> 'type' in ('SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned') then 'ok'
        else 'alarm'
      end as status,
      case
        when identity is not null and identity ->> 'type' in ('SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned') then name || ' uses managed identity.'
        else name || ' does not use managed identity.'
      end as reason,
      subscription_id
    from
      all_azure.azure_app_service_web_app
  EOQ
}

query "ksi_iam_05_azure_check" {
  sql = <<-EOQ
    -- Check custom RBAC roles with wildcard permissions
    select
      id as resource,
      case
        when role_type = 'BuiltInRole' then 'skip'
        when permissions @> '[{"actions": ["*"]}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when role_type = 'BuiltInRole' then role_name || ' is a built-in role.'
        when permissions @> '[{"actions": ["*"]}]' then role_name || ' has wildcard (*) permissions - violates least privilege.'
        else role_name || ' follows least privilege principle.'
      end as reason,
      subscription_id
    from
      all_azure.azure_role_definition
    where
      role_type = 'CustomRole'

    union all

    -- Check for overly permissive role assignments at subscription level
    select
      ra.id as resource,
      case
        when rd.role_name in ('Owner', 'Contributor')
          and ra.scope like '/subscriptions/%'
          and ra.scope not like '/subscriptions/%/resourceGroups/%' then 'alarm'
        else 'ok'
      end as status,
      case
        when rd.role_name in ('Owner', 'Contributor')
          and ra.scope like '/subscriptions/%'
          and ra.scope not like '/subscriptions/%/resourceGroups/%' then 'Broad ' || rd.role_name || ' role assigned at subscription level for ' || ra.principal_id || '.'
        else 'Role assignment ' || rd.role_name || ' is appropriately scoped.'
      end as reason,
      ra.subscription_id
    from
      all_azure.azure_role_assignment as ra
      join all_azure.azure_role_definition as rd on ra.role_definition_id = rd.id

    union all

    -- Check guest users with admin roles (CIS Azure 1.18)
    select
      u.id as resource,
      case
        when u.user_type = 'Guest' then 'info'
        else 'ok'
      end as status,
      case
        when u.user_type = 'Guest' then u.display_name || ' is a guest user (review access periodically).'
        else u.display_name || ' is a member user.'
      end as reason,
      u.tenant_id
    from
      azuread.azuread_user as u

    union all

    -- Check for inactive users with active credentials (best practice)
    select
      id as resource,
      case
        when account_enabled = false then 'ok'
        when sign_in_activity is null then 'info'
        when (sign_in_activity->>'lastSignInDateTime')::timestamp < (current_timestamp - interval '90 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when account_enabled = false then display_name || ' account is disabled.'
        when sign_in_activity is null then display_name || ' has no sign-in activity recorded.'
        when (sign_in_activity->>'lastSignInDateTime')::timestamp < (current_timestamp - interval '90 days') then display_name || ' has not signed in for over 90 days.'
        else display_name || ' is actively used.'
      end as reason,
      tenant_id
    from
      azuread.azuread_user
    where
      account_enabled = true
  EOQ
}

query "ksi_iam_06_azure_check" {
  sql = <<-EOQ
    -- KSI-IAM-06: Suspicious Activity Response
    -- Detect and respond to suspicious authentication activity

    -- Check Microsoft Defender for Cloud is enabled for identity protection
    select
      id as resource,
      case
        when pricing_tier = 'Standard' then 'ok'
        else 'alarm'
      end as status,
      case
        when pricing_tier = 'Standard'
          then 'Microsoft Defender for ' || name || ' is enabled (detects suspicious activity).'
        else 'Microsoft Defender for ' || name || ' is NOT enabled.'
      end as reason,
      subscription_id
    from
      all_azure.azure_security_center_subscription_pricing
    where
      name in ('KeyVaults', 'Arm', 'OpenSourceRelationalDatabases')

    union all

    -- Check security alerts are configured
    select
      id as resource,
      case
        when email_addresses is not null and jsonb_array_length(email_addresses) > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when email_addresses is not null and jsonb_array_length(email_addresses) > 0
          then 'Security contact emails configured for alerts.'
        else 'NO security contact emails configured (cannot respond to suspicious activity).'
      end as reason,
      subscription_id
    from
      all_azure.azure_security_center_contact
  EOQ
}

query "ksi_iam_07_azure_check" {
  sql = <<-EOQ
    -- KSI-IAM-07: Automated Account Management
    -- Automate account lifecycle management

    -- Check for stale users not signed in for 90+ days
    select
      id as resource,
      case
        when account_enabled = false then 'ok'
        when sign_in_activity is null then 'alarm'
        when (sign_in_activity->>'lastSignInDateTime')::timestamp < (current_timestamp - interval '90 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when account_enabled = false
          then display_name || ' is disabled (appropriate for stale accounts).'
        when sign_in_activity is null
          then display_name || ' has NEVER signed in (stale account, should be disabled automatically).'
        when (sign_in_activity->>'lastSignInDateTime')::timestamp < (current_timestamp - interval '90 days')
          then display_name || ' has not signed in for ' ||
            date_part('day', current_timestamp - (sign_in_activity->>'lastSignInDateTime')::timestamp)::int ||
            ' days (stale account, should be disabled automatically).'
        else display_name || ' is actively used.'
      end as reason,
      tenant_id
    from
      azuread.azuread_user
    where
      user_type = 'member'

    union all

    -- Check service principal credentials are rotated
    select
      id as resource,
      case
        when password_credentials is null or jsonb_array_length(password_credentials) = 0 then 'ok'
        when exists (
          select 1 from jsonb_array_elements(password_credentials) as cred
          where (cred->>'endDateTime')::timestamp < (current_timestamp + interval '30 days')
        ) then 'alarm'
        else 'ok'
      end as status,
      case
        when password_credentials is null or jsonb_array_length(password_credentials) = 0
          then display_name || ' uses certificate-based auth (no password rotation needed).'
        when exists (
          select 1 from jsonb_array_elements(password_credentials) as cred
          where (cred->>'endDateTime')::timestamp < (current_timestamp + interval '30 days')
        )
          then display_name || ' has credentials expiring soon or expired (rotation should be automated).'
        else display_name || ' credentials are valid.'
      end as reason,
      tenant_id
    from
      azuread.azuread_service_principal
    where
      account_enabled = true
  EOQ
}
