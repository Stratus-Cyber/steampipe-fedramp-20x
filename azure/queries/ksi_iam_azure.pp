# KSI-IAM: Identity and Access Management Queries - Azure

query "ksi_iam_01_azure_check" {
  sql = <<-EOQ
    -- Check MFA is enabled for users
    select
      u.id as resource,
      case
        when u.account_enabled and 
          exists (
            select 1 from azure_ad_user_registration_details r 
            where r.id = u.id and r.is_mfa_registered
          ) then 'ok'
        when not u.account_enabled then 'info'
        else 'alarm'
      end as status,
      case
        when u.account_enabled and 
          exists (
            select 1 from azure_ad_user_registration_details r 
            where r.id = u.id and r.is_mfa_registered
          ) then u.display_name || ' has MFA registered.'
        when not u.account_enabled then u.display_name || ' account is disabled.'
        else u.display_name || ' does not have MFA registered.'
      end as reason,
      u.tenant_id as subscription_id
    from
      azure_ad_user as u

    union all

    -- Check SQL database AD admin configured
    select
      id as resource,
      case
        when server_azure_ad_administrator is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when server_azure_ad_administrator is not null then name || ' has Azure AD administrator configured.'
        else name || ' does not have Azure AD administrator configured.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_sql_server
  EOQ
}

query "ksi_iam_02_azure_check" {
  sql = <<-EOQ
    -- Check users have strong authentication methods
    select
      u.id as resource,
      case
        when u.account_enabled and u.user_type = 'Member' then 'ok'
        when not u.account_enabled then 'info'
        else 'info'
      end as status,
      case
        when u.account_enabled and u.user_type = 'Member' then u.display_name || ' is a member account with Azure AD authentication.'
        when not u.account_enabled then u.display_name || ' account is disabled.'
        else u.display_name || ' is a ' || u.user_type || ' account.'
      end as reason,
      u.tenant_id as subscription_id
    from
      azure_ad_user as u

    union all

    -- Check App Service authentication enabled
    select
      id as resource,
      case
        when auth_settings ->> 'enabled' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when auth_settings ->> 'enabled' = 'true' then name || ' has authentication enabled.'
        else name || ' does not have authentication enabled.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_app_service_web_app
  EOQ
}

query "ksi_iam_03_azure_check" {
  sql = <<-EOQ
    -- Check service principals with credentials
    select
      id as resource,
      case
        when account_enabled then 'ok'
        else 'info'
      end as status,
      case
        when account_enabled then display_name || ' service principal is enabled.'
        else display_name || ' service principal is disabled.'
      end as reason,
      tenant_id as subscription_id
    from
      azure_ad_service_principal
    where
      service_principal_type = 'Application'

    union all

    -- Check managed identities are used for services
    select
      id as resource,
      case
        when identity is not null and identity ->> 'type' != 'None' then 'ok'
        else 'alarm'
      end as status,
      case
        when identity is not null and identity ->> 'type' != 'None' then name || ' uses managed identity (' || (identity ->> 'type') || ').'
        else name || ' does not use managed identity.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_compute_virtual_machine
  EOQ
}

query "ksi_iam_05_azure_check" {
  sql = <<-EOQ
    -- Check for custom RBAC roles with overly permissive access
    select
      id as resource,
      case
        when permissions @> '[{"actions": ["*"]}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when permissions @> '[{"actions": ["*"]}]' then role_name || ' has wildcard (*) permissions.'
        else role_name || ' does not have wildcard permissions.'
      end as reason,
      subscription_id
    from
      azure_role_definition
    where
      role_type = 'CustomRole'

    union all

    -- Check role assignments scope
    select
      id as resource,
      case
        when scope = '/' or scope like '/subscriptions/%' and scope not like '/subscriptions/%/resourceGroups/%' then 'info'
        else 'ok'
      end as status,
      case
        when scope = '/' then principal_id || ' has role assignment at root scope.'
        when scope like '/subscriptions/%' and scope not like '/subscriptions/%/resourceGroups/%' then principal_id || ' has role assignment at subscription scope.'
        else principal_id || ' has role assignment at resource/group scope.'
      end as reason,
      subscription_id
    from
      azure_role_assignment

    union all

    -- Check storage account access restrictions
    select
      id as resource,
      case
        when network_rule_default_action = 'Deny' then 'ok'
        else 'alarm'
      end as status,
      case
        when network_rule_default_action = 'Deny' then name || ' has network access restricted (default deny).'
        else name || ' allows network access by default.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account
  EOQ
}
