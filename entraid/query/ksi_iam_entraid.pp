# KSI-IAM: Identity and Access Management Queries - Entra ID
# Updated for azuread.* plugin schema

query "ksi_iam_01_entraid_check" {
  sql = <<-EOQ
    -- KSI-IAM-01: Phishing-Resistant MFA
    -- Check Conditional Access policies enforce phishing-resistant MFA methods

    select
      id as resource,
      case
        when state = 'enabled'
          and built_in_controls ? 'mfa' then 'ok'
        when state = 'disabled' then 'skip'
        else 'alarm'
      end as status,
      case
        when state = 'enabled'
          and built_in_controls ? 'mfa' then display_name || ' enforces MFA via Conditional Access.'
        when state = 'disabled' then display_name || ' is disabled.'
        else display_name || ' does not enforce phishing-resistant MFA.'
      end as reason,
      tenant_id
    from
      azuread.azuread_conditional_access_policy

    union all

    -- Check for users without MFA (if they exist and are enabled, MFA policy may be missing)
    select
      id as resource,
      case
        when account_enabled = false then 'skip'
        else 'info'
      end as status,
      case
        when account_enabled = false
          then display_name || ' (' || user_principal_name || ') is disabled.'
        else display_name || ' (' || user_principal_name || ') is enabled (verify MFA enforcement via CA policies).'
      end as reason,
      tenant_id
    from
      azuread.azuread_user
    where
      user_type = 'member'
  EOQ
}

query "ksi_iam_02_entraid_check" {
  sql = <<-EOQ
    -- KSI-IAM-02: Passwordless Authentication
    -- Check Conditional Access policies enforce passwordless authentication methods

    select
      id as resource,
      case
        when state = 'enabled'
          and (built_in_controls ? 'passwordAuthenticationMethod'
               or display_name ilike '%passwordless%') then 'ok'
        when state = 'enabled' then 'info'
        when state = 'disabled' then 'skip'
        else 'alarm'
      end as status,
      case
        when state = 'enabled'
          and (built_in_controls ? 'passwordAuthenticationMethod'
               or display_name ilike '%passwordless%')
          then display_name || ' enforces passwordless authentication methods.'
        when state = 'enabled'
          then display_name || ' is enabled but passwordless enforcement not explicitly configured.'
        when state = 'disabled'
          then display_name || ' is disabled.'
        else display_name || ' may not enforce passwordless authentication.'
      end as reason,
      tenant_id
    from
      azuread.azuread_conditional_access_policy

    union all

    -- Check enabled users (passwordless auth should be enforced via CA policies)
    select
      id as resource,
      'info' as status,
      display_name || ' (' || user_principal_name || ') should use passwordless authentication (verify CA policy enforcement).' as reason,
      tenant_id
    from
      azuread.azuread_user
    where
      user_type = 'member'
      and account_enabled = true
  EOQ
}

query "ksi_iam_04_entraid_check" {
  sql = <<-EOQ
    -- KSI-IAM-04: Just-in-Time Authorization
    -- Check PIM role eligibility schedules for privileged roles

    select
      principal_id || '-' || role_definition_id as resource,
      case
        when principal_id is not null then 'ok'
        else 'info'
      end as status,
      'Principal ' || principal_id || ' has eligible role assignment for role ' || role_definition_id || ' (JIT access configured).' as reason,
      tenant_id
    from
      azuread.azuread_directory_role_eligibility_schedule_instance

    union all

    -- Check for permanent privileged role assignments (should be minimal)
    select
      a.id as resource,
      case
        when r.display_name in ('Global Administrator', 'Privileged Role Administrator', 'Security Administrator') then 'alarm'
        else 'info'
      end as status,
      case
        when r.display_name in ('Global Administrator', 'Privileged Role Administrator', 'Security Administrator')
          then 'Principal ' || a.principal_id || ' has PERMANENT ' || r.display_name || ' role (should use PIM JIT instead).'
        else 'Principal ' || a.principal_id || ' has permanent assignment to ' || r.display_name || '.'
      end as reason,
      a.tenant_id
    from
      azuread.azuread_directory_role_assignment as a
      join azuread.azuread_directory_role as r on a.role_definition_id = r.id
  EOQ
}

query "ksi_iam_05_entraid_check" {
  sql = <<-EOQ
    -- KSI-IAM-05: Least Privilege
    -- Check for permanent privileged role assignments

    select
      a.id as resource,
      case
        when r.display_name in ('Global Administrator', 'Security Administrator', 'Privileged Role Administrator') then 'alarm'
        else 'ok'
      end as status,
      case
        when r.display_name in ('Global Administrator', 'Security Administrator', 'Privileged Role Administrator')
          then 'Principal ' || a.principal_id || ' has permanent ' || r.display_name || ' role (violates least privilege - use PIM).'
        else 'Principal ' || a.principal_id || ' role assignment ' || r.display_name || ' is appropriately scoped.'
      end as reason,
      a.tenant_id
    from
      azuread.azuread_directory_role_assignment as a
      join azuread.azuread_directory_role as r on a.role_definition_id = r.id

    union all

    -- Check for inactive users with roles (stale access)
    select
      u.id as resource,
      case
        when u.account_enabled = false then 'ok'
        when u.sign_in_activity is null then 'alarm'
        when (u.sign_in_activity->>'lastSignInDateTime')::timestamp < (current_timestamp - interval '90 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when u.account_enabled = false then u.display_name || ' is disabled (appropriate).'
        when u.sign_in_activity is null then u.display_name || ' has NEVER signed in but has role assignments (stale access).'
        when (u.sign_in_activity->>'lastSignInDateTime')::timestamp < (current_timestamp - interval '90 days')
          then u.display_name || ' has not signed in for ' ||
            date_part('day', current_timestamp - (u.sign_in_activity->>'lastSignInDateTime')::timestamp)::int ||
            ' days (stale access, violates least privilege).'
        else u.display_name || ' is actively used.'
      end as reason,
      u.tenant_id
    from
      azuread.azuread_user as u
    where
      u.user_type = 'member'
      and u.account_enabled = true
  EOQ
}

query "ksi_iam_07_entraid_check" {
  sql = <<-EOQ
    -- KSI-IAM-07: Automated Account Management
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
          then display_name || ' (' || user_principal_name || ') is disabled (appropriate for automated lifecycle).'
        when sign_in_activity is null
          then display_name || ' (' || user_principal_name || ') has NEVER signed in (should be auto-disabled).'
        when (sign_in_activity->>'lastSignInDateTime')::timestamp < (current_timestamp - interval '90 days')
          then display_name || ' (' || user_principal_name || ') has not signed in for ' ||
            date_part('day', current_timestamp - (sign_in_activity->>'lastSignInDateTime')::timestamp)::int ||
            ' days (should be auto-disabled by lifecycle policy).'
        else display_name || ' (' || user_principal_name || ') is actively used.'
      end as reason,
      tenant_id
    from
      azuread.azuread_user
    where
      user_type = 'member'

    union all

    -- Check service principal credentials for automated rotation
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
          then display_name || ' has credentials expiring soon or expired (automated rotation required).'
        else display_name || ' credentials are valid and managed.'
      end as reason,
      tenant_id
    from
      azuread.azuread_service_principal
    where
      account_enabled = true
  EOQ
}
