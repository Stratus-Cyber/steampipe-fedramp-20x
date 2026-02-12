# KSI-MLA: Monitoring, Logging, Auditing Queries - Entra ID
# Updated for azuread.* plugin schema

query "ksi_mla_08_entraid_check" {
  sql = <<-EOQ
    -- KSI-MLA-08: Log Data Access
    -- Check access to audit logs and security data requires PIM activation or restricted roles

    select
      a.id as resource,
      case
        when r.display_name in ('Security Reader', 'Security Administrator', 'Compliance Administrator', 'Global Reader')
          then 'info'
        when r.display_name in ('Global Administrator', 'Privileged Role Administrator')
          then 'alarm'
        else 'ok'
      end as status,
      case
        when r.display_name in ('Security Reader', 'Security Administrator', 'Compliance Administrator', 'Global Reader')
          then 'Principal ' || a.principal_id || ' has permanent ' || r.display_name || ' role (can access log data - verify PIM required).'
        when r.display_name in ('Global Administrator', 'Privileged Role Administrator')
          then 'Principal ' || a.principal_id || ' has permanent ' || r.display_name || ' role (UNRESTRICTED log access - should require PIM).'
        else 'Principal ' || a.principal_id || ' role ' || r.display_name || ' does not grant sensitive log access.'
      end as reason,
      a.tenant_id
    from
      azuread.azuread_directory_role_assignment as a
      join azuread.azuread_directory_role as r on a.role_definition_id = r.id
    where
      r.display_name like '%Security%'
      or r.display_name like '%Compliance%'
      or r.display_name like '%Global%'

    union all

    -- Check for users with privileged audit log access through PIM eligibility
    select
      principal_id || '-' || role_definition_id as resource,
      'ok' as status,
      'Principal ' || principal_id || ' has eligible (JIT) assignment for privileged role (appropriate log data access control).' as reason,
      tenant_id
    from
      azuread.azuread_directory_role_eligibility_schedule_instance
    where
      role_definition_id in (
        select id from azuread.azuread_directory_role
        where display_name like '%Security%'
          or display_name like '%Compliance%'
          or display_name like '%Audit%'
      )
  EOQ
}
