# Azure FedRAMP 20x Compliance Dashboard

dashboard "azure_compliance_overview" {
  title = "Azure Compliance Overview"

  tags = {
    type = "Azure"
  }

  container {
    card {
      title = "Azure AD Users"
      width = 3
      query = query.azure_ad_user_count
    }

    card {
      title = "Storage Accounts"
      width = 3
      query = query.azure_storage_account_count
    }

    card {
      title = "Key Vaults"
      width = 3
      query = query.azure_key_vault_count
    }

    card {
      title = "Network Security Groups"
      width = 3
      query = query.azure_nsg_count
    }
  }

  container {
    chart {
      title = "Users by Type"
      width = 6
      type  = "donut"
      query = query.azure_user_type_status
    }

    chart {
      title = "Storage Accounts by HTTPS Enforcement"
      width = 6
      type  = "donut"
      query = query.azure_storage_https_status
    }
  }

  container {
    table {
      title = "Azure AD Users"
      width = 12
      query = query.azure_ad_user_list
    }
  }
}

# ============================================================================
# AZURE QUERIES
# ============================================================================

query "azure_ad_user_count" {
  sql = <<-EOQ
    select count(*) as value
    from azuread_user
  EOQ
}

query "azure_storage_account_count" {
  sql = <<-EOQ
    select count(*) as value
    from azure_storage_account
  EOQ
}

query "azure_key_vault_count" {
  sql = <<-EOQ
    select count(*) as value
    from azure_key_vault
  EOQ
}

query "azure_nsg_count" {
  sql = <<-EOQ
    select count(*) as value
    from azure_network_security_group
  EOQ
}

query "azure_user_type_status" {
  sql = <<-EOQ
    select
      user_type as status,
      count(*) as count
    from azuread_user
    group by user_type
  EOQ
}

query "azure_storage_https_status" {
  sql = <<-EOQ
    select
      case
        when enable_https_traffic_only then 'HTTPS Enforced'
        else 'HTTPS Not Enforced'
      end as status,
      count(*) as count
    from azure_storage_account
    group by enable_https_traffic_only
  EOQ
}

query "azure_ad_user_list" {
  sql = <<-EOQ
    select
      display_name as "User",
      user_principal_name as "UPN",
      user_type as "Type",
      case when account_enabled then 'Yes' else 'No' end as "Enabled",
      created_date_time as "Created"
    from azuread_user
    order by display_name
  EOQ
}
