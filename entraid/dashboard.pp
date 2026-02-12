dashboard "fedramp_20x_entraid_overview" {
  title = "FedRAMP 20x - Entra ID"

  tags = {
    type      = "Entra ID"
    framework = "FedRAMP 20x"
  }

  container {
    card {
      title = "Total Controls"
      width = 3
      type  = "info"
      sql   = "select 6 as total"
    }

    card {
      title = "Critical Severity"
      width = 3
      type  = "alert"
      sql   = "select 1 as total"
    }

    card {
      title = "High Severity"
      width = 3
      type  = "alert"
      sql   = "select 4 as total"
    }

    card {
      title = "Medium Severity"
      width = 3
      type  = "info"
      sql   = "select 1 as total"
    }
  }

  container {
    chart {
      title = "Controls by Category"
      width = 6
      type  = "donut"
      sql   = <<-EOQ
        select
          'KSI-IAM (Identity & Access)' as category,
          5 as count
        union all
        select 'KSI-MLA (Monitoring & Logging)', 1
      EOQ
    }

    chart {
      title = "Controls by Severity"
      width = 6
      type  = "column"

      series critical {
        title = "Critical"
        color = "red"
      }

      series high {
        title = "High"
        color = "yellow"
      }

      series medium {
        title = "Medium"
        color = "blue"
      }

      sql   = <<-EOQ
        select
          severity,
          count
        from (
          select 'Critical' as severity, 1 as count
          union all
          select 'High', 4
          union all
          select 'Medium', 1
        ) as severity_data
        order by
          case severity
            when 'Critical' then 1
            when 'High' then 2
            when 'Medium' then 3
          end
      EOQ
    }
  }

  container {
    chart {
      title = "Controls by Category (Detailed)"
      width = 12
      type  = "column"
      sql   = <<-EOQ
        select
          'KSI-IAM (Identity & Access)' as category,
          5 as count
        union all
        select 'KSI-MLA (Monitoring & Logging)', 1
        order by count desc
      EOQ
    }
  }

  container {
    table {
      title = "All FedRAMP 20x KSI Controls - Entra ID"
      width = 12
      sql   = <<-EOQ
        select
          control_id,
          title,
          severity,
          category
        from (
          values
            ('KSI-IAM-01', 'Phishing-Resistant MFA', 'critical', 'Identity & Access Management'),
            ('KSI-IAM-02', 'Passwordless Authentication', 'high', 'Identity & Access Management'),
            ('KSI-IAM-04', 'Just-in-Time Authorization', 'high', 'Identity & Access Management'),
            ('KSI-IAM-05', 'Least Privilege Access', 'high', 'Identity & Access Management'),
            ('KSI-IAM-07', 'Automated Account Management', 'high', 'Identity & Access Management'),
            ('KSI-MLA-08', 'Log Data Access', 'medium', 'Monitoring, Logging & Auditing')
        ) as controls(control_id, title, severity, category)
        order by control_id
      EOQ
    }
  }
}
