dashboard "fedramp_20x_overview" {
  title = "FedRAMP 20x Overview"

  container {
    card {
      title = "Total Controls"
      width = 3
      type  = "info"
      sql   = "select 14 as value"
    }

    card {
      title = "Critical Severity"
      width = 3
      type  = "alert"
      sql   = "select 2 as value"
    }

    card {
      title = "High Severity"
      width = 3
      type  = "alert"
      sql   = "select 9 as value"
    }

    card {
      title = "Medium Severity"
      width = 3
      type  = "info"
      sql   = "select 3 as value"
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
          4 as count
        union all
        select 'KSI-CNA (Cloud Native Architecture)', 4
        union all
        select 'KSI-MLA (Monitoring & Logging)', 1
        union all
        select 'KSI-INR (Incident Response)', 1
        union all
        select 'KSI-PIY (Policy & Inventory)', 1
        union all
        select 'KSI-RPL (Recovery Planning)', 1
        union all
        select 'KSI-SVC (Service Configuration)', 2
      EOQ
    }

    chart {
      title = "Controls by Severity"
      width = 6
      type  = "column"
      sql   = <<-EOQ
        select
          severity,
          count
        from (
          select 'Critical' as severity, 2 as count
          union all
          select 'High', 9
          union all
          select 'Medium', 3
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
    table {
      title = "All FedRAMP 20x KSI Controls"
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
            ('KSI-IAM-02', 'Strong Password Policies', 'high', 'Identity & Access Management'),
            ('KSI-IAM-03', 'Non-User Account Authentication', 'high', 'Identity & Access Management'),
            ('KSI-IAM-05', 'Least Privilege Access', 'high', 'Identity & Access Management'),
            ('KSI-CNA-01', 'Network Traffic Limits', 'high', 'Cloud Native Architecture'),
            ('KSI-CNA-02', 'Minimal Attack Surface', 'high', 'Cloud Native Architecture'),
            ('KSI-CNA-03', 'Traffic Flow Controls', 'high', 'Cloud Native Architecture'),
            ('KSI-CNA-04', 'Immutable Infrastructure', 'high', 'Cloud Native Architecture'),
            ('KSI-MLA-01', 'Centralized Logging (SIEM)', 'critical', 'Monitoring, Logging & Auditing'),
            ('KSI-INR-01', 'Incident Response Procedures', 'high', 'Incident Response'),
            ('KSI-PIY-01', 'Real-Time Inventory Generation', 'medium', 'Policy & Inventory'),
            ('KSI-RPL-01', 'Recovery Time and Point Objectives', 'high', 'Recovery Planning'),
            ('KSI-SVC-01', 'Security Improvement Evaluation', 'medium', 'Service Configuration'),
            ('KSI-SVC-06', 'Key and Certificate Management', 'high', 'Service Configuration')
        ) as controls(control_id, title, severity, category)
        order by control_id
      EOQ
    }
  }
}
