dashboard "fedramp_20x_aws_overview" {
  title = "FedRAMP 20x - AWS"

  tags = {
    type      = "AWS"
    framework = "FedRAMP 20x"
  }

  container {
    card {
      title = "Total Controls"
      width = 3
      type  = "info"
      sql   = "select 14 as total"
    }

    card {
      title = "Critical Severity"
      width = 3
      type  = "alert"
      sql   = "select 2 as total"
    }

    card {
      title = "High Severity"
      width = 3
      type  = "alert"
      sql   = "select 9 as total"
    }

    card {
      title = "Medium Severity"
      width = 3
      type  = "info"
      sql   = "select 3 as total"
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
    chart {
      title = "Controls by Category (Detailed)"
      width = 12
      type  = "column"
      sql   = <<-EOQ
        select
          'KSI-IAM (Identity & Access)' as category,
          4 as count
        union all
        select 'KSI-CNA (Cloud Native Architecture)', 4
        union all
        select 'KSI-SVC (Service Configuration)', 2
        union all
        select 'KSI-MLA (Monitoring & Logging)', 1
        union all
        select 'KSI-INR (Incident Response)', 1
        union all
        select 'KSI-PIY (Policy & Inventory)', 1
        union all
        select 'KSI-RPL (Recovery Planning)', 1
        order by count desc
      EOQ
    }
  }

  container {
    table {
      title = "All FedRAMP 20x KSI Controls - AWS"
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

  container {
    card {
      title = "Exempt Resources"
      width = 6
      type  = "info"
      sql   = <<-EOQ
        select count(*) as total
        from aws_tagging_resource
        where tags->>'${var.exemption_tag_key}' is not null
      EOQ
    }

    card {
      title = "Expired Exemptions"
      width = 6
      type  = "alert"
      sql   = <<-EOQ
        select count(*) as total
        from aws_tagging_resource
        where tags->>'${var.exemption_tag_key}' is not null
          and tags->>'${var.exemption_expiry_tag}' is not null
          and (tags->>'${var.exemption_expiry_tag}')::date < current_date
      EOQ
    }
  }

  container {
    table {
      title = "AWS Exempt Resources"
      width = 12
      sql   = <<-EOQ
        select
          arn as resource,
          resource_type,
          tags->>'${var.exemption_tag_key}' as exempt_controls,
          tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
          case
            when tags->>'${var.exemption_expiry_tag}' is not null
              and (tags->>'${var.exemption_expiry_tag}')::date < current_date
              then 'Expired'
            else 'Active'
          end as exemption_status,
          account_id,
          region
        from
          aws_tagging_resource
        where
          tags->>'${var.exemption_tag_key}' is not null
        order by
          case
            when tags->>'${var.exemption_expiry_tag}' is not null
              and (tags->>'${var.exemption_expiry_tag}')::date < current_date then 1
            else 2
          end,
          resource_type,
          arn
      EOQ
    }
  }
}
