# Simple Powerpipe Dashboard Example
# Customize the SQL queries to match your Steampipe data

dashboard "overview" {
  title = "Overview Dashboard"
  
  # Container for summary cards at the top
  container {
    
    card {
      title = "Total Items"
      width = 3
      query = query.total_items_count
    }
    
    card {
      title = "Active Items"
      width = 3
      type  = "info"
      query = query.active_items_count
    }
    
    card {
      title = "Warnings"
      width = 3
      type  = "alert"
      query = query.warning_count
    }
    
    card {
      title = "Critical"
      width = 3
      type  = "alert"
      query = query.critical_count
    }
  }

  # Main content area
  container {
    
    chart {
      title = "Items by Category"
      width = 6
      type  = "donut"
      query = query.items_by_category
    }
    
    chart {
      title = "Trend Over Time"
      width = 6
      type  = "line"
      query = query.items_over_time
    }
  }

  # Data table
  container {
    
    table {
      title = "Recent Items"
      width = 12
      query = query.recent_items
    }
  }
}

# ============================================================================
# QUERIES - Customize these SQL queries for your Steampipe data
# ============================================================================

# Example: Count total items
query "total_items_count" {
  sql = <<-EOQ
    select count(*) as value
    from information_schema.tables
    where table_schema = 'public'
  EOQ
}

# Example: Active items count
query "active_items_count" {
  sql = <<-EOQ
    select count(*) as value
    from information_schema.tables
    where table_schema = 'public'
  EOQ
}

# Example: Warning count (customize for your use case)
query "warning_count" {
  sql = <<-EOQ
    select 0 as value
  EOQ
}

# Example: Critical count (customize for your use case)
query "critical_count" {
  sql = <<-EOQ
    select 0 as value
  EOQ
}

# Example: Items by category for donut chart
query "items_by_category" {
  sql = <<-EOQ
    select 
      table_type as category,
      count(*) as count
    from information_schema.tables
    where table_schema = 'public'
    group by table_type
  EOQ
}

# Example: Items over time for line chart
query "items_over_time" {
  sql = <<-EOQ
    select 
      now() - interval '7 days' as time,
      10 as count
    union all
    select 
      now() - interval '6 days',
      15
    union all
    select 
      now() - interval '5 days',
      12
    union all
    select 
      now() - interval '4 days',
      18
    union all
    select 
      now() - interval '3 days',
      20
    union all
    select 
      now() - interval '2 days',
      22
    union all
    select 
      now() - interval '1 day',
      25
    union all
    select 
      now(),
      28
  EOQ
}

# Example: Recent items table
query "recent_items" {
  sql = <<-EOQ
    select 
      table_name as "Name",
      table_type as "Type",
      table_schema as "Schema"
    from information_schema.tables
    where table_schema = 'public'
    order by table_name
    limit 20
  EOQ
}
