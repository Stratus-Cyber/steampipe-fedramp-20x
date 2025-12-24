mod "fedramp_20x_dashboards" {
  title       = "FedRAMP 20x Dashboards"
  description = "Custom dashboards for Steampipe data visualization"
  require {
    mod "github.com/turbot/steampipe-mod-aws-compliance.git" {
      version = "*"
    }
  }
}