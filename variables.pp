# Variables for FedRAMP 20x Compliance Checks

# Exemption Tag Configuration
# Resources with the exemption tag will be excluded from specific compliance controls
# The tag VALUE contains a colon-separated list of KSI control IDs to exempt
# Example: fedramp20x_exempt = "KSI-IAM-01:KSI-CNA-02"

# Primary exemption tag (OPTIONAL - only add to resources that need exemption)
# Value = colon-separated list of control IDs the resource is exempt from
# Example: fedramp20x_exempt = "KSI-IAM-01"
# Example: fedramp20x_exempt = "KSI-IAM-01:KSI-CNA-02:KSI-SVC-06"
variable "exemption_tag_key" {
  type        = string
  description = "Tag key used to identify resources exempt from specific compliance controls. Value must be a colon-separated list of KSI control IDs (e.g., 'KSI-IAM-01:KSI-CNA-02'). The fedramp20x_exempt_reason tag is optional for documentation."
  default     = "fedramp20x_exempt"
}

# Exemption reason tag (OPTIONAL - for documentation only)
# Example: fedramp20x_exempt_reason = "Compensating control via hardware token"
# Note: This tag is optional. Exemptions work without it.
variable "exemption_reason_key" {
  type        = string
  description = "Tag key for optional exemption reason. If present on a resource, the value will be displayed in reports for documentation purposes. Not required for exemption to work."
  default     = "fedramp20x_exempt_reason"
}

# Alternative: Use environment-based exemptions
variable "exempt_environments" {
  type        = list(string)
  description = "List of environment tag values to exclude (e.g., ['dev', 'test', 'sandbox'])"
  default     = ["dev", "test", "sandbox"]
}

# Exemption expiration tracking (OPTIONAL)
# No expiration if this tag is not present
variable "exemption_expiry_tag" {
  type        = string
  description = "Tag key that contains the OPTIONAL expiration date for the exemption (YYYY-MM-DD format). If not set, exemption has no expiration. If set and date is past, exemption is treated as expired (alarm)."
  default     = "fedramp20x_exempt_expiry"
}
