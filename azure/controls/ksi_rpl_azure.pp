# KSI-RPL: Recovery Planning Controls - Azure

control "ksi_rpl_01_azure" {
  title       = "KSI-RPL-01: Recovery Time and Point Objectives"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
  severity    = "high"

  query = query.ksi_rpl_01_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}
