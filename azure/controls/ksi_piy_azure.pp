# KSI-PIY: Policy and Inventory Controls - Azure

control "ksi_piy_01_azure" {
  title       = "KSI-PIY-01: Real-Time Inventory Generation"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."
  severity    = "medium"

  query = query.ksi_piy_01_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}
