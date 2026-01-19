# KSI-MLA: Monitoring, Logging, Auditing Controls - Azure

control "ksi_mla_01_azure" {
  title       = "KSI-MLA-01: Centralized Logging (SIEM)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"

  query = query.ksi_mla_01_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}
