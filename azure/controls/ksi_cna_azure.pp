# KSI-CNA: Cloud Native Architecture Controls - Azure

control "ksi_cna_01_azure" {
  title       = "KSI-CNA-01: Network Traffic Limits"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"

  query = query.ksi_cna_01_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

control "ksi_cna_02_azure" {
  title       = "KSI-CNA-02: Minimal Attack Surface"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"

  query = query.ksi_cna_02_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_03_azure" {
  title       = "KSI-CNA-03: Traffic Flow Controls"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"

  query = query.ksi_cna_03_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

control "ksi_cna_04_azure" {
  title       = "KSI-CNA-04: Immutable Infrastructure"
  description = "Use immutable infrastructure with strictly defined functionality and privileges by default."
  severity    = "high"

  query = query.ksi_cna_04_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-04"
    nist_800_53 = "cm-2,si-3"
  }
}
