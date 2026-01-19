# KSI-IAM: Identity and Access Management Controls - Azure

control "ksi_iam_01_azure" {
  title       = "KSI-IAM-01: Phishing-Resistant MFA"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
  severity    = "critical"

  query = query.ksi_iam_01_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}

control "ksi_iam_02_azure" {
  title       = "KSI-IAM-02: Strong Password Policies"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
  severity    = "high"

  query = query.ksi_iam_02_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}

control "ksi_iam_03_azure" {
  title       = "KSI-IAM-03: Non-User Account Authentication"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"

  query = query.ksi_iam_03_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

control "ksi_iam_05_azure" {
  title       = "KSI-IAM-05: Least Privilege Access"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"

  query = query.ksi_iam_05_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}
