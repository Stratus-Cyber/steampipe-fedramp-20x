# KSI-IAM: Identity and Access Management Controls - Entra ID

control "ksi_iam_01_entraid" {
  title       = "KSI-IAM-01: Phishing-Resistant MFA"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
  severity    = "critical"
  query       = query.ksi_iam_01_entraid_check

  tags = {
    type        = "Entra ID"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}

control "ksi_iam_02_entraid" {
  title       = "KSI-IAM-02: Passwordless Authentication"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
  severity    = "high"
  query       = query.ksi_iam_02_entraid_check

  tags = {
    type        = "Entra ID"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}

control "ksi_iam_04_entraid" {
  title       = "KSI-IAM-04: Just-in-Time Authorization"
  description = "Ensure privileged access requires activation through Privileged Identity Management (PIM) for just-in-time authorization."
  severity    = "high"
  query       = query.ksi_iam_04_entraid_check

  tags = {
    type        = "Entra ID"
    ksi_id      = "KSI-IAM-04"
    nist_800_53 = "ac-2,ac-2.5,ac-3,ac-6,ac-6.5,ia-11"
  }
}

control "ksi_iam_05_entraid" {
  title       = "KSI-IAM-05: Least Privilege Access"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"
  query       = query.ksi_iam_05_entraid_check

  tags = {
    type        = "Entra ID"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}

control "ksi_iam_07_entraid" {
  title       = "KSI-IAM-07: Automated Account Management"
  description = "Automate account lifecycle management including provisioning, deprovisioning, and access review processes."
  severity    = "high"
  query       = query.ksi_iam_07_entraid_check

  tags = {
    type        = "Entra ID"
    ksi_id      = "KSI-IAM-07"
    nist_800_53 = "ac-2,ac-2.1,ac-2.2,ac-2.3,ac-2.4,ac-2.7,ia-4,ia-5.8"
  }
}

# KSI-MLA: Monitoring, Logging, Auditing Controls - Entra ID

control "ksi_mla_08_entraid" {
  title       = "KSI-MLA-08: Log Data Access"
  description = "Restrict access to audit logs and security data to authorized personnel through PIM activation or documented role assignments."
  severity    = "medium"
  query       = query.ksi_mla_08_entraid_check

  tags = {
    type        = "Entra ID"
    ksi_id      = "KSI-MLA-08"
    nist_800_53 = "au-9,au-9.2,au-9.4,ac-6"
  }
}
