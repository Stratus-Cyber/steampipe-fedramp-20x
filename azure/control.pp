# KSI-IAM: Identity and Access Management Controls - Azure

benchmark "ksi_iam_01_azure" {
  title       = "KSI-IAM-01: Phishing-Resistant MFA"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."

  children = [
    control.ksi_iam_01_1_azure,
    control.ksi_iam_01_2_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}
control "ksi_iam_01_1_azure" {
  title       = "KSI-IAM-01.1: Check MFA registration status for Azure AD users"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
  severity    = "critical"
  query       = query.ksi_iam_01_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}

control "ksi_iam_01_2_azure" {
  title       = "KSI-IAM-01.2: Check conditional access policies require MFA"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
  severity    = "critical"
  query       = query.ksi_iam_01_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}

benchmark "ksi_iam_02_azure" {
  title       = "KSI-IAM-02: Strong Password Policies"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."

  children = [
    control.ksi_iam_02_1_azure,
    control.ksi_iam_02_2_azure,
    control.ksi_iam_02_3_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}
control "ksi_iam_02_1_azure" {
  title       = "KSI-IAM-02.1: Check Key Vault key expiration dates set (CIS Azure 8.1)"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
  severity    = "high"
  query       = query.ksi_iam_02_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}

control "ksi_iam_02_2_azure" {
  title       = "KSI-IAM-02.2: Check Key Vault secret expiration dates set (CIS Azure 8.2)"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
  severity    = "high"
  query       = query.ksi_iam_02_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}

control "ksi_iam_02_3_azure" {
  title       = "KSI-IAM-02.3: Check storage account requires secure transfer (CIS Azure 3.1)"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
  severity    = "high"
  query       = query.ksi_iam_02_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}

benchmark "ksi_iam_03_azure" {
  title       = "KSI-IAM-03: Non-User Account Authentication"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."

  children = [
    control.ksi_iam_03_1_azure,
    control.ksi_iam_03_2_azure,
    control.ksi_iam_03_3_azure,
    control.ksi_iam_03_4_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}
control "ksi_iam_03_1_azure" {
  title       = "KSI-IAM-03.1: Check service principals with password credentials"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"
  query       = query.ksi_iam_03_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

control "ksi_iam_03_2_azure" {
  title       = "KSI-IAM-03.2: Check managed identities used for Azure resources (best practice)"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"
  query       = query.ksi_iam_03_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

control "ksi_iam_03_3_azure" {
  title       = "KSI-IAM-03.3: Check SQL Server uses Azure AD authentication (CIS Azure 4.1.1)"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"
  query       = query.ksi_iam_03_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

control "ksi_iam_03_4_azure" {
  title       = "KSI-IAM-03.4: Check App Service uses managed identity (CIS Azure 9.1)"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"
  query       = query.ksi_iam_03_4_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

benchmark "ksi_iam_05_azure" {
  title       = "KSI-IAM-05: Least Privilege Access"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."

  children = [
    control.ksi_iam_05_1_azure,
    control.ksi_iam_05_2_azure,
    control.ksi_iam_05_3_azure,
    control.ksi_iam_05_4_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}
control "ksi_iam_05_1_azure" {
  title       = "KSI-IAM-05.1: Check custom RBAC roles with wildcard permissions"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"
  query       = query.ksi_iam_05_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}

control "ksi_iam_05_2_azure" {
  title       = "KSI-IAM-05.2: Check for overly permissive role assignments at subscription level"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"
  query       = query.ksi_iam_05_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}

control "ksi_iam_05_3_azure" {
  title       = "KSI-IAM-05.3: Check guest users with admin roles (CIS Azure 1.18)"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"
  query       = query.ksi_iam_05_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}

control "ksi_iam_05_4_azure" {
  title       = "KSI-IAM-05.4: Check for inactive users with active credentials (best practice)"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"
  query       = query.ksi_iam_05_4_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}

# KSI-CNA: Cloud Native Architecture Controls - Azure

benchmark "ksi_cna_01_azure" {
  title       = "KSI-CNA-01: Network Traffic Limits"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."

  children = [
    control.ksi_cna_01_1_azure,
    control.ksi_cna_01_2_azure,
    control.ksi_cna_01_3_azure,
    control.ksi_cna_01_4_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}
control "ksi_cna_01_1_azure" {
  title       = "KSI-CNA-01.1: Check Network Security Groups have restrictive rules (CIS Azure 6.1, 6.2)"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"
  query       = query.ksi_cna_01_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

control "ksi_cna_01_2_azure" {
  title       = "KSI-CNA-01.2: Check VMs without network security groups (best practice)"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"
  query       = query.ksi_cna_01_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

control "ksi_cna_01_3_azure" {
  title       = "KSI-CNA-01.3: Check subnets have network security groups (CIS Azure 6.6)"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"
  query       = query.ksi_cna_01_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

control "ksi_cna_01_4_azure" {
  title       = "KSI-CNA-01.4: Check Application Gateway has Web Application Firewall enabled (CIS Azure 6.7)"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"
  query       = query.ksi_cna_01_4_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

benchmark "ksi_cna_02_azure" {
  title       = "KSI-CNA-02: Minimal Attack Surface"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."

  children = [
    control.ksi_cna_02_1_azure,
    control.ksi_cna_02_2_azure,
    control.ksi_cna_02_3_azure,
    control.ksi_cna_02_4_azure,
    control.ksi_cna_02_5_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}
control "ksi_cna_02_1_azure" {
  title       = "KSI-CNA-02.1: Check VM disks are encrypted (CIS Azure 7.1)"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_02_2_azure" {
  title       = "KSI-CNA-02.2: Check SQL Database (TDE is enabled by default for Azure SQL)"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_02_3_azure" {
  title       = "KSI-CNA-02.3: Check storage accounts use encryption (CIS Azure 3.2)"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_02_4_azure" {
  title       = "KSI-CNA-02.4: Check storage accounts use customer-managed keys (best practice)"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_4_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_02_5_azure" {
  title       = "KSI-CNA-02.5: Check Azure Kubernetes Service (AKS) uses disk encryption (CIS Azure 8.3)"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_5_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

benchmark "ksi_cna_03_azure" {
  title       = "KSI-CNA-03: Traffic Flow Controls"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."

  children = [
    control.ksi_cna_03_1_azure,
    control.ksi_cna_03_2_azure,
    control.ksi_cna_03_3_azure,
    control.ksi_cna_03_4_azure,
    control.ksi_cna_03_5_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}
control "ksi_cna_03_1_azure" {
  title       = "KSI-CNA-03.1: Check storage accounts allow secure transfer only (CIS Azure 3.1)"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

control "ksi_cna_03_2_azure" {
  title       = "KSI-CNA-03.2: Check Application Gateway uses SSL/TLS policies (best practice)"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

control "ksi_cna_03_3_azure" {
  title       = "KSI-CNA-03.3: Check Redis Cache uses SSL/TLS (CIS Azure 4.3.1)"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

control "ksi_cna_03_4_azure" {
  title       = "KSI-CNA-03.4: Check PostgreSQL SSL enforcement (CIS Azure 4.3.2)"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_4_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

control "ksi_cna_03_5_azure" {
  title       = "KSI-CNA-03.5: Check MySQL SSL enforcement (CIS Azure 4.3.3)"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_5_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

benchmark "ksi_cna_04_azure" {
  title       = "KSI-CNA-04: Immutable Infrastructure"
  description = "Use immutable infrastructure with strictly defined functionality and privileges by default."

  children = [
    control.ksi_cna_04_1_azure,
    control.ksi_cna_04_2_azure,
    control.ksi_cna_04_3_azure,
    control.ksi_cna_04_4_azure,
    control.ksi_cna_04_5_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-04"
    nist_800_53 = "cm-2,si-3"
  }
}
control "ksi_cna_04_1_azure" {
  title       = "KSI-CNA-04.1: Check VM scale sets use custom images (best practice for immutable infrastructure)"
  description = "Use immutable infrastructure with strictly defined functionality and privileges by default."
  severity    = "high"
  query       = query.ksi_cna_04_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-04"
    nist_800_53 = "cm-2,si-3"
  }
}

control "ksi_cna_04_2_azure" {
  title       = "KSI-CNA-04.2: Check AKS uses Azure Policy for pod security (best practice)"
  description = "Use immutable infrastructure with strictly defined functionality and privileges by default."
  severity    = "high"
  query       = query.ksi_cna_04_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-04"
    nist_800_53 = "cm-2,si-3"
  }
}

control "ksi_cna_04_3_azure" {
  title       = "KSI-CNA-04.3: Check container registries have admin user disabled (CIS Azure 9.7)"
  description = "Use immutable infrastructure with strictly defined functionality and privileges by default."
  severity    = "high"
  query       = query.ksi_cna_04_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-04"
    nist_800_53 = "cm-2,si-3"
  }
}

control "ksi_cna_04_4_azure" {
  title       = "KSI-CNA-04.4: Check App Service uses latest runtime (best practice for immutable infrastructure)"
  description = "Use immutable infrastructure with strictly defined functionality and privileges by default."
  severity    = "high"
  query       = query.ksi_cna_04_4_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-04"
    nist_800_53 = "cm-2,si-3"
  }
}

control "ksi_cna_04_5_azure" {
  title       = "KSI-CNA-04.5: Check storage account public access is disabled (CIS Azure 3.7)"
  description = "Use immutable infrastructure with strictly defined functionality and privileges by default."
  severity    = "high"
  query       = query.ksi_cna_04_5_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-CNA-04"
    nist_800_53 = "cm-2,si-3"
  }
}

# KSI-MLA: Monitoring, Logging, Auditing Controls - Azure

benchmark "ksi_mla_01_azure" {
  title       = "KSI-MLA-01: Centralized Logging (SIEM)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."

  children = [
    control.ksi_mla_01_1_azure,
    control.ksi_mla_01_2_azure,
    control.ksi_mla_01_3_azure,
    control.ksi_mla_01_4_azure,
    control.ksi_mla_01_5_azure,
    control.ksi_mla_01_6_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}
control "ksi_mla_01_1_azure" {
  title       = "KSI-MLA-01.1: Check Activity Log retention is at least 365 days (CIS Azure 5.1.1)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

control "ksi_mla_01_2_azure" {
  title       = "KSI-MLA-01.2: Check diagnostic settings for Key Vault (CIS Azure 5.1.5)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

control "ksi_mla_01_3_azure" {
  title       = "KSI-MLA-01.3: Check diagnostic settings for Network Security Groups (CIS Azure 6.5)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

control "ksi_mla_01_4_azure" {
  title       = "KSI-MLA-01.4: Check SQL Server (auditing is enabled by default for Azure SQL)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_4_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

control "ksi_mla_01_5_azure" {
  title       = "KSI-MLA-01.5: Check Log Analytics workspace retention (best practice)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_5_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

control "ksi_mla_01_6_azure" {
  title       = "KSI-MLA-01.6: Check Azure Monitor log alerts exist (best practice)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_6_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

# KSI-INR: Incident Response Controls - Azure

benchmark "ksi_inr_01_azure" {
  title       = "KSI-INR-01: Incident Response Procedures"
  description = "Persistently review the effectiveness of documented incident response procedures."

  children = [
    control.ksi_inr_01_1_azure,
    control.ksi_inr_01_2_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-INR-01"
    nist_800_53 = "ir-4,ir-4.1,ir-6,ir-6.1,ir-6.3,ir-7,ir-7.1,ir-8,ir-8.1,si-4.5"
  }
}
control "ksi_inr_01_1_azure" {
  title       = "KSI-INR-01.1: Check Azure Defender enabled for services (best practice)"
  description = "Persistently review the effectiveness of documented incident response procedures."
  severity    = "high"
  query       = query.ksi_inr_01_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-INR-01"
    nist_800_53 = "ir-4,ir-4.1,ir-6,ir-6.1,ir-6.3,ir-7,ir-7.1,ir-8,ir-8.1,si-4.5"
  }
}

control "ksi_inr_01_2_azure" {
  title       = "KSI-INR-01.2: Check activity log alerts for administrative operations (CIS Azure 5.2.1-5.2.9)"
  description = "Persistently review the effectiveness of documented incident response procedures."
  severity    = "high"
  query       = query.ksi_inr_01_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-INR-01"
    nist_800_53 = "ir-4,ir-4.1,ir-6,ir-6.1,ir-6.3,ir-7,ir-7.1,ir-8,ir-8.1,si-4.5"
  }
}

# KSI-PIY: Policy and Inventory Controls - Azure

benchmark "ksi_piy_01_azure" {
  title       = "KSI-PIY-01: Real-Time Inventory Generation"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."

  children = [
    control.ksi_piy_01_1_azure,
    control.ksi_piy_01_2_azure,
    control.ksi_piy_01_3_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}
control "ksi_piy_01_1_azure" {
  title       = "KSI-PIY-01.1: Check Azure Resource Graph can query resources (inventory capability)"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."
  severity    = "medium"
  query       = query.ksi_piy_01_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}

control "ksi_piy_01_2_azure" {
  title       = "KSI-PIY-01.2: Check Azure Policy assignments for governance (CIS Azure 2.1-2.12)"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."
  severity    = "medium"
  query       = query.ksi_piy_01_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}

control "ksi_piy_01_3_azure" {
  title       = "KSI-PIY-01.3: Check subscriptions have management groups for organizational inventory (best practice)"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."
  severity    = "medium"
  query       = query.ksi_piy_01_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}

# KSI-RPL: Recovery Planning Controls - Azure

benchmark "ksi_rpl_01_azure" {
  title       = "KSI-RPL-01: Recovery Time and Point Objectives"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."

  children = [
    control.ksi_rpl_01_1_azure,
    control.ksi_rpl_01_2_azure,
    control.ksi_rpl_01_3_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}
control "ksi_rpl_01_1_azure" {
  title       = "KSI-RPL-01.1: Check SQL Database (backup retention configured by default)"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
  severity    = "high"
  query       = query.ksi_rpl_01_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}

control "ksi_rpl_01_2_azure" {
  title       = "KSI-RPL-01.2: Check Storage Account replication for disaster recovery (best practice)"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
  severity    = "high"
  query       = query.ksi_rpl_01_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}

control "ksi_rpl_01_3_azure" {
  title       = "KSI-RPL-01.3: Check Azure Site Recovery configured for VMs (best practice)"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
  severity    = "high"
  query       = query.ksi_rpl_01_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}

# KSI-SVC: Service Configuration Controls - Azure

control "ksi_svc_01_azure" {
  title       = "KSI-SVC-01: Security Improvement Evaluation"
  description = "Implement improvements based on persistent evaluation of information resources for opportunities to improve security."
  severity    = "medium"
  query       = query.ksi_svc_01_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-SVC-01"
    nist_800_53 = "cm-12.1,cm-7.1,ma-2,pl-8,sc-39,sc-7,si-2.2,si-4,sr-10"
  }
}

benchmark "ksi_svc_06_azure" {
  title       = "KSI-SVC-06: Key and Certificate Management"
  description = "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."

  children = [
    control.ksi_svc_06_1_azure,
    control.ksi_svc_06_2_azure,
    control.ksi_svc_06_3_azure,
    control.ksi_svc_06_4_azure,
    control.ksi_svc_06_5_azure,
    control.ksi_svc_06_6_azure,
  ]

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-SVC-06"
    nist_800_53 = "ac-17.2,ia-5.2,ia-5.6,sc-12,sc-17"
  }
}
control "ksi_svc_06_1_azure" {
  title       = "KSI-SVC-06.1: Check Key Vault key rotation policy configured (best practice)"
  description = "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."
  severity    = "high"
  query       = query.ksi_svc_06_1_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-SVC-06"
    nist_800_53 = "ac-17.2,ia-5.2,ia-5.6,sc-12,sc-17"
  }
}

control "ksi_svc_06_2_azure" {
  title       = "KSI-SVC-06.2: Check Key Vault keys have expiration dates (CIS Azure 8.1)"
  description = "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."
  severity    = "high"
  query       = query.ksi_svc_06_2_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-SVC-06"
    nist_800_53 = "ac-17.2,ia-5.2,ia-5.6,sc-12,sc-17"
  }
}

control "ksi_svc_06_3_azure" {
  title       = "KSI-SVC-06.3: Check Key Vault secrets have expiration dates (CIS Azure 8.2)"
  description = "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."
  severity    = "high"
  query       = query.ksi_svc_06_3_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-SVC-06"
    nist_800_53 = "ac-17.2,ia-5.2,ia-5.6,sc-12,sc-17"
  }
}

control "ksi_svc_06_4_azure" {
  title       = "KSI-SVC-06.4: Check Key Vault certificates expiration (best practice)"
  description = "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."
  severity    = "high"
  query       = query.ksi_svc_06_4_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-SVC-06"
    nist_800_53 = "ac-17.2,ia-5.2,ia-5.6,sc-12,sc-17"
  }
}

control "ksi_svc_06_5_azure" {
  title       = "KSI-SVC-06.5: Check Application Gateway SSL certificates (best practice)"
  description = "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."
  severity    = "high"
  query       = query.ksi_svc_06_5_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-SVC-06"
    nist_800_53 = "ac-17.2,ia-5.2,ia-5.6,sc-12,sc-17"
  }
}

control "ksi_svc_06_6_azure" {
  title       = "KSI-SVC-06.6: Check Storage Account access keys rotation (best practice)"
  description = "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."
  severity    = "high"
  query       = query.ksi_svc_06_6_azure_check

  tags = {
    type        = "Azure"
    ksi_id      = "KSI-SVC-06"
    nist_800_53 = "ac-17.2,ia-5.2,ia-5.6,sc-12,sc-17"
  }
}
