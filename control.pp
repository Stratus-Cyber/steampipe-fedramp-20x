# KSI-IAM: Identity and Access Management Controls - AWS

control "ksi_iam_01_aws" {
  title       = "KSI-IAM-01: Phishing-Resistant MFA"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
  severity    = "critical"
  query       = query.ksi_iam_01_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}

control "ksi_iam_02_aws" {
  title       = "KSI-IAM-02: Strong Password Policies"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
  severity    = "high"
  query       = query.ksi_iam_02_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}

control "ksi_iam_03_aws" {
  title       = "KSI-IAM-03: Non-User Account Authentication"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"
  query       = query.ksi_iam_03_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

control "ksi_iam_05_aws" {
  title       = "KSI-IAM-05: Least Privilege Access"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"
  query       = query.ksi_iam_05_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}

# KSI-CNA: Cloud Native Architecture Controls - AWS

control "ksi_cna_01_aws" {
  title       = "KSI-CNA-01: Network Traffic Limits"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"
  query       = query.ksi_cna_01_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

control "ksi_cna_02_aws" {
  title       = "KSI-CNA-02: Minimal Attack Surface"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_03_aws" {
  title       = "KSI-CNA-03: Traffic Flow Controls"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

control "ksi_cna_04_aws" {
  title       = "KSI-CNA-04: Immutable Infrastructure"
  description = "Use immutable infrastructure with strictly defined functionality and privileges by default."
  severity    = "high"
  query       = query.ksi_cna_04_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-04"
    nist_800_53 = "cm-2,si-3"
  }
}

# KSI-MLA: Monitoring, Logging, Auditing Controls - AWS

control "ksi_mla_01_aws" {
  title       = "KSI-MLA-01: Centralized Logging (SIEM)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

# KSI-INR: Incident Response Controls - AWS

control "ksi_inr_01_aws" {
  title       = "KSI-INR-01: Incident Response Procedures"
  description = "Persistently review the effectiveness of documented incident response procedures."
  severity    = "high"
  query       = query.ksi_inr_01_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-INR-01"
    nist_800_53 = "ir-4,ir-4.1,ir-6,ir-6.1,ir-6.3,ir-7,ir-7.1,ir-8,ir-8.1,si-4.5"
  }
}

# KSI-PIY: Policy and Inventory Controls - AWS

control "ksi_piy_01_aws" {
  title       = "KSI-PIY-01: Real-Time Inventory Generation"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."
  severity    = "medium"
  query       = query.ksi_piy_01_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}

# KSI-RPL: Recovery Planning Controls - AWS

control "ksi_rpl_01_aws" {
  title       = "KSI-RPL-01: Recovery Time and Point Objectives"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
  severity    = "high"
  query       = query.ksi_rpl_01_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}

# KSI-SVC: Service Configuration Controls - AWS

control "ksi_svc_01_aws" {
  title       = "KSI-SVC-01: Security Improvement Evaluation"
  description = "Implement improvements based on persistent evaluation of information resources for opportunities to improve security."
  severity    = "medium"
  query       = query.ksi_svc_01_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-SVC-01"
    nist_800_53 = "cm-12.1,cm-7.1,ma-2,pl-8,sc-39,sc-7,si-2.2,si-4,sr-10"
  }
}

control "ksi_svc_06_aws" {
  title       = "KSI-SVC-06: Key and Certificate Management"
  description = "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."
  severity    = "high"
  query       = query.ksi_svc_06_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-SVC-06"
    nist_800_53 = "ac-17.2,ia-5.2,ia-5.6,sc-12,sc-17"
  }
}
