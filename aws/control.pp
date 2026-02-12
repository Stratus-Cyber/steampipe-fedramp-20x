# KSI-IAM: Identity and Access Management Controls - AWS

benchmark "ksi_iam_01_aws" {
  title       = "KSI-IAM-01: Phishing-Resistant MFA"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."

  children = [
    control.ksi_iam_01_1_aws,
    control.ksi_iam_01_2_aws,
    control.ksi_iam_01_3_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}
control "ksi_iam_01_1_aws" {
  title       = "KSI-IAM-01.1: Check IAM users without any MFA enabled"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
  severity    = "critical"
  query       = query.ksi_iam_01_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}

control "ksi_iam_01_2_aws" {
  title       = "KSI-IAM-01.2: Virtual MFA (TOTP) is vulnerable to phishing; FIDO2/WebAuthn hardware tokens required"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
  severity    = "critical"
  query       = query.ksi_iam_01_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}

control "ksi_iam_01_3_aws" {
  title       = "KSI-IAM-01.3: Check console users without MFA from credential report"
  description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
  severity    = "critical"
  query       = query.ksi_iam_01_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-01"
    nist_800_53 = "ac-2,ia-2,ia-2.1,ia-2.2,ia-2.8,ia-5,ia-8,sc-23"
  }
}

benchmark "ksi_iam_02_aws" {
  title       = "KSI-IAM-02: Strong Password Policies"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."

  children = [
    control.ksi_iam_02_1_aws,
    control.ksi_iam_02_2_aws,
    control.ksi_iam_02_3_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}
control "ksi_iam_02_1_aws" {
  title       = "KSI-IAM-02.1: Check IAM password policy minimum length"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
  severity    = "high"
  query       = query.ksi_iam_02_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}

control "ksi_iam_02_2_aws" {
  title       = "KSI-IAM-02.2: Check IAM password reuse prevention"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
  severity    = "high"
  query       = query.ksi_iam_02_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}

control "ksi_iam_02_3_aws" {
  title       = "KSI-IAM-02.3: Check for users with passwords over 90 days old"
  description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
  severity    = "high"
  query       = query.ksi_iam_02_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-02"
    nist_800_53 = "ac-2,ac-3,ia-2.1,ia-2.2,ia-2.8,ia-5.1,ia-5.2,ia-5.6,ia-6"
  }
}

benchmark "ksi_iam_03_aws" {
  title       = "KSI-IAM-03: Non-User Account Authentication"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."

  children = [
    control.ksi_iam_03_1_aws,
    control.ksi_iam_03_2_aws,
    control.ksi_iam_03_3_aws,
    control.ksi_iam_03_4_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}
control "ksi_iam_03_1_aws" {
  title       = "KSI-IAM-03.1: Check IAM roles without condition constraints on assume role"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"
  query       = query.ksi_iam_03_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

control "ksi_iam_03_2_aws" {
  title       = "KSI-IAM-03.2: Check active access keys older than 90 days (long-lived keys = risk)"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"
  query       = query.ksi_iam_03_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

control "ksi_iam_03_3_aws" {
  title       = "KSI-IAM-03.3: Check for unused instance profiles (should be cleaned up)"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"
  query       = query.ksi_iam_03_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

control "ksi_iam_03_4_aws" {
  title       = "KSI-IAM-03.4: Check EC2 instances without managed identity (may use embedded credentials)"
  description = "Enforce appropriately secure authentication methods for non-user accounts and services."
  severity    = "high"
  query       = query.ksi_iam_03_4_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-03"
    nist_800_53 = "ac-2,ac-2.2,ac-4,ac-6.5,ia-3,ia-5.2,ra-5.5"
  }
}

benchmark "ksi_iam_05_aws" {
  title       = "KSI-IAM-05: Least Privilege Access"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."

  children = [
    control.ksi_iam_05_1_aws,
    control.ksi_iam_05_2_aws,
    control.ksi_iam_05_3_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}
control "ksi_iam_05_1_aws" {
  title       = "KSI-IAM-05.1: Check customer-managed policies with wildcard actions"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"
  query       = query.ksi_iam_05_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}

control "ksi_iam_05_2_aws" {
  title       = "KSI-IAM-05.2: Check users with AdministratorAccess policy"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"
  query       = query.ksi_iam_05_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}

control "ksi_iam_05_3_aws" {
  title       = "KSI-IAM-05.3: Check roles with AdministratorAccess (excluding AWS service roles)"
  description = "Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need."
  severity    = "high"
  query       = query.ksi_iam_05_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-IAM-05"
    nist_800_53 = "ac-12,ac-14,ac-17,ac-17.1,ac-17.2,ac-17.3,ac-2.5,ac-2.6,ac-20,ac-20.1,ac-3,ac-4,ac-6"
  }
}

# KSI-CNA: Cloud Native Architecture Controls - AWS

benchmark "ksi_cna_01_aws" {
  title       = "KSI-CNA-01: Network Traffic Limits"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."

  children = [
    control.ksi_cna_01_1_aws,
    control.ksi_cna_01_2_aws,
    control.ksi_cna_01_3_aws,
    control.ksi_cna_01_4_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}
control "ksi_cna_01_1_aws" {
  title       = "KSI-CNA-01.1: Check for overly permissive inbound security group rules (0.0.0.0/0)"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"
  query       = query.ksi_cna_01_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

control "ksi_cna_01_2_aws" {
  title       = "KSI-CNA-01.2: Check for unrestricted outbound rules (all protocols to 0.0.0.0/0)"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"
  query       = query.ksi_cna_01_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

control "ksi_cna_01_3_aws" {
  title       = "KSI-CNA-01.3: Check for default NACLs (may be overly permissive)"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"
  query       = query.ksi_cna_01_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

control "ksi_cna_01_4_aws" {
  title       = "KSI-CNA-01.4: Check sensitive ports (SSH/RDP/DB/Cache/Search) open to 0.0.0.0/0"
  description = "Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic."
  severity    = "high"
  query       = query.ksi_cna_01_4_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-01"
    nist_800_53 = "ac-17.3,ca-9,cm-7.1,sc-7.5,si-8"
  }
}

benchmark "ksi_cna_02_aws" {
  title       = "KSI-CNA-02: Minimal Attack Surface"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."

  children = [
    control.ksi_cna_02_1_aws,
    control.ksi_cna_02_2_aws,
    control.ksi_cna_02_3_aws,
    control.ksi_cna_02_4_aws,
    control.ksi_cna_02_5_aws,
    control.ksi_cna_02_6_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}
control "ksi_cna_02_1_aws" {
  title       = "KSI-CNA-02.1: Check EC2 instances with public IP addresses"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_02_2_aws" {
  title       = "KSI-CNA-02.2: Check for non-standard ports open inbound from 0.0.0.0/0"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_02_3_aws" {
  title       = "KSI-CNA-02.3: Check EC2 instances enforce IMDSv2 (prevents SSRF credential theft)"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_02_4_aws" {
  title       = "KSI-CNA-02.4: Check S3 buckets with public policies"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_4_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_02_5_aws" {
  title       = "KSI-CNA-02.5: Check RDS instances publicly accessible"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_5_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

control "ksi_cna_02_6_aws" {
  title       = "KSI-CNA-02.6: Check for internet-facing ALBs (need WAF verification)"
  description = "Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised."
  severity    = "high"
  query       = query.ksi_cna_02_6_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-02"
    nist_800_53 = "ac-17.3,ac-18.1,ac-18.3,ac-20.1,ca-9,sc-10,sc-7.3,sc-7.4,sc-7.5,sc-7.8,sc-8,si-10,si-11,si-16"
  }
}

benchmark "ksi_cna_03_aws" {
  title       = "KSI-CNA-03: Traffic Flow Controls"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."

  children = [
    control.ksi_cna_03_1_aws,
    control.ksi_cna_03_2_aws,
    control.ksi_cna_03_3_aws,
    control.ksi_cna_03_4_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}
control "ksi_cna_03_1_aws" {
  title       = "KSI-CNA-03.1: Check VPCs have flow logs enabled"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

control "ksi_cna_03_2_aws" {
  title       = "KSI-CNA-03.2: Check subnets don't auto-assign public IPs (bypass traffic controls)"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

control "ksi_cna_03_3_aws" {
  title       = "KSI-CNA-03.3: Check route tables with internet gateway routes (identify internet-facing paths)"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-CNA-03"
    nist_800_53 = "ac-12,ac-17.3,ca-9,sc-10,sc-4,sc-7,sc-7.7,sc-8"
  }
}

control "ksi_cna_03_4_aws" {
  title       = "KSI-CNA-03.4: Check VPCs have sufficient VPC endpoints (S3/KMS/SSM minimum for private traffic)"
  description = "Use logical networking and related capabilities to enforce traffic flow controls."
  severity    = "high"
  query       = query.ksi_cna_03_4_aws_check

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

benchmark "ksi_mla_01_aws" {
  title       = "KSI-MLA-01: Centralized Logging (SIEM)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."

  children = [
    control.ksi_mla_01_1_aws,
    control.ksi_mla_01_2_aws,
    control.ksi_mla_01_3_aws,
    control.ksi_mla_01_4_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}
control "ksi_mla_01_1_aws" {
  title       = "KSI-MLA-01.1: Check CloudTrail trails have log integrity validation (tamper-resistant)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

control "ksi_mla_01_2_aws" {
  title       = "KSI-MLA-01.2: Check CloudWatch log groups are encrypted (protect sensitive audit data)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

control "ksi_mla_01_3_aws" {
  title       = "KSI-MLA-01.3: Check Security Lake status (centralizes security telemetry)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

control "ksi_mla_01_4_aws" {
  title       = "KSI-MLA-01.4: Check log buckets have access logging enabled (detect unauthorized access)"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."
  severity    = "critical"
  query       = query.ksi_mla_01_4_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-01"
    nist_800_53 = "ac-17.1,ac-20.1,au-11,au-2,au-3,au-3.1,au-4,au-5,au-6.1,au-6.3,au-7,au-7.1,au-8,au-9,ir-4.1,si-4.2,si-4.4,si-7.7"
  }
}

benchmark "ksi_mla_02_aws" {
  title       = "KSI-MLA-02: Audit Logging"
  description = "Retain and review logs regularly to support incident detection and response."

  children = [
    control.ksi_mla_02_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-02"
    nist_800_53 = "au-2,au-3,au-3.1,au-6,au-6.1,au-6.3,au-7,au-7.1,au-11,au-12"
  }
}
control "ksi_mla_02_aws" {
  title       = "KSI-MLA-02: Check CloudTrail trails have comprehensive audit coverage"
  description = "Retain and review logs regularly to support incident detection and response."
  severity    = "high"
  query       = query.ksi_mla_02_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-02"
    nist_800_53 = "au-2,au-3,au-3.1,au-6,au-6.1,au-6.3,au-7,au-7.1,au-11,au-12"
  }
}

benchmark "ksi_mla_05_aws" {
  title       = "KSI-MLA-05: Configuration Evaluation"
  description = "Continuously evaluate infrastructure configuration against security baselines."

  children = [
    control.ksi_mla_05_1_aws,
    control.ksi_mla_05_2_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-05"
    nist_800_53 = "ca-7,cm-3,cm-6,cm-6.1,cm-8.3,si-4,si-7"
  }
}
control "ksi_mla_05_1_aws" {
  title       = "KSI-MLA-05.1: Check AWS Config recorders are actively recording configurations"
  description = "Continuously evaluate infrastructure configuration against security baselines."
  severity    = "high"
  query       = query.ksi_mla_05_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-05"
    nist_800_53 = "ca-7,cm-3,cm-6,cm-6.1,cm-8.3,si-4,si-7"
  }
}

control "ksi_mla_05_2_aws" {
  title       = "KSI-MLA-05.2: Check Config rules compliance status (configuration drift detection)"
  description = "Continuously evaluate infrastructure configuration against security baselines."
  severity    = "high"
  query       = query.ksi_mla_05_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-05"
    nist_800_53 = "ca-7,cm-3,cm-6,cm-6.1,cm-8.3,si-4,si-7"
  }
}

benchmark "ksi_mla_07_aws" {
  title       = "KSI-MLA-07: Event Type Coverage"
  description = "Log required event types comprehensively to ensure complete audit trail."

  children = [
    control.ksi_mla_07_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-07"
    nist_800_53 = "au-2,au-3,au-3.1,au-12,si-4"
  }
}
control "ksi_mla_07_aws" {
  title       = "KSI-MLA-07: Check CloudTrail trails have complete event type coverage"
  description = "Log required event types comprehensively to ensure complete audit trail."
  severity    = "high"
  query       = query.ksi_mla_07_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-07"
    nist_800_53 = "au-2,au-3,au-3.1,au-12,si-4"
  }
}

benchmark "ksi_mla_08_aws" {
  title       = "KSI-MLA-08: Log Data Access Control"
  description = "Restrict access to log data using least privilege to prevent tampering or unauthorized disclosure."

  children = [
    control.ksi_mla_08_1_aws,
    control.ksi_mla_08_2_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-08"
    nist_800_53 = "ac-3,ac-6,au-9,au-9.2,au-9.3,au-9.4"
  }
}
control "ksi_mla_08_1_aws" {
  title       = "KSI-MLA-08.1: Check log buckets don't have overly permissive ACLs"
  description = "Restrict access to log data using least privilege to prevent tampering or unauthorized disclosure."
  severity    = "high"
  query       = query.ksi_mla_08_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-08"
    nist_800_53 = "ac-3,ac-6,au-9,au-9.2,au-9.3,au-9.4"
  }
}

control "ksi_mla_08_2_aws" {
  title       = "KSI-MLA-08.2: Check log groups have KMS encryption (protect log data at rest)"
  description = "Restrict access to log data using least privilege to prevent tampering or unauthorized disclosure."
  severity    = "high"
  query       = query.ksi_mla_08_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-MLA-08"
    nist_800_53 = "ac-3,ac-6,au-9,au-9.2,au-9.3,au-9.4"
  }
}

# KSI-INR: Incident Response Controls - AWS

benchmark "ksi_inr_01_aws" {
  title       = "KSI-INR-01: Incident Response Procedures"
  description = "Persistently review the effectiveness of documented incident response procedures."

  children = [
    control.ksi_inr_01_1_aws,
    control.ksi_inr_01_2_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-INR-01"
    nist_800_53 = "ir-4,ir-4.1,ir-6,ir-6.1,ir-6.3,ir-7,ir-7.1,ir-8,ir-8.1,si-4.5"
  }
}
control "ksi_inr_01_1_aws" {
  title       = "KSI-INR-01.1: Check GuardDuty enabled for incident detection"
  description = "Persistently review the effectiveness of documented incident response procedures."
  severity    = "high"
  query       = query.ksi_inr_01_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-INR-01"
    nist_800_53 = "ir-4,ir-4.1,ir-6,ir-6.1,ir-6.3,ir-7,ir-7.1,ir-8,ir-8.1,si-4.5"
  }
}

control "ksi_inr_01_2_aws" {
  title       = "KSI-INR-01.2: Check CloudWatch log groups have sufficient retention for incident investigation"
  description = "Persistently review the effectiveness of documented incident response procedures."
  severity    = "high"
  query       = query.ksi_inr_01_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-INR-01"
    nist_800_53 = "ir-4,ir-4.1,ir-6,ir-6.1,ir-6.3,ir-7,ir-7.1,ir-8,ir-8.1,si-4.5"
  }
}

# KSI-PIY: Policy and Inventory Controls - AWS

benchmark "ksi_piy_01_aws" {
  title       = "KSI-PIY-01: Real-Time Inventory Generation"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."

  children = [
    control.ksi_piy_01_1_aws,
    control.ksi_piy_01_2_aws,
    control.ksi_piy_01_3_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}
control "ksi_piy_01_1_aws" {
  title       = "KSI-PIY-01.1: Check AWS Config provides automated inventory"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."
  severity    = "medium"
  query       = query.ksi_piy_01_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}

control "ksi_piy_01_2_aws" {
  title       = "KSI-PIY-01.2: Check EC2 instances have required inventory tags (Name and Environment minimum)"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."
  severity    = "medium"
  query       = query.ksi_piy_01_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}

control "ksi_piy_01_3_aws" {
  title       = "KSI-PIY-01.3: Check S3 buckets have required inventory tags"
  description = "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."
  severity    = "medium"
  query       = query.ksi_piy_01_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-PIY-01"
    nist_800_53 = "cm-12,cm-12.1,cm-2.2,cm-7.5,cm-8,cm-8.1,cp-2.8"
  }
}

# KSI-RPL: Recovery Planning Controls - AWS

benchmark "ksi_rpl_01_aws" {
  title       = "KSI-RPL-01: Recovery Time and Point Objectives"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."

  children = [
    control.ksi_rpl_01_1_aws,
    control.ksi_rpl_01_2_aws,
    control.ksi_rpl_01_3_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}
control "ksi_rpl_01_1_aws" {
  title       = "KSI-RPL-01.1: Check backup vaults have recovery points"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
  severity    = "high"
  query       = query.ksi_rpl_01_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}

control "ksi_rpl_01_2_aws" {
  title       = "KSI-RPL-01.2: Check RDS instances have adequate backup retention (minimum 7 days for RPO)"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
  severity    = "high"
  query       = query.ksi_rpl_01_2_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}

control "ksi_rpl_01_3_aws" {
  title       = "KSI-RPL-01.3: Check DynamoDB tables have Point-in-Time Recovery (PITR) enabled"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
  severity    = "high"
  query       = query.ksi_rpl_01_3_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}

# KSI-SVC: Service Configuration Controls - AWS

benchmark "ksi_svc_01_aws" {
  title       = "KSI-SVC-01: Security Improvement Evaluation"
  description = "Implement improvements based on persistent evaluation of information resources for opportunities to improve security."

  children = [
    control.ksi_svc_01_1_aws,
    control.ksi_svc_01_2_aws,
  ]

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-SVC-01"
    nist_800_53 = "cm-12.1,cm-7.1,ma-2,pl-8,sc-39,sc-7,si-2.2,si-4,sr-10"
  }
}
control "ksi_svc_01_1_aws" {
  title       = "KSI-SVC-01.1: Check Lambda functions for deprecated runtimes (indicates lack of continuous improvement)"
  description = "Implement improvements based on persistent evaluation of information resources for opportunities to improve security."
  severity    = "medium"
  query       = query.ksi_svc_01_1_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-SVC-01"
    nist_800_53 = "cm-12.1,cm-7.1,ma-2,pl-8,sc-39,sc-7,si-2.2,si-4,sr-10"
  }
}

control "ksi_svc_01_2_aws" {
  title       = "KSI-SVC-01.2: Check RDS instances have auto minor version upgrade enabled"
  description = "Implement improvements based on persistent evaluation of information resources for opportunities to improve security."
  severity    = "medium"
  query       = query.ksi_svc_01_2_aws_check

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
