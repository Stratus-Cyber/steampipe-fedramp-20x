# KSI-SVC: Service Configuration Controls - AWS

control "ksi_svc_01_aws" {
  title       = "KSI-SVC-01: Security Improvement Evaluation"
  description = "Implement improvements based on persistent evaluation of information resources for opportunities to improve security."
  severity    = "medium"

  query = query.ksi_svc_01_aws_check

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

  query = query.ksi_svc_06_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-SVC-06"
    nist_800_53 = "ac-17.2,ia-5.2,ia-5.6,sc-12,sc-17"
  }
}
