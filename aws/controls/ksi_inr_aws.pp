# KSI-INR: Incident Response Controls - AWS

control "ksi_inr_01_aws" {
  title       = "KSI-INR-01: Incident Response Procedures"
  description = "Persistently review the effectiveness of documented incident response procedures."
  severity    = "high"

  query = query.ksi_inr_01_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-INR-01"
    nist_800_53 = "ir-4,ir-4.1,ir-6,ir-6.1,ir-6.3,ir-7,ir-7.1,ir-8,ir-8.1,si-4.5"
  }
}
