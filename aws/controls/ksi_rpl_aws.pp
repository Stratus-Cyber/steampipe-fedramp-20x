# KSI-RPL: Recovery Planning Controls - AWS

control "ksi_rpl_01_aws" {
  title       = "KSI-RPL-01: Recovery Time and Point Objectives"
  description = "Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
  severity    = "high"

  query = query.ksi_rpl_01_aws_check

  tags = {
    type        = "AWS"
    ksi_id      = "KSI-RPL-01"
    nist_800_53 = "cp-10,cp-2.3"
  }
}
