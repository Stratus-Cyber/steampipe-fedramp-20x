# FedRAMP 20x Key Security Indicators (KSI) Benchmark
# AWS compliance checks

# ============================================================================
# COMMON TAGS
# ============================================================================

locals {
  fedramp_common_tags = {
    framework = "FedRAMP 20x"
  }

  aws_tags = {
    type      = "AWS"
    framework = "FedRAMP 20x"
  }
}

# ============================================================================
# TOP-LEVEL BENCHMARK - AWS
# ============================================================================

benchmark "fedramp_20x_aws" {
  title       = "FedRAMP 20x KSI - AWS"
  description = "FedRAMP 20x KSI compliance for AWS platform"

  children = [
    benchmark.ksi_cna_aws,
    benchmark.ksi_iam_aws,
    benchmark.ksi_inr_aws,
    benchmark.ksi_mla_aws,
    benchmark.ksi_piy_aws,
    benchmark.ksi_rpl_aws,
    benchmark.ksi_svc_aws,
  ]

  tags = local.aws_tags
}

# ============================================================================
# KSI FAMILY BENCHMARKS - AWS
# ============================================================================

benchmark "ksi_cna_aws" {
  title       = "KSI-CNA: Cloud Native Architecture - AWS"
  description = "AWS-specific cloud native architecture controls"

  children = [
    control.ksi_cna_01_aws,
    control.ksi_cna_02_aws,
    control.ksi_cna_03_aws,
    control.ksi_cna_04_aws,
  ]

  tags = merge(local.aws_tags, {
    ksi_family = "CNA"
  })
}

benchmark "ksi_iam_aws" {
  title       = "KSI-IAM: Identity and Access Management - AWS"
  description = "AWS-specific identity and access management controls"

  children = [
    control.ksi_iam_01_aws,
    control.ksi_iam_02_aws,
    control.ksi_iam_03_aws,
    control.ksi_iam_05_aws,
  ]

  tags = merge(local.aws_tags, {
    ksi_family = "IAM"
  })
}

benchmark "ksi_inr_aws" {
  title       = "KSI-INR: Incident Response - AWS"
  description = "AWS-specific incident response controls"

  children = [
    control.ksi_inr_01_aws,
  ]

  tags = merge(local.aws_tags, {
    ksi_family = "INR"
  })
}

benchmark "ksi_mla_aws" {
  title       = "KSI-MLA: Monitoring, Logging, Auditing - AWS"
  description = "AWS-specific monitoring, logging, and auditing controls"

  children = [
    control.ksi_mla_01_aws,
  ]

  tags = merge(local.aws_tags, {
    ksi_family = "MLA"
  })
}

benchmark "ksi_piy_aws" {
  title       = "KSI-PIY: Policy and Inventory - AWS"
  description = "AWS-specific policy and inventory controls"

  children = [
    control.ksi_piy_01_aws,
  ]

  tags = merge(local.aws_tags, {
    ksi_family = "PIY"
  })
}

benchmark "ksi_rpl_aws" {
  title       = "KSI-RPL: Recovery Planning - AWS"
  description = "AWS-specific recovery planning controls"

  children = [
    control.ksi_rpl_01_aws,
  ]

  tags = merge(local.aws_tags, {
    ksi_family = "RPL"
  })
}

benchmark "ksi_svc_aws" {
  title       = "KSI-SVC: Service Configuration - AWS"
  description = "AWS-specific service configuration controls"

  children = [
    control.ksi_svc_01_aws,
    control.ksi_svc_06_aws,
  ]

  tags = merge(local.aws_tags, {
    ksi_family = "SVC"
  })
}
