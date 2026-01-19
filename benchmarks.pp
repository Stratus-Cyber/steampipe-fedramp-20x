# FedRAMP 20x Key Security Indicators (KSI) Benchmark
# Comprehensive compliance checks across all cloud platforms

# ============================================================================
# COMMON TAGS
# ============================================================================

locals {
  fedramp_common_tags = {
    framework = "FedRAMP 20x"
  }

  aws_tags = {
    type     = "AWS"
    framework = "FedRAMP 20x"
  }

  azure_tags = {
    type     = "Azure"
    framework = "FedRAMP 20x"
  }
}

# ============================================================================
# AGGREGATE BENCHMARK - ALL PLATFORMS
# ============================================================================

benchmark "fedramp_20x_all" {
  title       = "FedRAMP 20x KSI - All Platforms"
  description = "Comprehensive FedRAMP 20x KSI compliance status across all enabled platforms"

  children = [
    benchmark.ksi_cna_all,
    benchmark.ksi_iam_all,
    benchmark.ksi_inr_all,
    benchmark.ksi_mla_all,
    benchmark.ksi_piy_all,
    benchmark.ksi_rpl_all,
    benchmark.ksi_svc_all,
  ]

  tags = {
    type      = "FedRAMP 20x"
    framework = "FedRAMP 20x"
  }
}

# ============================================================================
# PLATFORM-SPECIFIC ROLLUP BENCHMARKS
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

benchmark "fedramp_20x_azure" {
  title       = "FedRAMP 20x KSI - Azure"
  description = "FedRAMP 20x KSI compliance for Azure platform"

  children = [
    benchmark.ksi_cna_azure,
    benchmark.ksi_iam_azure,
    benchmark.ksi_inr_azure,
    benchmark.ksi_mla_azure,
    benchmark.ksi_piy_azure,
    benchmark.ksi_rpl_azure,
    benchmark.ksi_svc_azure,
  ]

  tags = local.azure_tags
}

# ============================================================================
# KSI FAMILY BENCHMARKS - ALL PLATFORMS
# ============================================================================

benchmark "ksi_cna_all" {
  title       = "KSI-CNA: Cloud Native Architecture - All Platforms"
  description = "Cloud native architecture requirements across all platforms"

  children = [
    benchmark.ksi_cna_aws,
    benchmark.ksi_cna_azure,
  ]

  tags = {
    type       = "FedRAMP 20x"
    ksi_family = "CNA"
  }
}

benchmark "ksi_iam_all" {
  title       = "KSI-IAM: Identity and Access Management - All Platforms"
  description = "Identity and access management requirements across all platforms"

  children = [
    benchmark.ksi_iam_aws,
    benchmark.ksi_iam_azure,
  ]

  tags = {
    type       = "FedRAMP 20x"
    ksi_family = "IAM"
  }
}

benchmark "ksi_inr_all" {
  title       = "KSI-INR: Incident Response - All Platforms"
  description = "Incident response requirements across all platforms"

  children = [
    benchmark.ksi_inr_aws,
    benchmark.ksi_inr_azure,
  ]

  tags = {
    type       = "FedRAMP 20x"
    ksi_family = "INR"
  }
}

benchmark "ksi_mla_all" {
  title       = "KSI-MLA: Monitoring, Logging, Auditing - All Platforms"
  description = "Monitoring, logging, and auditing requirements across all platforms"

  children = [
    benchmark.ksi_mla_aws,
    benchmark.ksi_mla_azure,
  ]

  tags = {
    type       = "FedRAMP 20x"
    ksi_family = "MLA"
  }
}

benchmark "ksi_piy_all" {
  title       = "KSI-PIY: Policy and Inventory - All Platforms"
  description = "Policy and inventory requirements across all platforms"

  children = [
    benchmark.ksi_piy_aws,
    benchmark.ksi_piy_azure,
  ]

  tags = {
    type       = "FedRAMP 20x"
    ksi_family = "PIY"
  }
}

benchmark "ksi_rpl_all" {
  title       = "KSI-RPL: Recovery Planning - All Platforms"
  description = "Recovery planning requirements across all platforms"

  children = [
    benchmark.ksi_rpl_aws,
    benchmark.ksi_rpl_azure,
  ]

  tags = {
    type       = "FedRAMP 20x"
    ksi_family = "RPL"
  }
}

benchmark "ksi_svc_all" {
  title       = "KSI-SVC: Service Configuration - All Platforms"
  description = "Service configuration requirements across all platforms"

  children = [
    benchmark.ksi_svc_aws,
    benchmark.ksi_svc_azure,
  ]

  tags = {
    type       = "FedRAMP 20x"
    ksi_family = "SVC"
  }
}

# ============================================================================
# KSI PLATFORM-SPECIFIC BENCHMARKS - AWS
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

# ============================================================================
# KSI PLATFORM-SPECIFIC BENCHMARKS - AZURE
# ============================================================================

benchmark "ksi_cna_azure" {
  title       = "KSI-CNA: Cloud Native Architecture - Azure"
  description = "Azure-specific cloud native architecture controls"

  children = [
    control.ksi_cna_01_azure,
    control.ksi_cna_02_azure,
    control.ksi_cna_03_azure,
    control.ksi_cna_04_azure,
  ]

  tags = merge(local.azure_tags, {
    ksi_family = "CNA"
  })
}

benchmark "ksi_iam_azure" {
  title       = "KSI-IAM: Identity and Access Management - Azure"
  description = "Azure-specific identity and access management controls"

  children = [
    control.ksi_iam_01_azure,
    control.ksi_iam_02_azure,
    control.ksi_iam_03_azure,
    control.ksi_iam_05_azure,
  ]

  tags = merge(local.azure_tags, {
    ksi_family = "IAM"
  })
}

benchmark "ksi_inr_azure" {
  title       = "KSI-INR: Incident Response - Azure"
  description = "Azure-specific incident response controls"

  children = [
    control.ksi_inr_01_azure,
  ]

  tags = merge(local.azure_tags, {
    ksi_family = "INR"
  })
}

benchmark "ksi_mla_azure" {
  title       = "KSI-MLA: Monitoring, Logging, Auditing - Azure"
  description = "Azure-specific monitoring, logging, and auditing controls"

  children = [
    control.ksi_mla_01_azure,
  ]

  tags = merge(local.azure_tags, {
    ksi_family = "MLA"
  })
}

benchmark "ksi_piy_azure" {
  title       = "KSI-PIY: Policy and Inventory - Azure"
  description = "Azure-specific policy and inventory controls"

  children = [
    control.ksi_piy_01_azure,
  ]

  tags = merge(local.azure_tags, {
    ksi_family = "PIY"
  })
}

benchmark "ksi_rpl_azure" {
  title       = "KSI-RPL: Recovery Planning - Azure"
  description = "Azure-specific recovery planning controls"

  children = [
    control.ksi_rpl_01_azure,
  ]

  tags = merge(local.azure_tags, {
    ksi_family = "RPL"
  })
}

benchmark "ksi_svc_azure" {
  title       = "KSI-SVC: Service Configuration - Azure"
  description = "Azure-specific service configuration controls"

  children = [
    control.ksi_svc_01_azure,
    control.ksi_svc_06_azure,
  ]

  tags = merge(local.azure_tags, {
    ksi_family = "SVC"
  })
}
