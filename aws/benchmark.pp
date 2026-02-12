benchmark "fedramp_20x_aws" {
  title       = "FedRAMP 20x - AWS"
  description = "FedRAMP 20x KSI compliance for AWS"

  children = [
    benchmark.ksi_iam_01_aws,
    benchmark.ksi_iam_02_aws,
    benchmark.ksi_iam_03_aws,
    benchmark.ksi_iam_05_aws,
    benchmark.ksi_cna_01_aws,
    benchmark.ksi_cna_02_aws,
    benchmark.ksi_cna_03_aws,
    control.ksi_cna_04_aws,
    benchmark.ksi_mla_01_aws,
    benchmark.ksi_mla_02_aws,
    benchmark.ksi_mla_05_aws,
    benchmark.ksi_mla_07_aws,
    benchmark.ksi_mla_08_aws,
    benchmark.ksi_inr_01_aws,
    benchmark.ksi_piy_01_aws,
    benchmark.ksi_rpl_01_aws,
    benchmark.ksi_svc_01_aws,
    control.ksi_svc_06_aws,
  ]
}
