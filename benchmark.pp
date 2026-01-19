benchmark "fedramp_20x_aws" {
  title       = "FedRAMP 20x KSI - AWS"
  description = "FedRAMP 20x KSI compliance for AWS"

  children = [
    control.ksi_iam_01_aws,
    control.ksi_iam_02_aws,
    control.ksi_iam_03_aws,
    control.ksi_iam_05_aws,
    control.ksi_cna_01_aws,
    control.ksi_cna_02_aws,
    control.ksi_cna_03_aws,
    control.ksi_cna_04_aws,
    control.ksi_mla_01_aws,
    control.ksi_inr_01_aws,
    control.ksi_piy_01_aws,
    control.ksi_rpl_01_aws,
    control.ksi_svc_01_aws,
    control.ksi_svc_06_aws,
  ]
}
