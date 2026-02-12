benchmark "fedramp_20x_entraid" {
  title       = "FedRAMP 20x - Entra ID"
  description = "FedRAMP 20x KSI compliance for Microsoft Entra ID"

  children = [
    control.ksi_iam_01_entraid,
    control.ksi_iam_02_entraid,
    control.ksi_iam_04_entraid,
    control.ksi_iam_05_entraid,
    control.ksi_iam_07_entraid,
    control.ksi_mla_08_entraid,
  ]
}
