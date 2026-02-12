benchmark "fedramp_20x_consolidated" {
  title       = "FedRAMP 20x - Consolidated"
  description = "FedRAMP 20x KSI compliance for AWS and Azure"

  children = [
    benchmark.fedramp_20x_aws,
    benchmark.fedramp_20x_azure,
    benchmark.fedramp_20x_entraid,
  ]
}