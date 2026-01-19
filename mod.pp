mod "fedramp_20x" {
  title       = "FedRAMP 20x Compliance"
  description = "FedRAMP 20x Key Security Indicators (KSI) compliance benchmarks and controls for AWS."

  require {
    plugin "aws" {
      min_version = "0.100.0"
    }
  }
}
