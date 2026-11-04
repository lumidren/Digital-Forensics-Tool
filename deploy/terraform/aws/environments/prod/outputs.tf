output "stack" {
  description = "All stack outputs (consumed by .github/workflows/deploy.yml to render Helm values)."
  value       = module.stack
}
