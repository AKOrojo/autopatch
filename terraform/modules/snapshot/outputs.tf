output "snapshot_name" {
  description = "Name of the created snapshot"
  value       = var.snapshot_name
}

output "vm_id" {
  description = "VMID that was snapshotted"
  value       = var.vm_id
}

output "existing_snapshots" {
  description = "Comma-separated list of existing snapshots"
  value       = data.external.snapshots.result.snapshots
}

output "snapshot_count" {
  description = "Number of existing snapshots on this VM"
  value       = data.external.snapshots.result.snapshot_count
}
