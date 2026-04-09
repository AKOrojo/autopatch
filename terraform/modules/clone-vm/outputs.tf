output "vm_id" {
  description = "VMID of the cloned VM"
  value       = proxmox_virtual_environment_vm.clone.vm_id
}

output "vm_name" {
  description = "Name of the cloned VM"
  value       = proxmox_virtual_environment_vm.clone.name
}

output "vm_ip" {
  description = "Primary IP address of the cloned VM (empty if no guest agent)"
  value       = try(proxmox_virtual_environment_vm.clone.ipv4_addresses[1][0], "")
}

output "vm_mac" {
  description = "MAC address of the first network interface"
  value       = try(proxmox_virtual_environment_vm.clone.network_device[0].mac_address, "")
}

output "target_node" {
  description = "Proxmox node the VM is on"
  value       = proxmox_virtual_environment_vm.clone.node_name
}

output "ssh_host" {
  description = "SSH connection string"
  value       = "${var.ci_user}@${try(proxmox_virtual_environment_vm.clone.ipv4_addresses[1][0], "")}"
}
