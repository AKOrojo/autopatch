output "bridge_name" {
  description = "Name of the isolated bridge"
  value       = var.bridge_name
}

output "vlan_tag" {
  description = "VLAN tag for clone isolation"
  value       = var.vlan_tag
}

output "subnet" {
  description = "Subnet CIDR for the isolated network"
  value       = var.subnet
}

output "gateway_ip" {
  description = "Gateway IP on the isolated bridge"
  value       = var.gateway_ip
}
