terraform {
  required_version = ">= 1.5"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = ">= 0.66"
    }
  }
}

# Create isolated network bridge and firewall rules via Proxmox API.
# Proxmox SDN/bridge creation is not natively supported by the Telmate
# provider, so we use a null_resource with the Proxmox API.

resource "null_resource" "isolated_bridge" {
  triggers = {
    bridge_name       = var.bridge_name
    subnet            = var.subnet
    gateway_ip        = var.gateway_ip
    node              = var.target_node
    proxmox_api_url   = var.proxmox_api_url
    proxmox_api_token = var.proxmox_api_token
  }

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      curl -sk -X PUT \
        -H "Authorization: PVEAPIToken=${var.proxmox_api_token}" \
        "${var.proxmox_api_url}/api2/json/nodes/${var.target_node}/network/${var.bridge_name}" \
        -d "type=bridge" \
        -d "cidr=${var.gateway_ip}/24" \
        -d "autostart=1" \
        -d "comments=Autopatch+isolated+clone+network" \
      || curl -sk -X POST \
        -H "Authorization: PVEAPIToken=${var.proxmox_api_token}" \
        "${var.proxmox_api_url}/api2/json/nodes/${var.target_node}/network" \
        -d "iface=${var.bridge_name}" \
        -d "type=bridge" \
        -d "cidr=${var.gateway_ip}/24" \
        -d "autostart=1" \
        -d "comments=Autopatch+isolated+clone+network"
    EOT
  }

  provisioner "local-exec" {
    when        = destroy
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      curl -sk -X DELETE \
        -H "Authorization: PVEAPIToken=${self.triggers.proxmox_api_token}" \
        "${self.triggers.proxmox_api_url}/api2/json/nodes/${self.triggers.node}/network/${self.triggers.bridge_name}"
    EOT
  }
}

# Apply the network config on the node
resource "null_resource" "apply_network" {
  depends_on = [null_resource.isolated_bridge]

  triggers = {
    bridge_name = var.bridge_name
  }

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      curl -sk -X PUT \
        -H "Authorization: PVEAPIToken=${var.proxmox_api_token}" \
        "${var.proxmox_api_url}/api2/json/nodes/${var.target_node}/network"
    EOT
  }
}

# Firewall rules — block inter-VLAN traffic, allow only controlled egress
resource "null_resource" "firewall_rules" {
  count      = var.firewall_enabled ? 1 : 0
  depends_on = [null_resource.apply_network]

  triggers = {
    allowed_ports = join(",", var.allowed_ports)
    subnet        = var.subnet
    enable_nat    = var.enable_nat
  }

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      # Drop all forwarding from isolated subnet by default
      curl -sk -X POST \
        -H "Authorization: PVEAPIToken=${var.proxmox_api_token}" \
        "${var.proxmox_api_url}/api2/json/nodes/${var.target_node}/firewall/rules" \
        -d "type=group" \
        -d "action=DROP" \
        -d "source=${var.subnet}" \
        -d "enable=1" \
        -d "comment=Autopatch:+block+clone+egress+by+default"

      %{for port in var.allowed_ports}
      curl -sk -X POST \
        -H "Authorization: PVEAPIToken=${var.proxmox_api_token}" \
        "${var.proxmox_api_url}/api2/json/nodes/${var.target_node}/firewall/rules" \
        -d "type=out" \
        -d "action=ACCEPT" \
        -d "source=${var.subnet}" \
        -d "dport=${port}" \
        -d "proto=tcp" \
        -d "enable=1" \
        -d "comment=Autopatch:+allow+port+${port}+from+clones"
      %{endfor}
    EOT
  }
}

# Optional NAT masquerade for outbound
resource "null_resource" "nat_masquerade" {
  count      = var.enable_nat ? 1 : 0
  depends_on = [null_resource.apply_network]

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      curl -sk -X POST \
        -H "Authorization: PVEAPIToken=${var.proxmox_api_token}" \
        "${var.proxmox_api_url}/api2/json/nodes/${var.target_node}/firewall/rules" \
        -d "type=out" \
        -d "action=ACCEPT" \
        -d "source=${var.subnet}" \
        -d "log=nolog" \
        -d "enable=1" \
        -d "comment=Autopatch:+NAT+masquerade+for+clones"
    EOT
  }
}
