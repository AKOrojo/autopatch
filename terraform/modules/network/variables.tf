variable "proxmox_api_url" {
  description = "Proxmox API URL"
  type        = string
}

variable "proxmox_api_token" {
  description = "Proxmox API token"
  type        = string
  sensitive   = true
}

variable "proxmox_tls_insecure" {
  description = "Skip TLS verification"
  type        = bool
  default     = true
}

variable "target_node" {
  description = "Proxmox node"
  type        = string
}

variable "bridge_name" {
  description = "Name for the isolated Linux bridge (e.g. vmbr100)"
  type        = string
  default     = "vmbr100"
}

variable "vlan_tag" {
  description = "VLAN tag for clone isolation"
  type        = number
  default     = 100
}

variable "subnet" {
  description = "Subnet CIDR for isolated network (e.g. 10.200.100.0/24)"
  type        = string
  default     = "10.200.100.0/24"
}

variable "gateway_ip" {
  description = "Gateway IP on the isolated bridge"
  type        = string
  default     = "10.200.100.1"
}

variable "enable_nat" {
  description = "Enable NAT for outbound internet from isolated network"
  type        = bool
  default     = false
}

variable "allowed_ports" {
  description = "Ports to allow outbound through firewall (empty = block all outbound)"
  type        = list(number)
  default     = [80, 443, 53]
}

variable "firewall_enabled" {
  description = "Enable Proxmox firewall on the bridge"
  type        = bool
  default     = true
}
