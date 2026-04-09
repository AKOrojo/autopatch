variable "proxmox_api_url" {
  description = "Proxmox API URL (e.g. https://10.100.201.24:8006)"
  type        = string
}

variable "proxmox_api_token" {
  description = "Proxmox API token in user!token=uuid format"
  type        = string
  sensitive   = true
}

variable "proxmox_tls_insecure" {
  description = "Skip TLS verification for self-signed certs"
  type        = bool
  default     = true
}

variable "target_node" {
  description = "Proxmox node to create VMs on"
  type        = string
}

variable "template_id" {
  description = "VMID of the template to clone from"
  type        = number
}

variable "clone_name" {
  description = "Name for the cloned VM"
  type        = string
}

variable "clone_id" {
  description = "VMID for the new clone (0 = auto-assign)"
  type        = number
  default     = 0
}

variable "full_clone" {
  description = "Full clone (true) vs linked clone (false)"
  type        = bool
  default     = true
}

variable "cores" {
  description = "Number of CPU cores"
  type        = number
  default     = 2
}

variable "memory" {
  description = "Memory in MB"
  type        = number
  default     = 2048
}

variable "disk_size" {
  description = "Boot disk size (e.g. '32G')"
  type        = string
  default     = "32G"
}

variable "storage_pool" {
  description = "Proxmox storage pool for the clone"
  type        = string
  default     = "local-lvm"
}

variable "network_bridge" {
  description = "Network bridge to attach the VM to"
  type        = string
  default     = "vmbr0"
}

variable "vlan_tag" {
  description = "VLAN tag for network isolation (-1 = no tag)"
  type        = number
  default     = -1
}

variable "ip_address" {
  description = "Static IP (CIDR) via cloud-init, empty = DHCP"
  type        = string
  default     = ""
}

variable "gateway" {
  description = "Default gateway via cloud-init"
  type        = string
  default     = ""
}

variable "dns_servers" {
  description = "DNS servers via cloud-init (space-separated)"
  type        = string
  default     = ""
}

variable "ssh_keys" {
  description = "SSH public keys for cloud-init"
  type        = string
  default     = ""
}

variable "ci_user" {
  description = "Cloud-init default user"
  type        = string
  default     = "autopatch"
}

variable "cloud_init" {
  description = "Enable cloud-init initialization block (disable for VMs without cloud-init like Metasploitable 2)"
  type        = bool
  default     = true
}

variable "start_on_create" {
  description = "Start VM immediately after cloning"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to the VM"
  type        = list(string)
  default     = ["autopatch", "clone"]
}

variable "description" {
  description = "VM description"
  type        = string
  default     = "Managed by Autopatch Terraform"
}
