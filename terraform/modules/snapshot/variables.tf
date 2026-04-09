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
  description = "Proxmox node the VM resides on"
  type        = string
}

variable "vm_id" {
  description = "VMID to snapshot"
  type        = number
}

variable "snapshot_name" {
  description = "Name for the snapshot"
  type        = string
  default     = "pre-patch"
}

variable "description" {
  description = "Snapshot description"
  type        = string
  default     = "Autopatch pre-patch snapshot"
}

variable "include_ram" {
  description = "Include RAM state in the snapshot"
  type        = bool
  default     = false
}
