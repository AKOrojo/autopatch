variable "proxmox_api_url" {
  description = "Proxmox API URL"
  type        = string
}

variable "proxmox_api_token" {
  description = "Proxmox API token (user!token=uuid)"
  type        = string
  sensitive   = true
}

variable "proxmox_tls_insecure" {
  description = "Skip TLS verification"
  type        = bool
  default     = true
}

variable "proxmox_node" {
  description = "Proxmox target node"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key for cloud-init"
  type        = string
  default     = ""
}

variable "clones" {
  description = "Map of VM clones to create for patch testing"
  type = map(object({
    template_id  = number
    full_clone   = optional(bool, true)
    cores        = optional(number, 2)
    memory       = optional(number, 2048)
    disk_size    = optional(string, "32G")
    storage_pool   = optional(string, "local-lvm")
    network_bridge = optional(string)
    ip_address     = optional(string, "")
  }))
  default = {}
}
