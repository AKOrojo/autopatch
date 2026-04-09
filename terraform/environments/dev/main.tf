terraform {
  required_version = ">= 1.5"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = ">= 0.66"
    }
  }

  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "proxmox" {
  endpoint  = var.proxmox_api_url
  api_token = var.proxmox_api_token
  insecure  = var.proxmox_tls_insecure
}

# --- Isolated network for patch-testing clones ---
module "clone_network" {
  source = "../../modules/network"

  proxmox_api_url      = var.proxmox_api_url
  proxmox_api_token    = var.proxmox_api_token
  proxmox_tls_insecure = var.proxmox_tls_insecure
  target_node          = var.proxmox_node

  bridge_name = "vmbr100"
  vlan_tag    = 100
  subnet      = "10.200.100.0/24"
  gateway_ip  = "10.200.100.1"
  enable_nat  = true
}

# --- VM clones for patch testing ---
module "test_clone" {
  source   = "../../modules/clone-vm"
  for_each = var.clones

  proxmox_api_url      = var.proxmox_api_url
  proxmox_api_token    = var.proxmox_api_token
  proxmox_tls_insecure = var.proxmox_tls_insecure
  target_node          = var.proxmox_node

  template_id    = each.value.template_id
  clone_name     = each.key
  full_clone     = lookup(each.value, "full_clone", true)
  cores          = lookup(each.value, "cores", 2)
  memory         = lookup(each.value, "memory", 2048)
  disk_size      = lookup(each.value, "disk_size", "32G")
  storage_pool   = lookup(each.value, "storage_pool", "local-lvm")
  network_bridge = lookup(each.value, "network_bridge", module.clone_network.bridge_name)
  vlan_tag       = lookup(each.value, "network_bridge", null) != null ? -1 : module.clone_network.vlan_tag
  ip_address     = lookup(each.value, "ip_address", "")
  gateway        = module.clone_network.gateway_ip
  cloud_init     = lookup(each.value, "cloud_init", true)
  ssh_keys       = var.ssh_public_key
  tags           = ["autopatch", "clone", "dev"]
}

# --- Pre-patch snapshots ---
module "pre_patch_snapshot" {
  source   = "../../modules/snapshot"
  for_each = var.clones

  proxmox_api_url      = var.proxmox_api_url
  proxmox_api_token    = var.proxmox_api_token
  proxmox_tls_insecure = var.proxmox_tls_insecure
  target_node          = var.proxmox_node

  vm_id         = module.test_clone[each.key].vm_id
  snapshot_name = "pre-patch-${formatdate("YYYYMMDD-hhmm", timestamp())}"
  description   = "Pre-patch snapshot for ${each.key}"
}
