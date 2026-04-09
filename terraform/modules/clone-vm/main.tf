terraform {
  required_version = ">= 1.5"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = ">= 0.66"
    }
  }
}

resource "proxmox_virtual_environment_vm" "clone" {
  name      = var.clone_name
  vm_id     = var.clone_id != 0 ? var.clone_id : null
  node_name = var.target_node
  tags      = var.tags

  clone {
    vm_id = var.template_id
    full  = var.full_clone
  }

  cpu {
    cores   = var.cores
    sockets = 1
    type    = "host"
  }

  memory {
    dedicated = var.memory
  }

  disk {
    interface    = "scsi0"
    size         = tonumber(replace(var.disk_size, "G", ""))
    datastore_id = var.storage_pool
  }

  network_device {
    model   = "virtio"
    bridge  = var.network_bridge
    vlan_id = var.vlan_tag >= 0 ? var.vlan_tag : null
  }

  dynamic "initialization" {
    for_each = var.cloud_init ? [1] : []
    content {
      user_account {
        username = var.ci_user
        keys     = var.ssh_keys != "" ? [var.ssh_keys] : []
      }

      ip_config {
        ipv4 {
          address = var.ip_address != "" ? var.ip_address : "dhcp"
          gateway = var.ip_address != "" ? var.gateway : null
        }
      }

      dns {
        servers = var.dns_servers != "" ? split(" ", var.dns_servers) : []
      }
    }
  }

  started = var.start_on_create

  lifecycle {
    ignore_changes = [
      network_device,
    ]
  }

}
