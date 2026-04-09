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

  # Discover DHCP-assigned IP for VMs without cloud-init/guest-agent.
  # Waits for boot, then scans the local ARP table by MAC address.
  provisioner "local-exec" {
    command = <<-EOT
      MAC=$(echo "${self.network_device[0].mac_address}" | tr '[:upper:]' '[:lower:]')
      echo "Waiting for VM ${self.vm_id} (MAC $MAC) to get an IP..."
      for i in $(seq 1 24); do
        sleep 5
        # Ping broadcast to populate ARP cache
        ping -c 1 -W 1 -b ${var.discovery_broadcast} >/dev/null 2>&1 || true
        # Check ARP table for the MAC
        IP=$(arp -an 2>/dev/null | grep -i "$MAC" | grep -oP '\\(\\K[0-9.]+(?=\\))' | head -1)
        if [ -n "$IP" ]; then
          echo "$IP" > /tmp/vm_${self.vm_id}_ip.txt
          echo "Discovered IP: $IP"
          exit 0
        fi
        echo "  attempt $i/24 — not found yet"
      done
      echo "" > /tmp/vm_${self.vm_id}_ip.txt
      echo "WARNING: Could not discover IP after 120s"
    EOT
  }
}

# Read the discovered IP from the file written by local-exec
data "local_file" "vm_ip" {
  filename   = "/tmp/vm_${proxmox_virtual_environment_vm.clone.vm_id}_ip.txt"
  depends_on = [proxmox_virtual_environment_vm.clone]
}
