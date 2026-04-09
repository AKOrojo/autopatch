output "clone_vms" {
  description = "Map of clone names to their details"
  value = {
    for name, clone in module.test_clone : name => {
      vm_id    = clone.vm_id
      vm_name  = clone.vm_name
      vm_ip    = clone.vm_ip
      vm_mac   = clone.vm_mac
      ssh_host = clone.ssh_host
      node     = clone.target_node
    }
  }
}

output "network" {
  description = "Isolated network details"
  value = {
    bridge   = module.clone_network.bridge_name
    vlan     = module.clone_network.vlan_tag
    subnet   = module.clone_network.subnet
    gateway  = module.clone_network.gateway_ip
  }
}

output "snapshots" {
  description = "Pre-patch snapshot details"
  value = {
    for name, snap in module.pre_patch_snapshot : name => {
      snapshot_name  = snap.snapshot_name
      vm_id          = snap.vm_id
      snapshot_count = snap.snapshot_count
    }
  }
}
