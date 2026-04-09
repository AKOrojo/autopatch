terraform {
  required_version = ">= 1.5"
}

# Proxmox snapshots are not natively supported by the Telmate provider,
# so we manage them via the Proxmox REST API directly.

resource "null_resource" "snapshot_create" {
  triggers = {
    vm_id         = var.vm_id
    snapshot_name = var.snapshot_name
    node          = var.target_node
    api_url       = var.proxmox_api_url
    api_token     = var.proxmox_api_token
  }

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      curl -sk -X POST \
        -H "Authorization: PVEAPIToken=${var.proxmox_api_token}" \
        "${var.proxmox_api_url}/api2/json/nodes/${var.target_node}/qemu/${var.vm_id}/snapshot" \
        -d "snapname=${var.snapshot_name}" \
        -d "description=${var.description}" \
        -d "vmstate=${var.include_ram ? "1" : "0"}"
    EOT
  }

  # Rollback on destroy — revert to this snapshot before deleting it
  provisioner "local-exec" {
    when        = destroy
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      curl -sk -X POST \
        -H "Authorization: PVEAPIToken=${self.triggers.api_token}" \
        "${self.triggers.api_url}/api2/json/nodes/${self.triggers.node}/qemu/${self.triggers.vm_id}/snapshot/${self.triggers.snapshot_name}/rollback" \
      && sleep 5 \
      && curl -sk -X DELETE \
        -H "Authorization: PVEAPIToken=${self.triggers.api_token}" \
        "${self.triggers.api_url}/api2/json/nodes/${self.triggers.node}/qemu/${self.triggers.vm_id}/snapshot/${self.triggers.snapshot_name}"
    EOT
  }
}

# Data source: list existing snapshots for the VM
data "external" "snapshots" {
  program = [
    "/bin/sh", "-c",
    <<-EOT
      RESULT=$(curl -sk \
        -H "Authorization: PVEAPIToken=${var.proxmox_api_token}" \
        "${var.proxmox_api_url}/api2/json/nodes/${var.target_node}/qemu/${var.vm_id}/snapshot")
      NAMES=$(echo "$RESULT" | jq -r '[.data[] | select(.name != "current") | .name] | join(",")')
      COUNT=$(echo "$RESULT" | jq -r '[.data[] | select(.name != "current")] | length | tostring')
      echo "{\"snapshot_count\": \"$COUNT\", \"snapshots\": \"$NAMES\"}"
    EOT
  ]
}
