
provider "nsxt" {
  host                 = var.host
  vmc_token            = var.vmc_token
  allow_unverified_ssl = true
  enforcement_point    = "vmc-enforcementpoint"
}

variable host {}
variable vmc_token {}

resource "nsxt_policy_context_profile" "test" {
  display_name = "test"
  description  = "Terraform provisioned ContextProfile"
  domain_name {
    description = "test-domain-name-attribute"
    value       = ["*-myfiles.sharepoint.com"]
  }
  app_id {
    description = "test-app-id-attribute"
    value       = ["SSL"]
    sub_attribute {
      tls_version = ["SSL_V3"]
    }
  }
}

/*=====================================
Create Security Group based on NSX Tags
======================================*/
resource "nsxt_policy_group" "Blue_VMs" {
  display_name = "Blue_VMs"
  description = "Terraform provisioned Group"
  domain       = "cgw"
  criteria {
    condition {
      key = "Tag"
      member_type = "VirtualMachine"
      operator = "EQUALS"
      value = "Blue|NSX_tag"
    }
  }
}

resource "nsxt_policy_group" "Red_VMs" {
  display_name = "Red_VMs"
  description  = "Terraform provisioned Group"
  domain       = "cgw"
  criteria {
    condition {
      key = "Tag"
      member_type = "VirtualMachine"
      operator = "EQUALS"
      value = "Red|NSX_tag"
    }
  }
}

/*=====================================
Create DFW rules
======================================*/

resource "nsxt_policy_security_policy" "Colors" {
  display_name = "Colors"
  description = "Terraform provisioned Security Policy"
  category = "Application"
  domain = "cgw"
  locked = false
  stateful = true
  tcp_strict = false

  rule {
    display_name = "Blue2Red"
    source_groups = [
      nsxt_policy_group.Blue_VMs.path]
    destination_groups = [
      nsxt_policy_group.Red_VMs.path]
    action = "DROP"
    services = ["/infra/services/ICMP-ALL"]
    logged = true
  }
  rule {
    display_name = "Red2Blue"
    source_groups = [
      nsxt_policy_group.Red_VMs.path]
    destination_groups = [
      nsxt_policy_group.Blue_VMs.path]
    action = "DROP"
    services = ["/infra/services/ICMP-ALL"]
    logged = true
  }
  rule {
    display_name = "Context-Aware Profile"
    source_groups = [
      nsxt_policy_group.Red_VMs.path]
    destination_groups = [
      nsxt_policy_group.Blue_VMs.path]
    action = "DROP"
    services = ["/infra/services/ICMP-ALL"]
    profiles = [nsxt_policy_context_profile.test.path]
    logged = true
  }
}
*/
data "nsxt_policy_ids_profile" "default" {
  display_name = "DefaultIDSProfile"
}
*/

resource "nsxt_policy_intrusion_service_policy" "policy1" {
  display_name = "policy1"
  description  = "Terraform provisioned Policy"
  locked       = false
  stateful     = true

  rule {
    display_name       = "rule1"
    destination_groups = [nsxt_policy_group.Red_VMs.path]
    action             = "DETECT"
    services           = ["/infra/services/ICMP-ALL"]
    logged             = true
    ids_profiles       = ["/infra/settings/firewall/security/intrusion-services/profiles/DefaultIDSProfile"]
  }
}
