provider "nsxt" {
  host                 = var.host
  vmc_token            = var.vmc_token
  allow_unverified_ssl = true
  enforcement_point    = "vmc-enforcementpoint"
}

variable "host" {}
variable "vmc_token" {}

/*=====================================
Create Security Group based on NSX Tags
======================================*/
resource "nsxt_policy_group" "Blue_VMs" {
  display_name = "Blue_VMs"
  description  = "Terraform provisioned Group"
  domain       = "cgw"
  criteria {
    condition {
      key         = "Tag"
      member_type = "VirtualMachine"
      operator    = "EQUALS"
      value       = "Blue|NSX_tag"
    }
  }
}

resource "nsxt_policy_group" "Red_VMs" {
  display_name = "Red_VMs"
  description  = "Terraform provisioned Group"
  domain       = "cgw"
  criteria {
    condition {
      key         = "Tag"
      member_type = "VirtualMachine"
      operator    = "EQUALS"
      value       = "Red|NSX_tag"
    }
  }
}


/*=====================================
Create Context Profile
======================================*/

resource "nsxt_policy_context_profile" "contextProfile" {
  display_name = "Context Profile"
  description  = "Terraform provisioned ContextProfile"
  domain_name {
    description = "test-domain-name-attribute"
    value       = ["nicovibert.com"]
  }
  app_id {
    description = "test-app-id-attribute"
    value       = ["HTTPS"]
  }
}


/*=====================================
Create DFW rules
======================================*/

resource "nsxt_policy_security_policy" "Colors" {
  display_name = "Colors"
  description  = "Terraform provisioned Security Policy"
  category     = "Application"
  domain       = "cgw"
  locked       = false
  stateful     = true
  tcp_strict   = false

  rule {
    display_name = "Context-Aware Profile"
    source_groups = [
    nsxt_policy_group.Red_VMs.path]
    destination_groups = [
    nsxt_policy_group.Blue_VMs.path]
    action   = "DROP"
    services = ["/infra/services/ICMP-ALL"]
    profiles = [nsxt_policy_context_profile.test.path]
    logged   = true
  }
}

/*=====================================
Create Profiles or Refer to existing Profile
======================================*/
  
resource "nsxt_policy_intrusion_service_profile" "networkScanProfile" {
  display_name = "Network-Scan-Policy"
  description  = "Terraform-provisioned Profile for network-scanning"
  severities   = ["HIGH", "CRITICAL", "MEDIUM", "LOW"]

  criteria {
    attack_types      = ["network-scan"]
  }

  overridden_signature {
    action       = "REJECT"
    enabled      = true
    signature_id = "2019876"
        }
}
data "nsxt_policy_intrusion_service_profile" "defaultProfile" {
  display_name = "DefaultIDSProfile"
}

/*=====================================
Create IPS Policies and Rules
======================================*/
  

resource "nsxt_policy_intrusion_service_policy" "policyBasedDefaultProfile" {
  display_name = "Policy based on the default IDS/IPS Profile"
  description  = "Terraform provisioned Policy"
  locked       = false
  stateful     = true
  domain       = "cgw"
  rule {
    display_name       = "rule1"
    destination_groups = [nsxt_policy_group.Red_VMs.path]
    action             = "DETECT"
    logged             = true
    ids_profiles       = [data.nsxt_policy_intrusion_service_profile.defaultProfile.path]
  }
}

resource "nsxt_policy_intrusion_service_policy" "policyBasedOnNetworkScanProfile" {
  display_name = "Policy based on the newly created Network Scan profile"
  description  = "Terraform provisioned Policy"
  locked       = false
  stateful     = true
  domain       = "cgw"
  rule {
    display_name       = "rule for Network Scan"
    destination_groups = [nsxt_policy_group.Red_VMs.path]
    action             = "DETECT"
    logged             = true
    ids_profiles       = [data.nsxt_policy_intrusion_service_profile.defaultProfile.path]
  }
}


