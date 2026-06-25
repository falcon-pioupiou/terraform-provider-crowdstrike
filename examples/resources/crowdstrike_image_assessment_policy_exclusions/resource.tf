# crowdstrike_image_assessment_policy_exclusions — Singleton resource
#
# This resource manages the ENTIRE global image assessment policy exclusion list
# for the tenant. Terraform is the source of truth: every apply replaces the
# full list with what is declared here. Any condition added outside Terraform
# (e.g. in the Falcon console) will be overwritten on the next apply.
#
# All conditions for the tenant must be declared in a single resource block.

resource "crowdstrike_image_assessment_policy_exclusions" "this" {
  conditions = [
    # Exclude specific CVE IDs from image assessment enforcement.
    {
      prop        = "cve_id"
      value       = ["CVE-2024-9681", "CVE-2024-9676"]
      description = "Known false positives"
    },

    # Exclude a CVE with a 30-day TTL (seconds).
    {
      prop        = "cve_id"
      value       = ["CVE-2024-9675"]
      description = "Excluded for 30 days while fix is tested"
      ttl         = 2592000
    },

    # Exclude a specific package version.
    {
      prop        = "packages"
      value       = ["nginx 1.27.3-r1"]
      description = "Approved version — tracked vulnerability"
    },

    # For some props (e.g. vulnerabilities_no_fix, vulnerabilities_published)
    # the exclusion applies to the property itself — no specific values needed.
    # Omitting value or setting value = [] are equivalent.
    {
      prop = "vulnerabilities_no_fix"
    },

    {
      prop        = "vulnerabilities_published"
      description = "Exclude recently published vulnerabilities while triaging"
      ttl         = 864000 # 10 days in seconds
    },
  ]
}
