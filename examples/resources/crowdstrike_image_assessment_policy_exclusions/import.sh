#!/usr/bin/env bash
# The singleton resource is always imported with the fixed ID "singleton".
# There is exactly one image assessment policy exclusion list per tenant.

terraform import crowdstrike_image_assessment_policy_exclusions.this singleton
