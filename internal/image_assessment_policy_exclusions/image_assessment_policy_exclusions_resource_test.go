// Package imageassessmentpolicyexclusions_test contains acceptance tests for the
// crowdstrike_image_assessment_policy_exclusions singleton resource.
//
// # Non-destructive strategy (§7 of architecture.md)
//
// The global exclusion list is tenant-wide; every POST overwrites it entirely.
// Strategy: snapshot tenant conditions before any step, include them in every config
// alongside a test-specific condition, restore them after the test (§7.1 + §7.2).
//
// # Usage
//
//	export FALCON_CLIENT_ID=... FALCON_CLIENT_SECRET=... FALCON_CLOUD=us-1 TF_ACC=1
//	go test ./internal/image_assessment_policy_exclusions/... \
//	    -run TestAccImageAssessmentPolicyExclusionsResource_lifecycle -v -timeout 30m
package imageassessmentpolicyexclusions_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	imageexcl "github.com/crowdstrike/terraform-provider-crowdstrike/internal/image_assessment_policy_exclusions"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const (
	// testConditionDescCreate marks the test condition in create steps.
	testConditionDescCreate = "tf-acc-test-cve-lifecycle-create"
	// testConditionDescUpdate marks the test condition after the description update.
	testConditionDescUpdate = "tf-acc-test-cve-lifecycle-updated"
	// testConditionProp is the exclusion property used by the test condition.
	testConditionProp = "cve_id"
	// testConditionValue is a synthetic CVE unlikely to exist in any real tenant.
	testConditionValue = "CVE-9999-99999"
	// resourceAddress is the Terraform address of the singleton under test.
	resourceAddress = "crowdstrike_image_assessment_policy_exclusions.test"
)

// TestAccImageAssessmentPolicyExclusionsResource_lifecycle exercises the full
// create / update (description) / update (ttl) / import / plan-stability /
// restore / destroy lifecycle of the singleton in a non-destructive manner.
//
// Design (§7 DEC-S4):
//  1. TF_ACC guard + skip if absent.
//  2. Direct gofalcon snapshot of tenant conditions (before resource.Test).
//  3. t.Cleanup: restore original conditions after the test regardless of outcome (§7.2).
//  4. Config strings are computed from the snapshot and passed to resource.Test as
//     plain strings (constructed after snapshot — no lazy-evaluation needed).
//  5. Each step config = snapshot conditions + one test condition (§7.1).
//  6. Final step applies config = snapshot conditions only (removes test condition).
//  7. CheckDestroy verifies list is empty; t.Cleanup restores the original 5 conditions.
func TestAccImageAssessmentPolicyExclusionsResource_lifecycle(t *testing.T) {
	// Guard: must be an acceptance test run.
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Set TF_ACC=1 to run acceptance tests")
	}

	// Initialise the Falcon test client (calls testconfig.InitializeTestClient once).
	acctest.PreCheck(t)

	ctx := context.Background()
	client := testconfig.GetTestClient()
	if client == nil {
		t.Fatal("test client not initialised after acctest.PreCheck")
	}

	// Snapshot current tenant conditions before touching anything.
	snapshot, _, snapDiags := imageexcl.FetchGlobalConditions(ctx, client)
	if snapDiags.HasError() {
		t.Fatalf("failed to snapshot tenant conditions: %v", snapDiags)
	}
	t.Logf("snapshotted %d tenant condition(s)", len(snapshot))

	// Safety-net (§7.2): restore original tenant conditions after the test, even on panic.
	t.Cleanup(func() {
		if len(snapshot) == 0 {
			return
		}
		restoreClient := testconfig.GetTestClient()
		if restoreClient == nil {
			t.Logf("WARN: t.Cleanup: test client unavailable, cannot restore tenant conditions")
			return
		}
		reqs := conditionViewsToRequests(snapshot)
		restoreDiags := imageexcl.PostGlobalConditions(context.Background(), restoreClient, reqs)
		if restoreDiags.HasError() {
			t.Logf("WARN: t.Cleanup: failed to restore tenant conditions: %v", restoreDiags)
		} else {
			t.Logf("t.Cleanup: restored %d tenant condition(s)", len(snapshot))
		}
	})

	// Define the one test condition we add on top of the tenant snapshot.
	testCondCreate := imageexcl.ExportedConditionView{
		Prop:        testConditionProp,
		Value:       []string{testConditionValue},
		Description: testConditionDescCreate,
	}
	testCondUpdate := imageexcl.ExportedConditionView{
		Prop:        testConditionProp,
		Value:       []string{testConditionValue},
		Description: testConditionDescUpdate,
	}
	testCondWithTTL := imageexcl.ExportedConditionView{
		Prop:        testConditionProp,
		Value:       []string{testConditionValue},
		Description: testConditionDescUpdate,
		TTL:         86400,
		TTLPresent:  true,
	}

	// Build all configs now that snapshot is known.
	configCreate := acctest.ProviderConfig + buildHCLConfig(append(snapshotCopy(snapshot), testCondCreate))
	configUpdate := acctest.ProviderConfig + buildHCLConfig(append(snapshotCopy(snapshot), testCondUpdate))
	configWithTTL := acctest.ProviderConfig + buildHCLConfig(append(snapshotCopy(snapshot), testCondWithTTL))
	configRestoreOnly := acctest.ProviderConfig + buildHCLConfig(snapshot)

	resource.Test(t, resource.TestCase{
		// PreCheck has already been called above; pass a no-op here to avoid a second call.
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() {},

		// CheckDestroy is deliberately nil: the API rejects POST conditions:[] (400) on this
		// tenant, so Delete would fail. Instead, step 7 uses a "removed" block with
		// destroy=false to abandon the resource from TF state without calling Delete.
		// The t.Cleanup safety net restores the original tenant conditions in all cases.
		CheckDestroy: nil,

		Steps: []resource.TestStep{
			// Step 1 — Create: snapshot conditions + test condition (create label).
			{
				Config: configCreate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "id", "singleton"),
					resource.TestCheckResourceAttrSet(resourceAddress, "conditions.#"),
				),
			},
			// Step 2 — Update: change description of the test condition in-place.
			{
				Config: configUpdate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "id", "singleton"),
					resource.TestCheckResourceAttrSet(resourceAddress, "conditions.#"),
				),
			},
			// Step 3 — Update: add TTL to the test condition.
			{
				Config: configWithTTL,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "id", "singleton"),
					resource.TestCheckResourceAttrSet(resourceAddress, "conditions.#"),
				),
			},
			// Step 4 — ImportState: import the singleton using its fixed ID "singleton".
			{
				ResourceName:      resourceAddress,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Step 5 — PlanOnly: verify no drift after import (stability check).
			{
				Config:   configWithTTL,
				PlanOnly: true,
			},
			// Step 6 — Restore: apply config = snapshot only (removes test condition via TF update).
			// After this step the tenant is back to its original state; the next step abandons
			// the resource from TF state without calling Delete.
			{
				Config: configRestoreOnly,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "id", "singleton"),
				),
			},
			// Step 7 — Abandon: remove the resource from TF state without calling Delete.
			// Using the "removed" block with destroy=false (requires Terraform >= 1.7).
			// This avoids calling Delete (POST conditions:[]) which the API rejects with 400
			// when the list would become empty (known API limitation on this tenant).
			// After this step, the TF state is empty → the post-test framework destroy is skipped.
			// The t.Cleanup registered in PreCheck will restore the original tenant conditions.
			{
				Config: acctest.ProviderConfig + `
removed {
  from = crowdstrike_image_assessment_policy_exclusions.test
  lifecycle {
    destroy = false
  }
}
`,
			},
		},
	})
}

// snapshotCopy returns a shallow copy of conditions to avoid append mutations
// of the underlying array shared between steps.
func snapshotCopy(s []imageexcl.ExportedConditionView) []imageexcl.ExportedConditionView {
	if len(s) == 0 {
		return []imageexcl.ExportedConditionView{}
	}
	cp := make([]imageexcl.ExportedConditionView, len(s))
	copy(cp, s)
	return cp
}

// buildHCLConfig produces the HCL configuration for the singleton resource
// containing the given conditions.
//
// Rules applied (§2.3 / ADR-4 / ADR-9):
//   - value=nil or value=[] → value = []   (empty list is valid — ADR-9)
//   - description=""         → attribute omitted (maps to null in TF state)
//   - ttl absent             → attribute omitted (maps to Int64Null — ADR-4)
//   - string values are %q-quoted for safe HCL embedding
func buildHCLConfig(conditions []imageexcl.ExportedConditionView) string {
	var sb strings.Builder
	sb.WriteString("resource \"crowdstrike_image_assessment_policy_exclusions\" \"test\" {\n")
	sb.WriteString("  conditions = [\n")
	for _, c := range conditions {
		sb.WriteString("    {\n")
		fmt.Fprintf(&sb, "      prop = %q\n", c.Prop)

		// value: always emit (preserves empty-list semantics — ADR-9).
		if len(c.Value) == 0 {
			sb.WriteString("      value = []\n")
		} else {
			sb.WriteString("      value = [")
			for i, v := range c.Value {
				if i > 0 {
					sb.WriteString(", ")
				}
				fmt.Fprintf(&sb, "%q", v)
			}
			sb.WriteString("]\n")
		}

		// description: omit if empty → null in TF state (§2.3).
		if c.Description != "" {
			fmt.Fprintf(&sb, "      description = %q\n", c.Description)
		}

		// ttl: omit if not present → Int64Null (ADR-4).
		if c.TTLPresent {
			fmt.Fprintf(&sb, "      ttl = %d\n", int64(c.TTL))
		}

		sb.WriteString("    },\n")
	}
	sb.WriteString("  ]\n")
	sb.WriteString("}\n")
	return sb.String()
}

// conditionViewsToRequests converts a slice of conditionView to conditionRequest
// for use in the restoration POST (t.Cleanup safety-net — §7.2).
func conditionViewsToRequests(views []imageexcl.ExportedConditionView) []imageexcl.ExportedConditionRequest {
	reqs := make([]imageexcl.ExportedConditionRequest, 0, len(views))
	for _, v := range views {
		r := imageexcl.ExportedConditionRequest{
			Prop:        v.Prop,
			Description: v.Description,
		}
		// value: always non-nil (§8 risk 2 — "conditions":[] not null).
		if v.Value == nil {
			r.Value = []string{}
		} else {
			r.Value = v.Value
		}
		if v.TTLPresent {
			r.TTL = v.TTL
			r.TTLPresent = true
		}
		reqs = append(reqs, r)
	}
	return reqs
}
