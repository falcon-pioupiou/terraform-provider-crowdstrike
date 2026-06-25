package imageassessmentpolicyexclusions

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// ExportedConditionView is the exported type alias for conditionView,
// used in acceptance tests to inspect and reconstruct tenant conditions.
type ExportedConditionView = conditionView

// ExportedConditionRequest is the exported type alias for conditionRequest,
// used in acceptance tests to build POST payloads for restoration.
type ExportedConditionRequest = conditionRequest

// FetchGlobalConditions exposes the internal fetchGlobalConditions for acceptance tests.
// Returns the flattened conditions, resource count, and diagnostics.
func FetchGlobalConditions(
	ctx context.Context,
	c *client.CrowdStrikeAPISpecification,
) ([]conditionView, int, diag.Diagnostics) {
	return fetchGlobalConditions(ctx, c)
}

// PostGlobalConditions exposes the internal postGlobalConditions for acceptance tests.
// Used by acceptance tests to restore tenant conditions after the test run.
// Uses tferrors.Update as the operation label for diagnostic messages.
func PostGlobalConditions(
	ctx context.Context,
	c *client.CrowdStrikeAPISpecification,
	conds []conditionRequest,
) diag.Diagnostics {
	return postGlobalConditions(ctx, c, tferrors.Update, conds)
}
