package imageassessmentpolicyexclusions

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// RegisterSweepers registers the sweep function for crowdstrike_image_assessment_policy_exclusions.
// With the singleton model, "sweeping" means POSTing an empty list — there is no prefix-based
// filtering since the singleton owns the entire list. The sweep clears all conditions.
func RegisterSweepers() {
	sweep.Register("crowdstrike_image_assessment_policy_exclusions", sweepImageAssessmentPolicyExclusions)
}

// sweepImageAssessmentPolicyExclusions implements the sweep by returning a single Sweepable
// that POSTs an empty conditions list — effectively destroying the singleton content.
func sweepImageAssessmentPolicyExclusions(
	ctx context.Context,
	c *client.CrowdStrikeAPISpecification,
) ([]sweep.Sweepable, error) {
	// With the singleton, "sweep" = POST empty list. Return one Sweepable that does exactly that.
	sweepables := []sweep.Sweepable{
		sweep.NewSweepResource(
			"singleton",
			"crowdstrike_image_assessment_policy_exclusions",
			func(ctx context.Context, c *client.CrowdStrikeAPISpecification, _ string) error {
				return clearAllExclusionConditions(ctx, c)
			},
		),
	}
	return sweepables, nil
}

// clearAllExclusionConditions posts an empty conditions list to clear the singleton.
// Uses make([]conditionRequest, 0) to guarantee JSON "conditions":[] (not null) — §8 risk 2.
func clearAllExclusionConditions(
	ctx context.Context,
	c *client.CrowdStrikeAPISpecification,
) error {
	postDiags := postGlobalConditions(ctx, c, tferrors.Delete, make([]conditionRequest, 0))
	if postDiags.HasError() {
		for _, d := range postDiags {
			if d.Severity() == diag.SeverityError {
				err := fmt.Errorf("%s: %s", d.Summary(), d.Detail())
				if sweep.ShouldIgnoreError(err) {
					sweep.Debug("Ignoring error during sweep clear: %s", err)
					return nil
				}
				return err
			}
		}
	}
	return nil
}
