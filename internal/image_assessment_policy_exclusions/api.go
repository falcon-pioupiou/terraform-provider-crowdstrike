package imageassessmentpolicyexclusions

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	imagepolicies "github.com/crowdstrike/gofalcon/falcon/client/image_assessment_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/retry"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// Retry configuration for transient API errors.
//
// retryWriteTimeout is the maximum total time we will wait for a POST to succeed.
// retryWriteInterval is the pause between successive POST attempts.
// retryReadTimeout / retryReadInterval mirror the same constants for the GET.
//
// Values match those used in internal/rtr_script/api.go (30 s / 5 s) and are
// appropriate for short-lived server-side transient failures (5xx / 429).
const (
	retryWriteTimeout  = 30 * time.Second
	retryWriteInterval = 5 * time.Second
	retryReadTimeout   = 30 * time.Second
	retryReadInterval  = 5 * time.Second
)

// isRetryablePostError reports whether err from UpdatePolicyExclusions warrants a retry.
//
// Strategy: prefer a type-switch on the gofalcon-generated error types for the two
// HTTP status codes whose retryability is certain (500, 429). For status codes that
// the swagger spec does not define (502, 503, 504) the SDK falls through to
// runtime.NewAPIError, which embeds the numeric code in the error string as "[NNN]".
// We therefore add a strings.Contains fallback for those three codes only.
//
// Codes that must NOT be retried: 400 (bad request / collision), 403 (forbidden /
// scope), 404, 409 and any other 4xx. Returning false for those lets the caller
// propagate them immediately via the normal tferrors path.
func isRetryablePostError(err error) bool {
	if err == nil {
		return false
	}
	// Type-switch on known gofalcon types for this endpoint.
	switch err.(type) {
	case *imagepolicies.UpdatePolicyExclusionsInternalServerError: // 500
		return true
	case *imagepolicies.UpdatePolicyExclusionsTooManyRequests: // 429
		return true
	}
	// Fallback for gateway-level errors (502, 503, 504) not defined in the swagger
	// spec; the go-openapi runtime wraps them as plain errors with "[NNN]" in the
	// message — consistent with the host_groups retry pattern (strings.Contains).
	msg := err.Error()
	return strings.Contains(msg, "[502]") ||
		strings.Contains(msg, "[503]") ||
		strings.Contains(msg, "[504]")
}

// isRetryableGetError is the read-side equivalent for ReadPolicyExclusions.
// Same logic: type-switch for 500/429, fallback for 502/503/504.
func isRetryableGetError(err error) bool {
	if err == nil {
		return false
	}
	switch err.(type) {
	case *imagepolicies.ReadPolicyExclusionsInternalServerError: // 500
		return true
	case *imagepolicies.ReadPolicyExclusionsTooManyRequests: // 429
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "[502]") ||
		strings.Contains(msg, "[503]") ||
		strings.Contains(msg, "[504]")
}

// conditionView is the internal representation of one exclusion condition as read from the API.
// It holds only the fields we consume (op is intentionally absent).
type conditionView struct {
	Description string
	Prop        string
	Value       []string // preserved as-is, including []
	TTL         float64  // 0 means absent (omitempty in JSON)
	TTLPresent  bool     // true when TTL was non-zero in the API response
	CreatedAt   string
	UpdatedAt   string
}

// conditionRequest is the internal representation of one exclusion condition to POST to the API.
// It mirrors ModelsExclusionConditionRequest fields without using the SDK type directly.
type conditionRequest struct {
	Description string // "" means omit (omitempty on the model)
	Prop        string
	Value       []string // always serialised, including []
	TTL         float64  // 0 means omit (omitempty on the model)
	TTLPresent  bool     // when false, TTL is not set even if zero
}

// fetchGlobalConditions calls ReadPolicyExclusions (GET) and returns all conditions
// flattened from all Resources entries plus the count of Resource entries (for the ADR-1 guard).
//
// The GET is wrapped in a retry loop (timeout retryReadTimeout, interval retryReadInterval)
// to handle transient server-side errors (5xx, 429). Non-retryable errors (4xx other than 429)
// are captured and propagated immediately without exhausting the retry budget.
func fetchGlobalConditions(
	ctx context.Context,
	c *client.CrowdStrikeAPISpecification,
) (conditions []conditionView, resourceCount int, diags diag.Diagnostics) {
	params := imagepolicies.NewReadPolicyExclusionsParamsWithContext(ctx)

	// nonRetryableErr captures the first non-retryable API error so we can
	// propagate it after the retry loop exits (via return nil in fn).
	var nonRetryableGetErr error
	var resp *imagepolicies.ReadPolicyExclusionsOK

	retryErr := retry.RetryUntilNoError(ctx, retryReadTimeout, retryReadInterval, func() error {
		var callErr error
		resp, callErr = c.ImageAssessmentPolicies.ReadPolicyExclusions(params)
		if callErr == nil {
			return nil // success
		}
		if isRetryableGetError(callErr) {
			return callErr // trigger another attempt
		}
		// Non-retryable error: capture it and stop the loop by returning nil.
		nonRetryableGetErr = callErr
		return nil
	})

	// Propagate a non-retryable error (4xx, etc.) immediately.
	if nonRetryableGetErr != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			nonRetryableGetErr,
			requiredScopes,
		))
		return nil, 0, diags
	}

	// Propagate a retryable error that was never resolved (timeout / ctx cancelled).
	if retryErr != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			retryErr,
			requiredScopes,
		))
		return nil, 0, diags
	}

	if resp == nil || resp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, 0, diags
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, resp.Payload.Errors); d != nil {
		diags.Append(d)
		return nil, 0, diags
	}

	// Resources may be empty (no exclusions configured at all) — that is valid.
	resourceCount = len(resp.Payload.Resources)

	// Defensive flattening: concatenate conditions from all Resources entries.
	for _, resource := range resp.Payload.Resources {
		if resource == nil {
			continue
		}
		for _, cond := range resource.Conditions {
			if cond == nil {
				continue
			}
			cv := conditionView{
				CreatedAt: cond.CreatedAt,
				UpdatedAt: cond.UpdatedAt,
			}
			if cond.Description != nil {
				cv.Description = *cond.Description
			}
			if cond.Prop != nil {
				cv.Prop = *cond.Prop
			}
			// Value preserved as-is, including []
			cv.Value = cond.Value
			if cond.TTL != 0 {
				cv.TTL = cond.TTL
				cv.TTLPresent = true
			}
			conditions = append(conditions, cv)
		}
	}

	return conditions, resourceCount, diags
}

// postGlobalConditions calls UpdatePolicyExclusions (POST) with the given full list of conditions.
//
// The POST is wrapped in a retry loop (timeout retryWriteTimeout, interval retryWriteInterval)
// to handle transient server-side errors (5xx, 429). Non-retryable errors (4xx other than 429,
// e.g. 400 collision, 403 scope) stop the loop immediately without consuming the retry budget.
//
// IMPORTANT: conds must be a non-nil slice (use make([]conditionRequest, 0) for Delete)
// to guarantee JSON marshalling produces "conditions":[] and not "conditions":null (§8 risk 2).
func postGlobalConditions(
	ctx context.Context,
	c *client.CrowdStrikeAPISpecification,
	op tferrors.Operation,
	conds []conditionRequest,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// Always initialise with make to guarantee "conditions":[] (not null) when empty — §8 risk 2.
	apiConds := make([]*models.ModelsExclusionConditionRequest, 0, len(conds))
	for _, cr := range conds {
		prop := cr.Prop
		req := &models.ModelsExclusionConditionRequest{
			Prop:        &prop,
			Value:       cr.Value,
			Description: cr.Description,
		}
		if cr.TTLPresent {
			req.TTL = cr.TTL
		}
		apiConds = append(apiConds, req)
	}

	params := imagepolicies.NewUpdatePolicyExclusionsParamsWithContext(ctx)
	params.SetBody(&models.ModelsUpdateExclusionsRequest{
		Conditions: apiConds,
	})

	// nonRetryableErr captures the first non-retryable API error so we can
	// propagate it after the retry loop exits (via return nil in fn).
	var nonRetryablePostErr error
	var resp *imagepolicies.UpdatePolicyExclusionsOK

	retryErr := retry.RetryUntilNoError(ctx, retryWriteTimeout, retryWriteInterval, func() error {
		var callErr error
		resp, callErr = c.ImageAssessmentPolicies.UpdatePolicyExclusions(params)
		if callErr == nil {
			return nil // success
		}
		if isRetryablePostError(callErr) {
			return callErr // trigger another attempt
		}
		// Non-retryable error (400, 403, 404, 409, …): capture it and stop the loop.
		nonRetryablePostErr = callErr
		return nil
	})

	// Propagate a non-retryable error (4xx, etc.) immediately.
	if nonRetryablePostErr != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			op,
			nonRetryablePostErr,
			requiredScopes,
		))
		return diags
	}

	// Propagate a retryable error that was never resolved (timeout / ctx cancelled).
	if retryErr != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			op,
			retryErr,
			requiredScopes,
		))
		return diags
	}

	if resp == nil || resp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(op))
		return diags
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(op, resp.Payload.Errors); d != nil {
		diags.Append(d)
		return diags
	}

	return diags
}

// mapConditionsToRequests converts the Set of conditionModel (from TF plan/state) to a slice of
// conditionRequest for POST. For each condition:
//   - prop: cond.Prop.ValueString()
//   - value: extracted via ElementsAs; null OR [] → []string{} non-nil ALWAYS (never nil — §8 risk 2)
//   - description: null → "" (omitempty handles it); otherwise cond.Description.ValueString()
//   - ttl: null → TTLPresent=false; otherwise float64(cond.TTL.ValueInt64()), TTLPresent=true
func mapConditionsToRequests(ctx context.Context, conditions []conditionModel) ([]conditionRequest, diag.Diagnostics) {
	var diags diag.Diagnostics
	result := make([]conditionRequest, 0, len(conditions))

	for _, cond := range conditions {
		cr := conditionRequest{
			Prop: cond.Prop.ValueString(),
		}

		// value: always use non-nil empty slice as default (never nil — §8 risk 2).
		cr.Value = []string{}
		if !cond.Value.IsNull() && !cond.Value.IsUnknown() {
			var slice []string
			d := cond.Value.ElementsAs(ctx, &slice, false)
			diags.Append(d...)
			if slice != nil {
				cr.Value = slice
			}
			// If slice is nil after ElementsAs on empty list, cr.Value stays []string{}.
		}

		// description: null → "" (omitempty); otherwise the string value.
		if !cond.Description.IsNull() && !cond.Description.IsUnknown() {
			cr.Description = cond.Description.ValueString()
		}

		// ttl: null → TTLPresent=false (field omitted via omitempty); otherwise convert.
		if !cond.TTL.IsNull() && !cond.TTL.IsUnknown() {
			cr.TTL = float64(cond.TTL.ValueInt64())
			cr.TTLPresent = true
		}

		result = append(result, cr)
	}

	return result, diags
}

// floatTTLToInt64 converts a float64 TTL value (from API) to int64 (for TF state).
// Returns an error diagnostic if the value is not a whole number (ADR-4).
func floatTTLToInt64(_ context.Context, ttl float64) (int64, diag.Diagnostic) {
	rounded := math.Round(ttl)
	if math.Abs(ttl-rounded) > 1e-9 {
		return 0, diag.NewErrorDiagnostic(
			"Non-integer TTL value",
			"The API returned a fractional TTL value which cannot be represented as an integer. "+
				"Please report this issue at: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)
	}
	return int64(rounded), nil
}
