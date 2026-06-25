package imageassessmentpolicyexclusions

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &imageAssessmentPolicyExclusionsResource{}
	_ resource.ResourceWithConfigure   = &imageAssessmentPolicyExclusionsResource{}
	_ resource.ResourceWithImportState = &imageAssessmentPolicyExclusionsResource{}
)

// requiredScopes declares the API scopes needed by this resource.
var requiredScopes = []scopes.Scope{
	{
		Name:  "Falcon Container Image",
		Read:  true,
		Write: true,
	},
}

// NewImageAssessmentPolicyExclusionsResource returns a new resource.Resource for
// crowdstrike_image_assessment_policy_exclusions (singleton).
func NewImageAssessmentPolicyExclusionsResource() resource.Resource {
	return &imageAssessmentPolicyExclusionsResource{}
}

type imageAssessmentPolicyExclusionsResource struct {
	client *client.CrowdStrikeAPISpecification
}

// imageAssessmentPolicyExclusionsModel is the Terraform state model for the singleton resource.
// All fields use Terraform Framework types (never Go native types), with tfsdk tags.
type imageAssessmentPolicyExclusionsModel struct {
	// id: Computed, UseStateForUnknown. Fixed value "singleton".
	ID types.String `tfsdk:"id"`
	// conditions: Required Set of NestedAttributeObject. The exhaustive list of global exclusions.
	Conditions types.Set `tfsdk:"conditions"`
}

// conditionModel is the model for a single element of the conditions Set.
type conditionModel struct {
	Prop        types.String `tfsdk:"prop"`
	Value       types.List   `tfsdk:"value"`
	Description types.String `tfsdk:"description"`
	TTL         types.Int64  `tfsdk:"ttl"`
}

// conditionObjectAttrTypes returns the attribute types map for conditionModel, used to build Set elements.
func conditionObjectAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"prop":        types.StringType,
		"value":       types.ListType{ElemType: types.StringType},
		"description": types.StringType,
		"ttl":         types.Int64Type,
	}
}

// wrap maps a slice of conditionView (already flattened) to TF state on the model.
// It sets m.Conditions but does NOT set m.ID — the CRUD layer does that.
//
// For each conditionView:
//   - prop: types.StringValue
//   - value: ALWAYS non-null List (empty or populated) — never use flex.FlattenStringValueList
//     which would nullify empty lists (ADR-9 / §2.3).
//   - description: flex.StringValueToFramework → "" → null TF
//   - ttl: TTLPresent=false → Int64Null; otherwise floatTTLToInt64 with error diag on fraction
func (m *imageAssessmentPolicyExclusionsModel) wrap(
	ctx context.Context,
	globals []conditionView,
) diag.Diagnostics {
	var diags diag.Diagnostics

	items := make([]conditionModel, 0, len(globals))
	for _, cv := range globals {
		cm := conditionModel{}

		cm.Prop = types.StringValue(cv.Prop)
		cm.Description = flex.StringValueToFramework(cv.Description)

		// value: always produce a non-null list — empty or populated.
		// We intentionally do NOT use flex.FlattenStringValueList here because that
		// function converts [] to null — but we need to preserve the empty list (ADR-9 / §2.3).
		if len(cv.Value) == 0 {
			listVal, d := types.ListValueFrom(ctx, types.StringType, []string{})
			diags.Append(d...)
			cm.Value = listVal
		} else {
			listVal, d := types.ListValueFrom(ctx, types.StringType, cv.Value)
			diags.Append(d...)
			cm.Value = listVal
		}

		// ttl: null if absent; convert float64 → int64 with diagnostic on non-integer.
		if !cv.TTLPresent {
			cm.TTL = types.Int64Null()
		} else {
			i64, d := floatTTLToInt64(ctx, cv.TTL)
			if d != nil {
				diags.Append(d)
				cm.TTL = types.Int64Null()
			} else {
				cm.TTL = types.Int64Value(i64)
			}
		}

		items = append(items, cm)
	}

	// Build the Set from the slice of conditionModel.
	setVal, d := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: conditionObjectAttrTypes()}, items)
	diags.Append(d...)
	m.Conditions = setVal

	return diags
}

func (r *imageAssessmentPolicyExclusionsResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	r.client = providerConfig.Client
}

func (r *imageAssessmentPolicyExclusionsResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_image_assessment_policy_exclusions"
}

func (r *imageAssessmentPolicyExclusionsResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Container Security",
			"Manages the complete global image assessment policy exclusions list as a singleton resource "+
				"in the CrowdStrike Falcon Platform. This resource owns the entire list: every apply "+
				"replaces the list with the conditions declared in the configuration. "+
				"**Terraform is the source of truth — any change made outside Terraform (e.g. in the "+
				"Falcon console) will be overwritten on the next apply.** "+
				"This resource uses a singleton pattern (ID = `\"singleton\"`); only one instance may "+
				"exist per Terraform configuration. To import the existing conditions: "+
				"`terraform import crowdstrike_image_assessment_policy_exclusions.this singleton`. "+
				"The `-parallelism=1` constraint of the previous per-condition resource is no longer "+
				"needed with this singleton. "+
				"**Note on destroy:** `terraform destroy` removes this resource from Terraform state "+
				"only — it does NOT clear the exclusion list on the tenant. The CrowdStrike public API "+
				"does not expose an endpoint to empty the list. To clear all exclusions, set "+
				"`conditions = []` in your configuration and run `terraform apply` before destroying.",
			requiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Stable identifier for this singleton resource. Always `\"singleton\"`. " +
					"Use `terraform import crowdstrike_image_assessment_policy_exclusions.this singleton` " +
					"to import the current tenant conditions.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"conditions": schema.SetNestedAttribute{
				Required: true,
				MarkdownDescription: "The exhaustive list of global image assessment policy exclusion conditions. " +
					"**Terraform is the source of truth** — any change made outside Terraform " +
					"(e.g. in the Falcon console) will be overwritten on the next apply. " +
					"Use `conditions = []` to explicitly declare an empty list. " +
					"An empty set is valid and will POST `conditions:[]` to the API. " +
					"The `-parallelism=1` constraint is no longer required with this singleton resource. " +
					"Common values for `prop`: `vulnerabilities_no_fix`, `cve_id`, `packages`, " +
					"`vulnerabilities_published` (non-exhaustive — the backend may accept additional values). " +
					"For `vulnerabilities_no_fix` and `vulnerabilities_published`, omitting `value` or " +
					"setting `value = []` is valid — the exclusion applies to the property alone. " +
					"Setting `value = []` is equivalent to omitting `value`.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"prop": schema.StringAttribute{
							Required: true,
							MarkdownDescription: "The exclusion property. Common values: `vulnerabilities_no_fix`, " +
								"`cve_id`, `packages`, `vulnerabilities_published`. The list is non-exhaustive — " +
								"the backend may accept additional values.",
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
						"value": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							MarkdownDescription: "List of values for the exclusion property. " +
								"An empty list (`value = []`) or omitting this attribute is valid for properties " +
								"like `vulnerabilities_no_fix` and `vulnerabilities_published` where the exclusion " +
								"applies to the property alone. Both are equivalent at the API level.",
							Validators: []validator.List{
								listvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
							},
						},
						"description": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Optional description for this exclusion condition.",
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
						"ttl": schema.Int64Attribute{
							Optional: true,
							MarkdownDescription: "Time-to-live for this exclusion condition, in seconds " +
								"(e.g. `2592000` = 30 days, `864000` = 10 days). " +
								"When absent or null the condition has no expiry.",
							Validators: []validator.Int64{
								int64validator.AtLeast(1),
							},
						},
					},
				},
			},
		},
	}
}

// Create implements the singleton creation (§3.1).
// Early state sets id="singleton" so TF can track/clean up even if subsequent steps fail.
func (r *imageAssessmentPolicyExclusionsResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan imageAssessmentPolicyExclusionsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Early state set: guarantee TF can track/clean up even if subsequent steps fail (§3.1).
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), "singleton")...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract conditions from the Set into []conditionModel.
	conditions, diags := planSetToConditionModels(ctx, plan.Conditions)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Map to []conditionRequest for POST.
	reqList, diags := mapConditionsToRequests(ctx, conditions)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// POST.
	resp.Diagnostics.Append(postGlobalConditions(ctx, r.client, tferrors.Create, reqList)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Re-read after POST (ADR-1 guard: warn if >1 resource entries).
	globals, n, diags := fetchGlobalConditions(ctx, r.client)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if n > 1 {
		resp.Diagnostics.AddWarning(
			"Multiple policy exclusion resource entries detected",
			fmt.Sprintf(
				"The API returned %d resource entries in the policy exclusions list. "+
					"This provider flattens all conditions and re-posts them as a single list. "+
					"Groupings may be collapsed.",
				n,
			),
		)
	}

	// Wrap the API response back into TF state.
	resp.Diagnostics.Append(plan.wrap(ctx, globals)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = types.StringValue("singleton")

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read implements the refresh of the singleton (§3.2).
func (r *imageAssessmentPolicyExclusionsResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state imageAssessmentPolicyExclusionsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	globals, n, diags := fetchGlobalConditions(ctx, r.client)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if n > 1 {
		resp.Diagnostics.AddWarning(
			"Multiple policy exclusion resource entries detected",
			fmt.Sprintf(
				"The API returned %d resource entries in the policy exclusions list. "+
					"This provider flattens all conditions and re-posts them as a single list. "+
					"Groupings may be collapsed.",
				n,
			),
		)
	}

	resp.Diagnostics.Append(state.wrap(ctx, globals)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.ID = types.StringValue("singleton")

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update implements in-place replacement of the full conditions list (§3.3).
func (r *imageAssessmentPolicyExclusionsResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan imageAssessmentPolicyExclusionsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract conditions from the Set into []conditionModel.
	conditions, diags := planSetToConditionModels(ctx, plan.Conditions)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Map to []conditionRequest for POST.
	reqList, diags := mapConditionsToRequests(ctx, conditions)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// POST.
	resp.Diagnostics.Append(postGlobalConditions(ctx, r.client, tferrors.Update, reqList)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Re-read after POST (ADR-1 guard: warn if >1 resource entries).
	globals, n, diags := fetchGlobalConditions(ctx, r.client)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if n > 1 {
		resp.Diagnostics.AddWarning(
			"Multiple policy exclusion resource entries detected",
			fmt.Sprintf(
				"The API returned %d resource entries in the policy exclusions list. "+
					"This provider flattens all conditions and re-posts them as a single list. "+
					"Groupings may be collapsed.",
				n,
			),
		)
	}

	resp.Diagnostics.Append(plan.wrap(ctx, globals)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = types.StringValue("singleton")

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete removes the resource from Terraform state only.
//
// The CrowdStrike public API does not support clearing the global exclusion list:
// POST with conditions:[] returns HTTP 400. The console uses an internal PATCH endpoint
// (not exposed in the public API) to empty the list. Until a public API endpoint
// supports this operation, destroy is a no-op against the API — the exclusion list
// on the tenant is left unchanged. To clear the list, set conditions = [] in your
// configuration and run terraform apply before destroying.
func (r *imageAssessmentPolicyExclusionsResource) Delete(
	_ context.Context,
	_ resource.DeleteRequest,
	_ *resource.DeleteResponse,
) {
	// No-op: the framework removes the resource from state automatically after this returns.
}

// ImportState allows importing the singleton by providing "singleton" as the ID.
// The subsequent Read call will populate state from the API.
func (r *imageAssessmentPolicyExclusionsResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// planSetToConditionModels extracts []conditionModel from a types.Set.
// Returns an empty slice (not nil) when the set is empty.
func planSetToConditionModels(ctx context.Context, set types.Set) ([]conditionModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	conditions := make([]conditionModel, 0)

	if set.IsNull() || set.IsUnknown() {
		return conditions, diags
	}

	diags.Append(set.ElementsAs(ctx, &conditions, false)...)
	return conditions, diags
}
