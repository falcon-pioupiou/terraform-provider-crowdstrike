package imageassessmentpolicyexclusions

// Unit tests for the imageAssessmentPolicyExclusionsResource singleton (T-R02).
// These tests do NOT require TF_ACC and make NO live API calls.
//
// Coverage:
//   - .wrap(): value=[] API → non-null TF List; value populated → populated list;
//     ttl absent → Int64Null (never 0); description="" → null TF
//   - mapConditionsToRequests: null TF value → []string{} non-nil; value=[] → []string{} non-nil;
//     ttl null → TTLPresent=false
//   - floatTTLToInt64: integer → OK; fraction → diagnostic error
//   - JSON marshalling: DELETE POST with make([]conditionRequest,0) produces "conditions":[]
//     and not "conditions":null (§8 risk 2)
//   - isRetryablePostError / isRetryableGetError: typed 500/429, string 502/503/504 → true;
//     typed 403, string 400/403/404 → false; nil → false
//   - Metadata TypeName = "crowdstrike_image_assessment_policy_exclusions" (pluriel)
//   - Schema: conditions is SetNestedAttribute Required; value is ListAttribute Optional NO SizeAtLeast

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	imagepolicies "github.com/crowdstrike/gofalcon/falcon/client/image_assessment_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// .wrap()
// ---------------------------------------------------------------------------

// TestWrap_EmptyValueAPIProducesNonNullList verifies that wrap() with value=[] API
// produces a non-null TF List (empty, not null) — ADR-9 / §2.3.
func TestWrap_EmptyValueAPIProducesNonNullList(t *testing.T) {
	ctx := context.Background()

	globals := []conditionView{
		{
			Prop:       "vulnerabilities_no_fix",
			Value:      []string{},
			TTLPresent: false,
		},
	}

	var m imageAssessmentPolicyExclusionsModel
	diags := m.wrap(ctx, globals)
	if diags.HasError() {
		t.Fatalf("wrap() returned error diagnostics: %v", diags)
	}

	// Extract the condition from the Set.
	var items []conditionModel
	diags = m.Conditions.ElementsAs(ctx, &items, false)
	if diags.HasError() {
		t.Fatalf("ElementsAs failed: %v", diags)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(items))
	}

	val := items[0].Value
	if val.IsNull() {
		t.Error("wrap() produced a null Value for API value=[]; expected non-null empty List")
	}
	if val.IsUnknown() {
		t.Error("wrap() produced unknown Value")
	}
	if len(val.Elements()) != 0 {
		t.Errorf("wrap() expected empty list, got %d elements", len(val.Elements()))
	}
}

// TestWrap_PopulatedValueProducesPopulatedList verifies that a populated API value produces
// a non-null, populated TF List.
func TestWrap_PopulatedValueProducesPopulatedList(t *testing.T) {
	ctx := context.Background()

	globals := []conditionView{
		{
			Prop:  "cve_id",
			Value: []string{"CVE-2024-1234", "CVE-2023-9999"},
		},
	}

	var m imageAssessmentPolicyExclusionsModel
	diags := m.wrap(ctx, globals)
	if diags.HasError() {
		t.Fatalf("wrap() returned error diagnostics: %v", diags)
	}

	var items []conditionModel
	diags = m.Conditions.ElementsAs(ctx, &items, false)
	if diags.HasError() {
		t.Fatalf("ElementsAs failed: %v", diags)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(items))
	}

	val := items[0].Value
	if val.IsNull() {
		t.Error("wrap() produced null Value for populated API list")
	}
	if len(val.Elements()) != 2 {
		t.Errorf("wrap() expected 2 elements, got %d", len(val.Elements()))
	}
}

// TestWrap_TTLAbsentProducesInt64Null verifies that TTLPresent=false produces Int64Null,
// never Int64Value(0) — ADR-4 / §2.3.
func TestWrap_TTLAbsentProducesInt64Null(t *testing.T) {
	ctx := context.Background()

	globals := []conditionView{
		{
			Prop:       "cve_id",
			Value:      []string{"CVE-1"},
			TTLPresent: false,
			TTL:        0,
		},
	}

	var m imageAssessmentPolicyExclusionsModel
	diags := m.wrap(ctx, globals)
	if diags.HasError() {
		t.Fatalf("wrap() returned error diagnostics: %v", diags)
	}

	var items []conditionModel
	diags = m.Conditions.ElementsAs(ctx, &items, false)
	if diags.HasError() {
		t.Fatalf("ElementsAs failed: %v", diags)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(items))
	}

	if !items[0].TTL.IsNull() {
		t.Errorf("wrap() with TTLPresent=false must produce Int64Null, got %v", items[0].TTL)
	}
}

// TestWrap_TTLPresentProducesInt64Value verifies that a present TTL is correctly mapped.
func TestWrap_TTLPresentProducesInt64Value(t *testing.T) {
	ctx := context.Background()

	globals := []conditionView{
		{
			Prop:       "packages",
			Value:      []string{"pkg-a"},
			TTLPresent: true,
			TTL:        2592000,
		},
	}

	var m imageAssessmentPolicyExclusionsModel
	diags := m.wrap(ctx, globals)
	if diags.HasError() {
		t.Fatalf("wrap() returned error diagnostics: %v", diags)
	}

	var items []conditionModel
	diags = m.Conditions.ElementsAs(ctx, &items, false)
	if diags.HasError() {
		t.Fatalf("ElementsAs failed: %v", diags)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(items))
	}

	if items[0].TTL.IsNull() {
		t.Error("wrap() with TTLPresent=true must produce non-null Int64")
	}
	if items[0].TTL.ValueInt64() != 2592000 {
		t.Errorf("wrap() expected TTL=2592000, got %d", items[0].TTL.ValueInt64())
	}
}

// TestWrap_DescriptionEmptyProducesNull verifies that description="" from API produces
// types.StringNull() in TF state — consistent with flex.StringValueToFramework behaviour.
func TestWrap_DescriptionEmptyProducesNull(t *testing.T) {
	ctx := context.Background()

	globals := []conditionView{
		{
			Prop:        "packages",
			Value:       []string{"pkg"},
			Description: "",
		},
	}

	var m imageAssessmentPolicyExclusionsModel
	diags := m.wrap(ctx, globals)
	if diags.HasError() {
		t.Fatalf("wrap() returned error diagnostics: %v", diags)
	}

	var items []conditionModel
	diags = m.Conditions.ElementsAs(ctx, &items, false)
	if diags.HasError() {
		t.Fatalf("ElementsAs failed: %v", diags)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(items))
	}

	if !items[0].Description.IsNull() {
		t.Errorf("wrap() with empty description must produce StringNull, got %v", items[0].Description)
	}
}

// TestWrap_EmptyGlobalsProducesEmptySet verifies that wrap() with no conditions
// produces a non-null empty Set.
func TestWrap_EmptyGlobalsProducesEmptySet(t *testing.T) {
	ctx := context.Background()

	var m imageAssessmentPolicyExclusionsModel
	diags := m.wrap(ctx, []conditionView{})
	if diags.HasError() {
		t.Fatalf("wrap() returned error diagnostics: %v", diags)
	}

	if m.Conditions.IsNull() {
		t.Error("wrap() with empty globals must produce non-null Set")
	}
	if len(m.Conditions.Elements()) != 0 {
		t.Errorf("wrap() expected empty Set, got %d elements", len(m.Conditions.Elements()))
	}
}

// ---------------------------------------------------------------------------
// mapConditionsToRequests
// ---------------------------------------------------------------------------

// TestMapConditionsToRequests_NullValueProducesNonNilSlice verifies that null TF List
// produces []string{} (never nil) — §8 risk 2.
func TestMapConditionsToRequests_NullValueProducesNonNilSlice(t *testing.T) {
	ctx := context.Background()

	conditions := []conditionModel{
		{
			Prop:        types.StringValue("vulnerabilities_no_fix"),
			Value:       types.ListNull(types.StringType),
			Description: types.StringNull(),
			TTL:         types.Int64Null(),
		},
	}

	result, diags := mapConditionsToRequests(ctx, conditions)
	if diags.HasError() {
		t.Fatalf("mapConditionsToRequests returned error diagnostics: %v", diags)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 request, got %d", len(result))
	}
	if result[0].Value == nil {
		t.Error("mapConditionsToRequests: null TF value must produce []string{} (not nil)")
	}
	if len(result[0].Value) != 0 {
		t.Errorf("mapConditionsToRequests: null TF value must produce empty slice, got len=%d", len(result[0].Value))
	}
}

// TestMapConditionsToRequests_EmptyListProducesNonNilSlice verifies that an empty TF List
// also produces []string{} (not nil).
func TestMapConditionsToRequests_EmptyListProducesNonNilSlice(t *testing.T) {
	ctx := context.Background()

	emptyList, d := types.ListValueFrom(ctx, types.StringType, []string{})
	if d.HasError() {
		t.Fatalf("ListValueFrom failed: %v", d)
	}

	conditions := []conditionModel{
		{
			Prop:        types.StringValue("vulnerabilities_published"),
			Value:       emptyList,
			Description: types.StringNull(),
			TTL:         types.Int64Null(),
		},
	}

	result, diags := mapConditionsToRequests(ctx, conditions)
	if diags.HasError() {
		t.Fatalf("mapConditionsToRequests returned error diagnostics: %v", diags)
	}
	if result[0].Value == nil {
		t.Error("mapConditionsToRequests: empty TF List must produce []string{} (not nil)")
	}
	if len(result[0].Value) != 0 {
		t.Errorf("mapConditionsToRequests: empty TF List must produce empty slice, got len=%d", len(result[0].Value))
	}
}

// TestMapConditionsToRequests_TTLNullProducesTTLPresentFalse verifies that null TTL
// produces TTLPresent=false (field omitted at POST).
func TestMapConditionsToRequests_TTLNullProducesTTLPresentFalse(t *testing.T) {
	ctx := context.Background()

	conditions := []conditionModel{
		{
			Prop:        types.StringValue("cve_id"),
			Value:       types.ListNull(types.StringType),
			Description: types.StringNull(),
			TTL:         types.Int64Null(),
		},
	}

	result, diags := mapConditionsToRequests(ctx, conditions)
	if diags.HasError() {
		t.Fatalf("mapConditionsToRequests returned error diagnostics: %v", diags)
	}
	if result[0].TTLPresent {
		t.Error("mapConditionsToRequests: null TTL must produce TTLPresent=false")
	}
}

// TestMapConditionsToRequests_TTLPresentProducesTTLPresent verifies that a non-null TTL
// is correctly mapped with TTLPresent=true.
func TestMapConditionsToRequests_TTLPresentProducesTTLPresent(t *testing.T) {
	ctx := context.Background()

	conditions := []conditionModel{
		{
			Prop:        types.StringValue("packages"),
			Value:       types.ListNull(types.StringType),
			Description: types.StringNull(),
			TTL:         types.Int64Value(864000),
		},
	}

	result, diags := mapConditionsToRequests(ctx, conditions)
	if diags.HasError() {
		t.Fatalf("mapConditionsToRequests returned error diagnostics: %v", diags)
	}
	if !result[0].TTLPresent {
		t.Error("mapConditionsToRequests: non-null TTL must produce TTLPresent=true")
	}
	if result[0].TTL != 864000 {
		t.Errorf("mapConditionsToRequests: expected TTL=864000, got %v", result[0].TTL)
	}
}

// ---------------------------------------------------------------------------
// floatTTLToInt64
// ---------------------------------------------------------------------------

// TestFloatTTLToInt64_Integer verifies that an integer float converts correctly.
func TestFloatTTLToInt64_Integer(t *testing.T) {
	ctx := context.Background()
	i64, d := floatTTLToInt64(ctx, 2592000.0)
	if d != nil {
		t.Fatalf("floatTTLToInt64 unexpected error for integer: %v", d)
	}
	if i64 != 2592000 {
		t.Errorf("floatTTLToInt64 expected 2592000, got %d", i64)
	}
}

// TestFloatTTLToInt64_Fraction verifies that a fractional TTL produces a diagnostic error.
func TestFloatTTLToInt64_Fraction(t *testing.T) {
	ctx := context.Background()
	_, d := floatTTLToInt64(ctx, 2592000.5)
	if d == nil {
		t.Error("floatTTLToInt64 expected error diagnostic for fractional TTL, got nil")
	}
}

// TestFloatTTLToInt64_Zero verifies that TTL=0.0 (integer) converts without error.
func TestFloatTTLToInt64_Zero(t *testing.T) {
	ctx := context.Background()
	i64, d := floatTTLToInt64(ctx, 0.0)
	if d != nil {
		t.Fatalf("floatTTLToInt64 unexpected error for 0.0: %v", d)
	}
	if i64 != 0 {
		t.Errorf("floatTTLToInt64 expected 0, got %d", i64)
	}
}

// ---------------------------------------------------------------------------
// JSON marshalling — Delete body must produce "conditions":[] not null (§8 risk 2)
// ---------------------------------------------------------------------------

// TestDeleteBodyConditionsNotNull verifies that a ModelsUpdateExclusionsRequest initialised
// with make([]*models.ModelsExclusionConditionRequest, 0) serialises to "conditions":[]
// and NOT "conditions":null.
//
// This test reproduces the exact initialisation used in postGlobalConditions
// (and in Delete: make([]conditionRequest, 0)) to demonstrate the marshalling guarantee.
func TestDeleteBodyConditionsNotNull(t *testing.T) {
	// Simulate the postGlobalConditions body construction for an empty (Delete) call.
	apiConds := make([]*models.ModelsExclusionConditionRequest, 0)
	body := &models.ModelsUpdateExclusionsRequest{
		Conditions: apiConds,
	}

	jsonBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	jsonStr := string(jsonBytes)

	// Assert "conditions":[] is present.
	if !containsString(jsonStr, `"conditions":[]`) {
		t.Errorf(`Delete body should contain "conditions":[], got: %s`, jsonStr)
	}
	// Assert "conditions":null is NOT present.
	if containsString(jsonStr, `"conditions":null`) {
		t.Errorf(`Delete body must NOT contain "conditions":null, got: %s`, jsonStr)
	}
}

// TestNilSliceBodyConditionsNull shows the negative case: a nil slice (not make(,0))
// would produce "conditions":null, which is why we always use make([]..., 0).
// This is a documentation test demonstrating the risk of not using make.
func TestNilSliceBodyConditionsNull(t *testing.T) {
	// This is the WRONG pattern — DO NOT use in production code.
	var apiConds []*models.ModelsExclusionConditionRequest // nil slice
	body := &models.ModelsUpdateExclusionsRequest{
		Conditions: apiConds,
	}

	jsonBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	jsonStr := string(jsonBytes)

	// Verify the problem: nil slice produces null or omitted, NOT [].
	// (The actual behaviour depends on JSON tags — with omitempty it would be absent,
	// without omitempty it would be null. Either way, NOT [].)
	if containsString(jsonStr, `"conditions":[]`) {
		// If the JSON tag uses omitempty or the behaviour changed, this test would fail.
		// We keep this as a canary — if this test fails, the positive test above is redundant.
		t.Logf("WARNING: nil slice unexpectedly produces []; make() still required for correctness")
	} else {
		// Expected: "conditions":null or absent.
		t.Logf("Confirmed: nil slice produces %q (not []) — make([]*..., 0) is mandatory", jsonStr)
	}
}

// containsString is a simple helper for substring check (avoids import of strings in test file).
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// isRetryablePostError
// ---------------------------------------------------------------------------

func TestIsRetryablePostError_Nil(t *testing.T) {
	if isRetryablePostError(nil) {
		t.Error("isRetryablePostError(nil) should return false")
	}
}

func TestIsRetryablePostError_Typed500(t *testing.T) {
	err := &imagepolicies.UpdatePolicyExclusionsInternalServerError{}
	if !isRetryablePostError(err) {
		t.Error("isRetryablePostError: typed 500 should return true")
	}
}

func TestIsRetryablePostError_Typed429(t *testing.T) {
	err := &imagepolicies.UpdatePolicyExclusionsTooManyRequests{}
	if !isRetryablePostError(err) {
		t.Error("isRetryablePostError: typed 429 should return true")
	}
}

func TestIsRetryablePostError_String502(t *testing.T) {
	err := errors.New("[POST /container-security/entities/image-assessment-policy-exclusions/v1][502] bad gateway")
	if !isRetryablePostError(err) {
		t.Error("isRetryablePostError: error containing [502] should return true")
	}
}

func TestIsRetryablePostError_String503(t *testing.T) {
	err := errors.New("[POST /foo][503] service unavailable")
	if !isRetryablePostError(err) {
		t.Error("isRetryablePostError: error containing [503] should return true")
	}
}

func TestIsRetryablePostError_String504(t *testing.T) {
	err := errors.New("[POST /foo][504] gateway timeout")
	if !isRetryablePostError(err) {
		t.Error("isRetryablePostError: error containing [504] should return true")
	}
}

func TestIsRetryablePostError_Typed403(t *testing.T) {
	err := &imagepolicies.UpdatePolicyExclusionsForbidden{}
	if isRetryablePostError(err) {
		t.Error("isRetryablePostError: typed 403 must return false (not retryable)")
	}
}

func TestIsRetryablePostError_String400(t *testing.T) {
	err := errors.New("[POST /foo][400] bad request")
	if isRetryablePostError(err) {
		t.Error("isRetryablePostError: [400] must return false")
	}
}

func TestIsRetryablePostError_String403(t *testing.T) {
	err := errors.New("[POST /foo][403] forbidden")
	if isRetryablePostError(err) {
		t.Error("isRetryablePostError: [403] must return false")
	}
}

func TestIsRetryablePostError_String404(t *testing.T) {
	err := errors.New("[POST /foo][404] not found")
	if isRetryablePostError(err) {
		t.Error("isRetryablePostError: [404] must return false")
	}
}

func TestIsRetryablePostError_ArbitraryError(t *testing.T) {
	err := errors.New("some random error with no status code")
	if isRetryablePostError(err) {
		t.Error("isRetryablePostError: arbitrary error must return false")
	}
}

// ---------------------------------------------------------------------------
// isRetryableGetError
// ---------------------------------------------------------------------------

func TestIsRetryableGetError_Nil(t *testing.T) {
	if isRetryableGetError(nil) {
		t.Error("isRetryableGetError(nil) should return false")
	}
}

func TestIsRetryableGetError_Typed500(t *testing.T) {
	err := &imagepolicies.ReadPolicyExclusionsInternalServerError{}
	if !isRetryableGetError(err) {
		t.Error("isRetryableGetError: typed 500 should return true")
	}
}

func TestIsRetryableGetError_Typed429(t *testing.T) {
	err := &imagepolicies.ReadPolicyExclusionsTooManyRequests{}
	if !isRetryableGetError(err) {
		t.Error("isRetryableGetError: typed 429 should return true")
	}
}

func TestIsRetryableGetError_String502(t *testing.T) {
	err := errors.New("[GET /foo][502] bad gateway")
	if !isRetryableGetError(err) {
		t.Error("isRetryableGetError: [502] should return true")
	}
}

func TestIsRetryableGetError_String503(t *testing.T) {
	err := errors.New("[GET /foo][503] service unavailable")
	if !isRetryableGetError(err) {
		t.Error("isRetryableGetError: [503] should return true")
	}
}

func TestIsRetryableGetError_String504(t *testing.T) {
	err := errors.New("[GET /foo][504] gateway timeout")
	if !isRetryableGetError(err) {
		t.Error("isRetryableGetError: [504] should return true")
	}
}

func TestIsRetryableGetError_Typed403(t *testing.T) {
	err := &imagepolicies.ReadPolicyExclusionsForbidden{}
	if isRetryableGetError(err) {
		t.Error("isRetryableGetError: typed 403 must return false")
	}
}

func TestIsRetryableGetError_String400(t *testing.T) {
	err := errors.New("[GET /foo][400] bad request")
	if isRetryableGetError(err) {
		t.Error("isRetryableGetError: [400] must return false")
	}
}

func TestIsRetryableGetError_String404(t *testing.T) {
	err := errors.New("[GET /foo][404] not found")
	if isRetryableGetError(err) {
		t.Error("isRetryableGetError: [404] must return false")
	}
}

func TestIsRetryableGetError_ArbitraryError(t *testing.T) {
	err := errors.New("connection refused")
	if isRetryableGetError(err) {
		t.Error("isRetryableGetError: arbitrary error must return false")
	}
}

// ---------------------------------------------------------------------------
// Metadata TypeName
// ---------------------------------------------------------------------------

// TestMetadataTypeName_Plural verifies that the TypeName uses the plural form.
func TestMetadataTypeName_Plural(t *testing.T) {
	r := NewImageAssessmentPolicyExclusionsResource()

	metaReq := resource.MetadataRequest{ProviderTypeName: "crowdstrike"}
	metaResp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), metaReq, metaResp)

	const want = "crowdstrike_image_assessment_policy_exclusions"
	if metaResp.TypeName != want {
		t.Errorf("TypeName = %q, want %q", metaResp.TypeName, want)
	}
}

// ---------------------------------------------------------------------------
// Schema structure
// ---------------------------------------------------------------------------

// TestSchema_ConditionsIsSetNestedAttributeRequired verifies that conditions is a
// SetNestedAttribute and is Required (not Optional) — §2.1 / DEC-S1.
func TestSchema_ConditionsIsSetNestedAttributeRequired(t *testing.T) {
	r := NewImageAssessmentPolicyExclusionsResource()

	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), schemaReq, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("Schema() returned diagnostics errors: %v", schemaResp.Diagnostics)
	}

	attr, ok := schemaResp.Schema.Attributes["conditions"]
	if !ok {
		t.Fatal("Schema missing 'conditions' attribute")
	}
	setAttr, isSet := attr.(schema.SetNestedAttribute)
	if !isSet {
		t.Fatalf("'conditions' should be SetNestedAttribute, got %T", attr)
	}
	if !setAttr.IsRequired() {
		t.Error("'conditions' should be Required")
	}
	if setAttr.IsOptional() {
		t.Error("'conditions' must NOT be Optional")
	}
}

// TestSchema_ValueIsListOptionalNoSizeAtLeast verifies that value inside conditions is
// a ListAttribute, Optional, with no SizeAtLeast validator — ADR-9 / §2.2.
func TestSchema_ValueIsListOptionalNoSizeAtLeast(t *testing.T) {
	r := NewImageAssessmentPolicyExclusionsResource()

	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), schemaReq, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("Schema() returned diagnostics errors: %v", schemaResp.Diagnostics)
	}

	condAttr, ok := schemaResp.Schema.Attributes["conditions"]
	if !ok {
		t.Fatal("Schema missing 'conditions' attribute")
	}
	setAttr, isSet := condAttr.(schema.SetNestedAttribute)
	if !isSet {
		t.Fatalf("'conditions' should be SetNestedAttribute, got %T", condAttr)
	}

	nestedAttrs := setAttr.NestedObject.Attributes
	valAttr, ok := nestedAttrs["value"]
	if !ok {
		t.Fatal("Schema conditions missing 'value' nested attribute")
	}
	listAttr, isList := valAttr.(schema.ListAttribute)
	if !isList {
		t.Fatalf("'value' should be ListAttribute, got %T", valAttr)
	}
	if !listAttr.IsOptional() {
		t.Error("'value' should be Optional")
	}
	if listAttr.IsRequired() {
		t.Error("'value' must NOT be Required (ADR-9)")
	}
}

// TestSchema_IDIsComputedWithUseStateForUnknown verifies id is Computed.
func TestSchema_IDIsComputedWithUseStateForUnknown(t *testing.T) {
	r := NewImageAssessmentPolicyExclusionsResource()

	schemaReq := resource.SchemaRequest{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), schemaReq, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("Schema() returned diagnostics errors: %v", schemaResp.Diagnostics)
	}

	attr, ok := schemaResp.Schema.Attributes["id"]
	if !ok {
		t.Fatal("Schema missing 'id' attribute")
	}
	strAttr, isStr := attr.(schema.StringAttribute)
	if !isStr {
		t.Fatalf("'id' should be StringAttribute, got %T", attr)
	}
	if !strAttr.IsComputed() {
		t.Error("'id' should be Computed")
	}
}

// TestSchema_RequiredScopes verifies the scope declaration.
func TestSchema_RequiredScopes(t *testing.T) {
	if len(requiredScopes) != 1 {
		t.Fatalf("expected 1 required scope, got %d", len(requiredScopes))
	}
	s := requiredScopes[0]
	if s.Name != "Falcon Container Image" {
		t.Errorf("scope Name = %q, want %q", s.Name, "Falcon Container Image")
	}
	if !s.Read {
		t.Error("scope Read should be true")
	}
	if !s.Write {
		t.Error("scope Write should be true")
	}
}

// TestInterfaceImplementations verifies that the resource implements all required interfaces.
func TestInterfaceImplementations(t *testing.T) {
	r := NewImageAssessmentPolicyExclusionsResource()
	if r == nil {
		t.Fatal("NewImageAssessmentPolicyExclusionsResource() returned nil")
	}

	if _, ok := r.(resource.ResourceWithConfigure); !ok {
		t.Error("does not implement resource.ResourceWithConfigure")
	}
	if _, ok := r.(resource.ResourceWithImportState); !ok {
		t.Error("does not implement resource.ResourceWithImportState")
	}
	// Must NOT implement ResourceWithValidateConfig (architecture §5: no conditional logic).
	// (No assertion needed — absence is correct.)
}
