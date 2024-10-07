/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package unsafedeletepolicy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"k8s.io/utils/ptr"
)

func TestValidate(t *testing.T) {
	var (
		verb                 = "unsafe-delete-ignore-read-errors"
		auditDecisionKeyWant = strings.ToLower(PluginName) + ".admission.k8s.io/" + "decision"
		auditReasonKeyWant   = strings.ToLower(PluginName) + ".admission.k8s.io/" + "reason"
	)

	tests := []struct {
		name           string
		featureEnabled bool
		reqInfo        *request.RequestInfo
		attr           admission.Attributes
		authz          authorizer.Authorizer
		err            func(admission.Attributes) error
		annotations    map[string]string
	}{
		{
			name:           "feature enabled, operation is not delete, admit",
			featureEnabled: true,
			attr:           newAttributes(attributes{operation: admission.Update}),
			authz:          nil, // Authorize should not be invoked
		},
		{
			name:           "feature enabled, delete, operation option is nil, admit",
			featureEnabled: true,
			attr: newAttributes(attributes{
				operation:        admission.Delete,
				operationOptions: nil,
			}),
			authz: nil, // Authorize should not be invoked
		},
		{
			name:           "feature enabled, delete, operation option is not a match, forbid",
			featureEnabled: true,
			attr: newAttributes(attributes{
				operation:        admission.Delete,
				operationOptions: &metav1.PatchOptions{},
			}),
			authz: nil, // Authorize should not be invoked
			err: func(admission.Attributes) error {
				return fmt.Errorf("expected an option of type: %T, but got: %T", &metav1.DeleteOptions{}, &metav1.PatchOptions{})
			},
		},
		{
			name:           "feature enabled, delete, IgnoreStoreReadErrorWithClusterBreakingPotential is nil, admit",
			featureEnabled: true,
			attr: newAttributes(attributes{
				operation: admission.Delete,
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: nil,
				},
			}),
			authz: nil, // Authorize should not be invoked
		},
		{
			name:           "feature enabled, delete, IgnoreStoreReadErrorWithClusterBreakingPotential is false, admit",
			featureEnabled: true,
			attr: newAttributes(attributes{
				operation: admission.Delete,
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: ptr.To[bool](false),
				},
			}),
			authz: nil, // Authorize should not be invoked
		},
		{
			name:           "feature enabled, delete, IgnoreStoreReadErrorWithClusterBreakingPotential is true, no RequestInfo in request context, forbid",
			featureEnabled: true,
			reqInfo:        nil,
			attr: newAttributes(attributes{
				operation: admission.Delete,
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: ptr.To[bool](true),
				},
			}),
			authz: nil,
			err: func(attr admission.Attributes) error {
				return admission.NewForbidden(attr, fmt.Errorf("no RequestInfo found in the context"))
			},
		},
		{
			name:           "feature enabled, delete, IgnoreStoreReadErrorWithClusterBreakingPotential is true, subresource request, forbid",
			featureEnabled: true,
			reqInfo:        &request.RequestInfo{IsResourceRequest: true},
			attr: newAttributes(attributes{
				operation:   admission.Delete,
				subresource: "foo",
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: ptr.To[bool](true),
				},
			}),
			authz: nil,
			err: func(attr admission.Attributes) error {
				return admission.NewForbidden(attr, fmt.Errorf("ignoreStoreReadErrorWithClusterBreakingPotential delete option is not allowed on a subresource or non-resource request"))
			},
		},
		{
			name:           "feature enabled, delete, IgnoreStoreReadErrorWithClusterBreakingPotential is true, subresource request, forbid",
			featureEnabled: true,
			reqInfo:        &request.RequestInfo{IsResourceRequest: false},
			attr: newAttributes(attributes{
				operation:   admission.Delete,
				subresource: "",
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: ptr.To[bool](true),
				},
			}),
			authz: nil,
			err: func(attr admission.Attributes) error {
				return admission.NewForbidden(attr, fmt.Errorf("ignoreStoreReadErrorWithClusterBreakingPotential delete option is not allowed on a subresource or non-resource request"))
			},
		},
		{
			name:           "feature enabled, delete, IgnoreStoreReadErrorWithClusterBreakingPotential is true, authorizer returns error, forbid",
			featureEnabled: true,
			reqInfo:        &request.RequestInfo{IsResourceRequest: true},
			attr: newAttributes(attributes{
				subresource: "",
				operation:   admission.Delete,
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: ptr.To[bool](true),
				},
			}),
			authz: &fakeAuthorizer{err: fmt.Errorf("unexpected error")},
			err: func(attr admission.Attributes) error {
				return admission.NewForbidden(attr, fmt.Errorf("error while checking permission for %q, %w", verb, fmt.Errorf("unexpected error")))
			},
			annotations: map[string]string{
				auditReasonKeyWant: "internal error",
			},
		},
		{
			name:           "feature enabled, delete, IgnoreStoreReadErrorWithClusterBreakingPotential is true, user does not have permission, forbid",
			featureEnabled: true,
			reqInfo:        &request.RequestInfo{IsResourceRequest: true},
			attr: newAttributes(attributes{
				operation:   admission.Delete,
				subresource: "",
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: ptr.To[bool](true),
				},
			}),
			authz: &fakeAuthorizer{
				decision: authorizer.DecisionDeny,
				reason:   "does not have permission",
			},
			err: func(attr admission.Attributes) error {
				return admission.NewForbidden(attr, fmt.Errorf("not permitted to do %q, reason: %s", verb, "does not have permission"))
			},
			annotations: map[string]string{
				auditDecisionKeyWant: "deny",
				auditReasonKeyWant:   "does not have permission",
			},
		},
		{
			name:           "feature enabled, delete, IgnoreStoreReadErrorWithClusterBreakingPotential is true, authorizer gives no opinion, forbid",
			featureEnabled: true,
			reqInfo:        &request.RequestInfo{IsResourceRequest: true},
			attr: newAttributes(attributes{
				operation:   admission.Delete,
				subresource: "",
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: ptr.To[bool](true),
				},
			}),
			authz: &fakeAuthorizer{
				decision: authorizer.DecisionNoOpinion,
				reason:   "no opinion",
			},
			err: func(attr admission.Attributes) error {
				return admission.NewForbidden(attr, fmt.Errorf("not permitted to do %q, reason: %s", verb, "no opinion"))
			},
			annotations: map[string]string{
				auditDecisionKeyWant: "deny",
				auditReasonKeyWant:   "no opinion",
			},
		},
		{
			name:           "feature enabled, delete, IgnoreStoreReadErrorWithClusterBreakingPotential is true, user has permission, admit",
			featureEnabled: true,
			reqInfo:        &request.RequestInfo{IsResourceRequest: true},
			attr: newAttributes(attributes{
				operation:   admission.Delete,
				subresource: "",
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: ptr.To[bool](true),
				},
				userInfo: &user.DefaultInfo{Name: "foo"},
			}),
			authz: &fakeAuthorizer{
				decision: authorizer.DecisionAllow,
				reason:   "permitted",
			},
			annotations: map[string]string{
				auditDecisionKeyWant: "allow",
				auditReasonKeyWant:   "permitted",
			},
		},
		{
			name:           "feature disabled, always admit",
			featureEnabled: false,
			reqInfo:        &request.RequestInfo{IsResourceRequest: true},
			attr: newAttributes(attributes{
				operation:   admission.Delete,
				subresource: "",
				operationOptions: &metav1.DeleteOptions{
					IgnoreStoreReadErrorWithClusterBreakingPotential: ptr.To[bool](true),
				},
				userInfo: &user.DefaultInfo{Name: "foo"},
			}),
			authz: &fakeAuthorizer{
				err: fmt.Errorf("Authorize should not be invoked when feature is disabled"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.AllowUnsafeMalformedObjectDeletion, test.featureEnabled)

			validator := NewUnsafeDeletePolicy()
			validator.SetAuthorizer(test.authz)

			var want error
			if test.err != nil {
				want = test.err(test.attr)
			}

			ctx := context.Background()
			if test.reqInfo != nil {
				ctx = request.WithRequestInfo(ctx, test.reqInfo)
			}

			// wrap the attributes so we can access the annotations set during admission
			attrs := &fakeAttributes{Attributes: test.attr}
			got := validator.Validate(ctx, attrs, nil)
			switch {
			case want != nil:
				if got == nil || want.Error() != got.Error() {
					t.Errorf("expected error: %v, but got: %v", want, got)
				}
			default:
				if got != nil {
					t.Errorf("expected no error, but got: %v", got)
				}
			}
			if want, got := test.annotations, attrs.annotations; !cmp.Equal(want, got) {
				t.Errorf("expected the annotations to match, diff: %s", cmp.Diff(want, got))
			}
		})
	}
}

// attributes of interest for this test
type attributes struct {
	operation        admission.Operation
	operationOptions runtime.Object
	userInfo         user.Info
	subresource      string
}

func newAttributes(attr attributes) admission.Attributes {
	return admission.NewAttributesRecord(
		nil,                           // this plugin should never inspect the object
		nil,                           // old object, this plugin should never inspect it
		schema.GroupVersionKind{},     // this plugin should never inspect kind
		"",                            // namespace, leave it empty, this plugin only passes it along to the authorizer
		"",                            // name, leave it empty, this plugin only passes it along to the authorizer
		schema.GroupVersionResource{}, // resource, leave it empty, this plugin only passes it along to the authorizer
		attr.subresource,
		attr.operation,
		attr.operationOptions,
		false, // dryRun, this plugin should never inspect this attribute
		attr.userInfo)
}

type fakeAttributes struct {
	admission.Attributes
	annotations map[string]string
}

func (f *fakeAttributes) AddAnnotation(key, value string) error {
	if err := f.Attributes.AddAnnotation(key, value); err != nil {
		return err
	}

	if len(f.annotations) == 0 {
		f.annotations = map[string]string{}
	}
	f.annotations[key] = value
	return nil
}

type fakeAuthorizer struct {
	decision authorizer.Decision
	reason   string
	err      error
}

func (authorizer fakeAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	return authorizer.decision, authorizer.reason, authorizer.err
}
