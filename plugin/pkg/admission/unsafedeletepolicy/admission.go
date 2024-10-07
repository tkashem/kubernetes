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
	"errors"
	"fmt"
	"io"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	genericadmissioninit "k8s.io/apiserver/pkg/admission/initializer"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	authorizationapi "k8s.io/kubernetes/pkg/apis/authorization"
	authorizationutil "k8s.io/kubernetes/pkg/registry/authorization/util"

	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

// PluginName is the name of the admission plugin
const PluginName = "AllowUnsafeMalformedObjectDeletion"

var (
	prefix           = strings.ToLower(PluginName) + ".admission.k8s.io/"
	auditDecisionKey = prefix + "decision"
	auditReasonKey   = prefix + "reason"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewUnsafeDeletePolicy(), nil
	})
}

// NewUnsafeDeletePolicy creates a new admission control handler that will admit
// an unsafe delete of a corrupt object if the user has the appropriate privilege
func NewUnsafeDeletePolicy() *UnsafeDeletePolicy {
	return &UnsafeDeletePolicy{
		Handler: admission.NewHandler(admission.Delete),
	}
}

type UnsafeDeletePolicy struct {
	*admission.Handler
	authz authorizer.Authorizer
}

var _ admission.ValidationInterface = &UnsafeDeletePolicy{}
var _ admission.InitializationValidator = &UnsafeDeletePolicy{}
var _ genericadmissioninit.WantsAuthorizer = &UnsafeDeletePolicy{}

// SetAuthorizer sets the authorizer.
func (p *UnsafeDeletePolicy) SetAuthorizer(authz authorizer.Authorizer) {
	p.authz = authz
}

// ValidateInitialization ensures an authorizer is set.
func (p *UnsafeDeletePolicy) ValidateInitialization() error {
	if p.authz == nil {
		return fmt.Errorf("%s requires an authorizer", PluginName)
	}
	return nil
}

// Validate ensures that the user has permission to do 'delete-ignore-read-errors'
// on the resource being deeted when ignoreStoreReadErrorWithClusterBreakingPotential
// is enabled, these are the constraints:
// a) must be a DELETE operation
// b) ignoreStoreReadErrorWithClusterBreakingPotential is set to true
// c) the request is a resource, no sub-resource or non-resource endpoint
// d) the user has permission to do 'delete-ignore-read-errors' on the resource
func (p *UnsafeDeletePolicy) Validate(ctx context.Context, attr admission.Attributes, o admission.ObjectInterfaces) (err error) {
	// if the feature is disabled, this plugin, although enabled should not
	// be active, and requests with the delete option
	// 'ignoreStoreReadErrorWithClusterBreakingPotential' enabled will
	// fallback to using the normal deletion flow
	if !utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AllowUnsafeMalformedObjectDeletion) {
		return nil
	}
	if attr.GetOperation() != admission.Delete || attr.GetOperationOptions() == nil {
		return nil
	}

	options, ok := attr.GetOperationOptions().(*metav1.DeleteOptions)
	if !ok {
		return fmt.Errorf("expected an option of type: %T, but got: %T", &metav1.DeleteOptions{}, attr.GetOperationOptions())
	}
	if !ptr.Deref(options.IgnoreStoreReadErrorWithClusterBreakingPotential, false) {
		return nil
	}

	requestInfo, found := request.RequestInfoFrom(ctx)
	if !found {
		return admission.NewForbidden(attr, errors.New("no RequestInfo found in the context"))
	}
	if !requestInfo.IsResourceRequest || len(attr.GetSubresource()) > 0 {
		return admission.NewForbidden(attr, errors.New("ignoreStoreReadErrorWithClusterBreakingPotential delete option is not allowed on a subresource or non-resource request"))
	}

	// if we are here, IgnoreStoreReadErrorWithClusterBreakingPotential
	// is set to true in the delete options, the user must have permission
	// to do 'unsafe-delete-ignore-read-errors' on the given resource.
	record := authorizationutil.ResourceAttributesFrom(attr.GetUserInfo(), authorizationapi.ResourceAttributes{
		Namespace: attr.GetNamespace(),
		Verb:      "unsafe-delete-ignore-read-errors",
		Group:     attr.GetResource().Group,
		Version:   attr.GetResource().Version,
		Resource:  attr.GetResource().Resource,
		Name:      attr.GetName(),
		FieldSelector: &authorizationapi.FieldSelectorAttributes{
			RawSelector: requestInfo.FieldSelector,
		},
		LabelSelector: &authorizationapi.LabelSelectorAttributes{
			RawSelector: requestInfo.LabelSelector,
		},
	})
	decision, reason, err := p.authz.Authorize(ctx, record)
	if err != nil {
		if annotationErr := attr.AddAnnotation(auditReasonKey, "internal error"); annotationErr != nil {
			err = fmt.Errorf("authoriztion err: %w, failed to add annotation: %s", err, annotationErr.Error())
		}
		err = fmt.Errorf("error while checking permission for %q, %w", record.Verb, err)
		klog.FromContext(ctx).V(1).Error(err, "failed to authorize")
		return admission.NewForbidden(attr, err)
	}

	if err := attr.AddAnnotation(auditDecisionKey, decisionToString(decision)); err != nil {
		return fmt.Errorf("failed to add annotation: key: %q, reason: %q", auditDecisionKey, decisionToString(decision))
	}
	if err := attr.AddAnnotation(auditReasonKey, reason); err != nil {
		return fmt.Errorf("failed to add annotation: key: %q, reason: %q", auditReasonKey, reason)
	}

	if decision == authorizer.DecisionAllow {
		return nil
	}

	return admission.NewForbidden(attr, fmt.Errorf("not permitted to do %q, reason: %s", record.Verb, reason))
}

func decisionToString(decision authorizer.Decision) string {
	if decision == authorizer.DecisionAllow {
		return "allow"
	}
	return "deny"
}
