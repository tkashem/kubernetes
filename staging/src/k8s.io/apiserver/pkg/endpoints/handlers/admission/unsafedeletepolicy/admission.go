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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"

	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

const (
	auditDecisionKey = "allowunsafemalformedobjectdeletion.admission.k8s.io/decision"
	auditReasonKey   = "allowunsafemalformedobjectdeletion.admission.k8s.io/reason"
)

// New creates a new admission handler that will admit an unsafe delete
// of a corrupt object if the user has the appropriate privilege
func New(authz authorizer.Authorizer) *unsafeDeletePolicy {
	return &unsafeDeletePolicy{
		Handler: admission.NewHandler(admission.Delete),
		authz:   authz,
	}
}

type unsafeDeletePolicy struct {
	*admission.Handler
	authz authorizer.Authorizer
}

var _ admission.ValidationInterface = &unsafeDeletePolicy{}

// Validate ensures that the user has permission to do 'unsafe-delete-ignore-read-errors'
// on the resource being deeted when ignoreStoreReadErrorWithClusterBreakingPotential
// is enabled, these are the constraints:
// a) must be a DELETE operation
// b) ignoreStoreReadErrorWithClusterBreakingPotential is set to true
// c) the request is a resource, no sub-resource or non-resource endpoint
// d) the user has permission to do 'unsafe-delete-ignore-read-errors' on the resource
func (p *unsafeDeletePolicy) Validate(ctx context.Context, attr admission.Attributes, _ admission.ObjectInterfaces) (err error) {
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
	record := authorizer.AttributesRecord{
		User:            attr.GetUserInfo(),
		Verb:            "unsafe-delete-ignore-read-errors",
		Namespace:       attr.GetNamespace(),
		Name:            attr.GetName(),
		APIGroup:        attr.GetResource().Group,
		APIVersion:      attr.GetResource().Version,
		Resource:        attr.GetResource().Resource,
		ResourceRequest: true,
	}
	// TODO: can't use ResourceAttributesFrom from k8s.io/kubernetes/pkg/registry/authorization/util
	// due to prevent staging --> k8s.io/kubernetes dep issue
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AuthorizeWithSelectors) {
		if len(requestInfo.FieldSelector) > 0 {
			fieldSelector, err := fields.ParseSelector(requestInfo.FieldSelector)
			if err != nil {
				record.FieldSelectorRequirements, record.FieldSelectorParsingErr = nil, err
			} else {
				if requirements := fieldSelector.Requirements(); len(requirements) > 0 {
					record.FieldSelectorRequirements, record.FieldSelectorParsingErr = fieldSelector.Requirements(), nil
				}
			}
		}
		if len(requestInfo.LabelSelector) > 0 {
			labelSelector, err := labels.Parse(requestInfo.LabelSelector)
			if err != nil {
				record.LabelSelectorRequirements, record.LabelSelectorParsingErr = nil, err
			} else {
				if requirements, _ /*selectable*/ := labelSelector.Requirements(); len(requirements) > 0 {
					record.LabelSelectorRequirements, record.LabelSelectorParsingErr = requirements, nil
				}
			}
		}
	}

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
