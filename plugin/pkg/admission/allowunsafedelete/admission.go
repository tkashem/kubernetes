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

package allowunsafedelete

import (
	"context"
	"errors"
	"fmt"
	"io"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	genericadmissioninit "k8s.io/apiserver/pkg/admission/initializer"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"

	"k8s.io/klog/v2"
)

// PluginName indicates name of admission plugin.
const PluginName = "AllowUnsafeMalformedObjectDeletion"

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewAllowUnsafeDelete(), nil
	})
}

// NewAllowUnsafeDelete creates a new admission control handler that will admit
// an unsafe delete of a corrupt object if the user has the appropriate privilege
func NewAllowUnsafeDelete() *AllowUnsafeDelete {
	return &AllowUnsafeDelete{
		Handler: admission.NewHandler(admission.Delete),
	}
}

type AllowUnsafeDelete struct {
	*admission.Handler
	authz authorizer.Authorizer
}

var _ admission.ValidationInterface = &AllowUnsafeDelete{}
var _ admission.InitializationValidator = &AllowUnsafeDelete{}
var _ genericadmissioninit.WantsAuthorizer = &AllowUnsafeDelete{}

// SetAuthorizer sets the authorizer.
func (p *AllowUnsafeDelete) SetAuthorizer(authz authorizer.Authorizer) {
	p.authz = authz
}

// ValidateInitialization ensures an authorizer is set.
func (p *AllowUnsafeDelete) ValidateInitialization() error {
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
func (p *AllowUnsafeDelete) Validate(ctx context.Context, attr admission.Attributes, o admission.ObjectInterfaces) (err error) {
	// if the feature is disabled, this plugin, although
	// enabled, should not be active
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
	if ignore := options.IgnoreStoreReadErrorWithClusterBreakingPotential; ignore == nil || !*ignore {
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
	// to do 'delete-ignore-read-errors' on the given resource.
	const verb = "delete-ignore-read-errors"
	record := authorizer.AttributesRecord{
		User:            attr.GetUserInfo(),
		Verb:            verb,
		Namespace:       attr.GetNamespace(),
		Name:            attr.GetName(),
		APIGroup:        attr.GetResource().Group,
		APIVersion:      attr.GetResource().Version,
		Resource:        attr.GetResource().Resource,
		ResourceRequest: true,
	}

	decision, reason, err := p.authz.Authorize(ctx, record)
	if err != nil {
		err = fmt.Errorf("error while checking permission for %q, %w", verb, err)
		klog.V(1).ErrorS(err, "failed to authorize")
		return admission.NewForbidden(attr, err)
	}
	if decision == authorizer.DecisionAllow {
		// TODO: no distinguishable attribute in the audit entry to
		// discern whether it was a normal deletion flow or unsafe,
		// add an annotation to audit to make that distinction?
		return nil
	}

	return admission.NewForbidden(attr, fmt.Errorf("user not permitted to do %q, reason: %s", verb, reason))
}
