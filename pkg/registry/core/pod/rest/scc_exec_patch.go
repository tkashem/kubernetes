package rest

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	coreapis "k8s.io/kubernetes/pkg/apis/core"

	"k8s.io/kubernetes/openshift-kube-apiserver/enablement"
)

func ValidateUsingSCCExecPlugin(ctx context.Context, name string, options runtime.Object, subresource string) error {
	if !enablement.IsOpenShift() {
		return nil
	}

	attrs, err := newSCCExecAdmissionAttributes(ctx, name, options, subresource)
	if err != nil {
		return fmt.Errorf("failed to create admission attributes for SCC pods/exec : %#v", options)
	}
	// NOTE: SCC Exec plugin does NOT utilize the ObjectInterfaces passed,
	// so passing it as nil.
	return getSCCExecValidator().Validate(ctx, attrs, nil)
}

// newSCCExecAdmissionAttributes returns an admission.Attributes that is
// appropriately initialized for SCC Exec admission plugin
// It is intended to be used by AttachREST, and ExecREST.
func newSCCExecAdmissionAttributes(ctx context.Context, name string, options runtime.Object, subresource string) (admission.Attributes, error) {
	requestInfo, ok := apirequest.RequestInfoFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve request info from request context")
	}
	userInfo, ok := apirequest.UserFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve user info from request context")
	}

	// create admission.Attributes applicable to SCC Exec Validate method
	attr := admission.NewAttributesRecord(nil, nil,
		coreapis.Kind("Pod").WithVersion(""),
		requestInfo.Namespace,
		name,
		coreapis.Resource("pods").WithVersion(""),
		subresource,
		admission.Connect,
		options,
		// Neither PodExecOptions, nor PodAttachOptions have a field for
		// dry mode, so dry mode is always disabled for this operation.
		false,
		userInfo)
	return attr, nil
}

// getSCCExecValidator returns the SCC Exec admission plugin instance
// that is located in the OpenShift enablement package.
// Note: we make two assumptions here, which should hold true:
//   - the SCC Exec plugin instance has been initialized before the apiserver
//     starts receiving incoming requests.
//   - the SCC Exec plugin instance is thread safe so it can be used
//     concurrently by in flight requests
//
// It is intended to be used by AttachREST, and ExecREST.
func getSCCExecValidator() admission.ValidationInterface {
	return enablement.SCCExecAdmissionValidator
}
