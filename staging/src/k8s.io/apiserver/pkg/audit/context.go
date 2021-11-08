/*
Copyright 2020 The Kubernetes Authors.

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

package audit

import (
	"context"
	"errors"

	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// The key type is unexported to prevent collisions
type key int

const (
	// auditKey is the context key for storing the audit event that is being
	// captured and the evaluated policy that applies to the given request.
	auditKey = iota
)

var (
	NoAuditInContextErr = errors.New("no audit object found in context, handler chain must be wrong")
)

// AuditContext is a pair of the audit configuration object that applies to
// a given request and the audit Event object that is being captured.
// It's a convenient placeholder to store both these objects in the request context.
type AuditContext struct {
	// RequestAuditConfig is the audit configuration that applies to the request
	RequestAuditConfig RequestAuditConfig

	// This allows layers that run before WithAudit (such as authentication)
	// to insert annotations for a request.
	accessor EventAccessor
}

// WithAuditInitialized initializes the request context with an
// AuditContext instance during audit initialization.
func WithAuditInitialized(parent context.Context) context.Context {
	// this should never really happen, but prevent double registration
	if _, ok := parent.Value(auditKey).(*AuditContext); ok {
		return parent
	}

	// we don't know whether the request is being audited yet, so we need to provide
	// a mechanism to store the audit annotations that will be written.
	ac := &AuditContext{
		accessor: &eventAccessor{},
	}

	return genericapirequest.WithValue(parent, auditKey, ac)
}

// SetAuditEventAndConfig makes two following associations:
// - the audit configuration object applicable to this request is attached
//   to the request context
// - the associated audit Event object that will be written to the audit log
//   is attached to the request context.
//
// This function also ensures that the temporary annotations added so far
// are moved to the audit Event object.
//
// ev should not be nil, this function should be called when a request is
// being audited and with a non-nil audit Event object.
func SetAuditEventAndConfig(ctx context.Context, ev *auditinternal.Event, config RequestAuditConfig) error {
	auditCtx := AuditContextFrom(ctx)
	if auditCtx == nil || auditCtx.accessor == nil {
		return NoAuditInContextErr
	}

	auditCtx.RequestAuditConfig = config
	auditCtx.accessor.SetAuditEvent(ev)
	return nil
}

// AddAuditAnnotation sets the audit annotation for the given key, value pair.
// It is safe to call at most parts of request flow that come after WithAuditAnnotations.
// The notable exception being that this function must not be called via a
// defer statement (i.e. after ServeHTTP) in a handler that runs before WithAudit
// as at that point the audit event has already been sent to the audit sink.
// Handlers that are unaware of their position in the overall request flow should
// prefer AddAuditAnnotation over LogAnnotation to avoid dropping annotations.
func AddAuditAnnotation(ctx context.Context, key, value string) {
	// use the audit event directly if we have it
	if ac := AuditContextFrom(ctx); ac != nil {
		ac.accessor.AddAnnotation(key, value)
	}
}

func CopyAnnotations(ctx context.Context) map[string]string {
	if ac := AuditContextFrom(ctx); ac != nil {
		return ac.accessor.CopyAnnotations()
	}
	return nil
}

// AuditEventFrom returns the audit event struct on the ctx
func AuditEventFrom(ctx context.Context) *auditinternal.Event {
	if ac := AuditContextFrom(ctx); ac != nil {
		return ac.accessor.GetAuditEvent()
	}
	return nil
}

// AuditContextFrom returns the pair of the audit configuration object
// that applies to the given request and the audit event that is going to
// be written to the API audit log.
func AuditContextFrom(ctx context.Context) *AuditContext {
	ev, _ := ctx.Value(auditKey).(*AuditContext)
	return ev
}
