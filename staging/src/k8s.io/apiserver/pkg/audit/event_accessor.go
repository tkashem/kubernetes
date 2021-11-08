/*
Copyright 2021 The Kubernetes Authors.

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
	"sync"

	auditinternal "k8s.io/apiserver/pkg/apis/audit"
)

// EventAccessor provides access to the underlying audit event object
// that is written to the audit log.
// The annotations of an audit event are read from or written to concurrently
// for a request, this interface provides a mechansim to manipulate the annotations
// in a thread safe manner.
// NOTE: Other fields on the audit event object are not accessed concurrently yet
type EventAccessor interface {
	// AddAnnotation adds the given key, value pair as an annotation to the underlying
	// audit event object.
	// This should be done in the thread safe manner
	AddAnnotation(key, value string)

	// CopyAnnotations copies the annotations associated with the audit event.
	// This should be a thread safe function
	CopyAnnotations() map[string]string

	// SetAuditEvent sets the given event in ev as the audit event object that will
	// be written to audit log.
	// This should be called only when we have been determined that the request
	// is being audited.
	SetAuditEvent(ev *auditinternal.Event)

	// GetAuditEvent returns the underlying audit event obeject.
	// It should never be used to read or write to the annotations directly.
	// It should only be used to to manipukate other attributes (except annotations field)
	GetAuditEvent() *auditinternal.Event
}

// annotations = []*annotation instead of a map to preserve order of insertions
type Annotation struct {
	Key, Value string
}

type eventAccessor struct {
	lock sync.Mutex
	// []{key, value} that is merged with the audit.Event.Annotations map.
	// This allows layers that run before WithAudit (such as authentication)
	// to insert annotations for a request.
	annotations []*Annotation
	// Event is the audit Event object that is being captured to be written in
	// the API audit log. It is set to nil when the request is not being audited.
	*auditinternal.Event
}

func (a *eventAccessor) AddAnnotation(key, value string) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.Event != nil {
		logAnnotation(a.Event, key, value)
		return
	}

	a.annotations = append(a.annotations, &Annotation{Key: key, Value: value})
}

func (a *eventAccessor) GetAuditEvent() *auditinternal.Event {
	return a.Event
}

func (a *eventAccessor) ProcessEvent(f func(ae *auditinternal.Event)) {
	a.lock.Lock()
	defer a.lock.Unlock()

	f(a.Event)
}

func (a *eventAccessor) SetAuditEvent(ev *auditinternal.Event) {
	if ev == nil {
		return
	}
	if a.Event != nil {
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	a.Event = ev
	for _, annotation := range a.annotations {
		logAnnotation(a.Event, annotation.Key, annotation.Value)
	}
}

func (a *eventAccessor) CopyAnnotations() map[string]string {
	a.lock.Lock()
	defer a.lock.Unlock()

	var annotations map[string]string
	switch {
	case a.Event == nil:
		if len(a.annotations) == 0 {
			return nil
		}
		annotations = map[string]string{}
		for _, annotation := range a.annotations {
			annotations[annotation.Key] = annotation.Value
		}

	case len(a.Event.Annotations) > 0:
		annotations = map[string]string{}
		for k,v := range a.Event.Annotations {
			annotations[k] = v
		}

	}

	return annotations
}

//type annotationAccessor struct {
//	lock sync.Mutex
//	// []{key, value} that is merged with the audit.Event.Annotations map.
//	// This allows layers that run before WithAudit (such as authentication)
//	// to insert annotations for a request.
//	annotations []*annotation
//}
//
//func (a *annotationAccessor) AddAnnotation(key, value string) {
//	a.lock.Lock()
//	defer a.lock.Unlock()
//
//	a.annotations = append(a.annotations, &annotation{key: key, value: value})
//}
//
//func (a *annotationAccessor) GetAuditEvent() *auditinternal.Event {
//	return nil
//}
