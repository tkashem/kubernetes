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
	"github.com/google/go-cmp/cmp"
	"testing"

	auditinternal "k8s.io/apiserver/pkg/apis/audit"
)

func TestAnnotations(t *testing.T) {
	tests := []struct{
		name string
		accessor func() EventAccessor
		event *auditinternal.Event
		before, after map[string]string
		expected map[string]string
	} {
		{
			name: "request is being audited, annotations are added before and after",
			accessor: func() EventAccessor {
				return &eventAccessor{}
			},
			before: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			event: &auditinternal.Event{
				Level: auditinternal.LevelMetadata,
			},
			after: map[string]string{
				"key3": "value3",
				"key4": "value4",
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
				"key4": "value4",
			},
		},
		{
			name: "request is not being audited, annotations are added before and after",
			accessor: func() EventAccessor {
				return &eventAccessor{}
			},
			before: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			event: &auditinternal.Event{
				Level: auditinternal.LevelNone,
			},
			after: map[string]string{
				"key3": "value3",
				"key4": "value4",
			},
			expected: nil,
		},
		{
			name: "event is nil",
			accessor: func() EventAccessor {
				return &eventAccessor{}
			},
			before: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			event: nil,
			after: map[string]string{
				"key3": "value3",
				"key4": "value4",
			},
			expected: nil,
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accessor := test.accessor()

			// annotations are added before we know whether this request is being audited
			for k, v := range test.before {
				accessor.AddAnnotation(k, v)
			}

			// if this request is audited, then add the audit event
			accessor.SetAuditEvent(test.event)

			// annotations are added after we know whether this request is being audited
			for k, v := range test.after {
				accessor.AddAnnotation(k, v)
			}

			var annotationsGot map[string]string
			if accessor.GetAuditEvent() != nil {
				annotationsGot = accessor.GetAuditEvent().Annotations
			}

			if !cmp.Equal(test.expected, annotationsGot) {
				t.Errorf("Expected the annotations to match: %s", cmp.Diff(test.expected, annotationsGot))
			}
		})
	}
}