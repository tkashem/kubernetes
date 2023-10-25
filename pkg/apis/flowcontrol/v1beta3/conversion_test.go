/*
Copyright 2023 The Kubernetes Authors.

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

package v1beta3

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"k8s.io/api/flowcontrol/v1beta3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/apis/flowcontrol"
	"k8s.io/utils/ptr"
)

func TestConvert_v1beta3_PriorityLevelConfiguration_To_flowcontrol_PriorityLevelConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		in       *v1beta3.PriorityLevelConfiguration
		expected *flowcontrol.PriorityLevelConfiguration
	}{
		{
			name: "v1beta3 object has the roundtrip annotation, and NominalConcurrencyShares is zero; the roundtrip annotation should be removed from the internal object",
			in: &v1beta3.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
						v1beta3.PriorityLevelConcurrencyShareDefaultKey: "",
					},
				},
				Spec: v1beta3.PriorityLevelConfigurationSpec{
					Type: v1beta3.PriorityLevelEnablementLimited,
					Limited: &v1beta3.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: 0,
						LimitResponse: v1beta3.LimitResponse{
							Type: v1beta3.LimitResponseTypeReject,
						},
					},
				},
			},
			expected: &flowcontrol.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
				Spec: flowcontrol.PriorityLevelConfigurationSpec{
					Type: flowcontrol.PriorityLevelEnablementLimited,
					Limited: &flowcontrol.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: ptr.To(int32(0)),
						LimitResponse: flowcontrol.LimitResponse{
							Type: flowcontrol.LimitResponseTypeReject,
						},
					},
				},
			},
		},
		{
			name: "the roundtrip annotation should be removed from the internal object unconditonally",
			in: &v1beta3.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
						v1beta3.PriorityLevelConcurrencyShareDefaultKey: "",
					},
				},
				Spec: v1beta3.PriorityLevelConfigurationSpec{
					Type: v1beta3.PriorityLevelEnablementLimited,
				},
			},
			expected: &flowcontrol.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
				Spec: flowcontrol.PriorityLevelConfigurationSpec{
					Type: flowcontrol.PriorityLevelEnablementLimited,
				},
			},
		},
		{
			name: "v1beta3 object does not have the roundtrip annotation, and NominalConcurrencyShares is zero; the roundtripannotation should not be added to the internal object",
			in: &v1beta3.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
				Spec: v1beta3.PriorityLevelConfigurationSpec{
					Type: v1beta3.PriorityLevelEnablementLimited,
					Limited: &v1beta3.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: 0,
						LimitResponse: v1beta3.LimitResponse{
							Type: v1beta3.LimitResponseTypeReject,
						},
					},
				},
			},
			expected: &flowcontrol.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
				Spec: flowcontrol.PriorityLevelConfigurationSpec{
					Type: flowcontrol.PriorityLevelEnablementLimited,
					Limited: &flowcontrol.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: ptr.To(int32(0)),
						LimitResponse: flowcontrol.LimitResponse{
							Type: flowcontrol.LimitResponseTypeReject,
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := test.in.DeepCopy()

			out := &flowcontrol.PriorityLevelConfiguration{}
			if err := Convert_v1beta3_PriorityLevelConfiguration_To_flowcontrol_PriorityLevelConfiguration(test.in, out, nil); err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			}
			if !cmp.Equal(test.expected, out) {
				t.Errorf("Expected a match, diff: %s", cmp.Diff(test.expected, out))
			}
			if want, got := copy.ObjectMeta.Annotations, test.in.ObjectMeta.Annotations; !cmp.Equal(want, got) {
				t.Errorf("Did not expect the 'Annotations' field of the source to be mutated, diff: %s", cmp.Diff(want, got))
			}
		})
	}
}

func TestConvert_flowcontrol_PriorityLevelConfiguration_To_v1beta3_PriorityLevelConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		in          *flowcontrol.PriorityLevelConfiguration
		expected    *v1beta3.PriorityLevelConfiguration
		errExpected error
	}{
		{
			name: "the value of the NominalConcurrencyShares field in the internal object is 0; v1beta3 object should have the roundtrip annotation",
			in: &flowcontrol.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
				Spec: flowcontrol.PriorityLevelConfigurationSpec{
					Type: flowcontrol.PriorityLevelEnablementLimited,
					Limited: &flowcontrol.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: ptr.To(int32(0)),
						LimitResponse: flowcontrol.LimitResponse{
							Type: flowcontrol.LimitResponseTypeReject,
						},
					},
				},
			},
			expected: &v1beta3.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
						v1beta3.PriorityLevelConcurrencyShareDefaultKey: "",
					},
				},
				Spec: v1beta3.PriorityLevelConfigurationSpec{
					Type: v1beta3.PriorityLevelEnablementLimited,
					Limited: &v1beta3.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: 0,
						LimitResponse: v1beta3.LimitResponse{
							Type: v1beta3.LimitResponseTypeReject,
						},
					},
				},
			},
		},
		{
			name: "the value of the NominalConcurrencyShares field is not 0; v1beta3 object should not have the roundtrip annotation",
			in: &flowcontrol.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
				Spec: flowcontrol.PriorityLevelConfigurationSpec{
					Type: flowcontrol.PriorityLevelEnablementLimited,
					Limited: &flowcontrol.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: ptr.To(int32(1)),
						LimitResponse: flowcontrol.LimitResponse{
							Type: flowcontrol.LimitResponseTypeReject,
						},
					},
				},
			},
			expected: &v1beta3.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
				Spec: v1beta3.PriorityLevelConfigurationSpec{
					Type: v1beta3.PriorityLevelEnablementLimited,
					Limited: &v1beta3.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: 1,
						LimitResponse: v1beta3.LimitResponse{
							Type: v1beta3.LimitResponseTypeReject,
						},
					},
				},
			},
		},
		{
			name: "the NominalConcurrencyShares field of the internal object is nil; error expected",
			in: &flowcontrol.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
				Spec: flowcontrol.PriorityLevelConfigurationSpec{
					Type: flowcontrol.PriorityLevelEnablementLimited,
					Limited: &flowcontrol.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: nil,
						LimitResponse: flowcontrol.LimitResponse{
							Type: flowcontrol.LimitResponseTypeReject,
						},
					},
				},
			},
			expected: &v1beta3.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
				Spec: v1beta3.PriorityLevelConfigurationSpec{
					Type: v1beta3.PriorityLevelEnablementLimited,
					Limited: &v1beta3.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: 0,
						LimitResponse: v1beta3.LimitResponse{
							Type: v1beta3.LimitResponseTypeReject,
						},
					},
				},
			},
			errExpected: fmt.Errorf("unexpected nil value for NominalConcurrencyShares in the internal object"),
		},
		{
			name: "the value of the NominalConcurrencyShares field is 0, the internal object already has the roundtrip annotation",
			in: &flowcontrol.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						v1beta3.PriorityLevelConcurrencyShareDefaultKey: "",
						"foo": "bar",
					},
				},
				Spec: flowcontrol.PriorityLevelConfigurationSpec{
					Type: flowcontrol.PriorityLevelEnablementLimited,
					Limited: &flowcontrol.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: ptr.To(int32(0)),
						LimitResponse: flowcontrol.LimitResponse{
							Type: flowcontrol.LimitResponseTypeReject,
						},
					},
				},
			},
			expected: &v1beta3.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
						v1beta3.PriorityLevelConcurrencyShareDefaultKey: "",
					},
				},
				Spec: v1beta3.PriorityLevelConfigurationSpec{
					Type: v1beta3.PriorityLevelEnablementLimited,
					Limited: &v1beta3.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: 0,
						LimitResponse: v1beta3.LimitResponse{
							Type: v1beta3.LimitResponseTypeReject,
						},
					},
				},
			},
		},
		{
			name: "the value of the NominalConcurrencyShares field is 0, the roundtrip annotation is set to an non empty value",
			in: &flowcontrol.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						v1beta3.PriorityLevelConcurrencyShareDefaultKey: "non-empty",
						"foo": "bar",
					},
				},
				Spec: flowcontrol.PriorityLevelConfigurationSpec{
					Type: flowcontrol.PriorityLevelEnablementLimited,
					Limited: &flowcontrol.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: ptr.To(int32(0)),
						LimitResponse: flowcontrol.LimitResponse{
							Type: flowcontrol.LimitResponseTypeReject,
						},
					},
				},
			},
			expected: &v1beta3.PriorityLevelConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
						v1beta3.PriorityLevelConcurrencyShareDefaultKey: "",
					},
				},
				Spec: v1beta3.PriorityLevelConfigurationSpec{
					Type: v1beta3.PriorityLevelEnablementLimited,
					Limited: &v1beta3.LimitedPriorityLevelConfiguration{
						NominalConcurrencyShares: 0,
						LimitResponse: v1beta3.LimitResponse{
							Type: v1beta3.LimitResponseTypeReject,
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := test.in.DeepCopy()

			out := &v1beta3.PriorityLevelConfiguration{}
			errGot := Convert_flowcontrol_PriorityLevelConfiguration_To_v1beta3_PriorityLevelConfiguration(test.in, out, nil)

			switch {
			case test.errExpected != nil:
				if want, got := test.errExpected.Error(), errGot.Error(); want != got {
					t.Errorf("Expected error: %v, but got: %v", want, got)
				}
				return
			default:
				if errGot != nil {
					t.Errorf("Expected no error, but got: %v", errGot)
				}
			}

			if !cmp.Equal(test.expected, out) {
				t.Errorf("Expected a match, diff: %s", cmp.Diff(test.expected, out))
			}
			if want, got := copy.ObjectMeta.Annotations, test.in.ObjectMeta.Annotations; !cmp.Equal(want, got) {
				t.Errorf("Did not expect the 'Annotations' field of the source to be mutated, diff: %s", cmp.Diff(want, got))
			}
		})
	}
}
