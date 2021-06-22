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

package request

import (
	"net/http"
	"testing"

	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

func TestWidthEstimator(t *testing.T) {
	tests := []struct {
		name          string
		requestURI    string
		requestInfo   *apirequest.RequestInfo
		counts        map[string]int64
		seatsExpected uint
	}{
		{
			name:          "request has no RequestInfo",
			requestURI:    "http://server/apis/v1/foos/",
			requestInfo:   nil,
			seatsExpected: 10,
		},
		{
			name:       "request verb is not list",
			requestURI: "http://server/apis/v1/foos/",
			requestInfo: &apirequest.RequestInfo{
				Verb: "get",
			},
			seatsExpected: 1,
		},
		{
			name:       "request verb is list, resource version not set",
			requestURI: "http://server/apis/v1/foos/1?limit=499",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			counts: map[string]int64{
				"resource.foo.bar": 799,
			},
			seatsExpected: 5,
		},
		{
			name:       "request verb is list, continuation is set",
			requestURI: "http://server/apis/v1/foos/1?continue=token&limit=499&resourceVersion=1",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			counts: map[string]int64{
				"resource.foo.bar": 799,
			},
			seatsExpected: 5,
		},
		{
			name:       "request verb is list, has limit",
			requestURI: "http://server/apis/v1/foos/1?limit=499&resourceVersion=1",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			counts: map[string]int64{
				"resource.foo.bar": 799,
			},
			seatsExpected: 5,
		},
		{
			name:       "request verb is list, resource version is zero",
			requestURI: "http://server/apis/v1/foos/1?resourceVersion=0",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			counts: map[string]int64{
				"resource.foo.bar": 799,
			},
			seatsExpected: 8,
		},
		{
			name:       "request verb is list, no query parameters, count known",
			requestURI: "http://server/apis/v1/foos/1",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			counts: map[string]int64{
				"resource.foo.bar": 799,
			},
			seatsExpected: 8,
		},
		{
			name:       "request verb is list, no query parameters, count not known",
			requestURI: "http://server/apis/v1/foos/1",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			seatsExpected: 10,
		},
		{
			name:       "request verb is list, resource version match is Exact",
			requestURI: "http://server/apis/v1/foos/1?resourceVersion=foo&resourceVersionMatch=Exact&limit=499",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			counts: map[string]int64{
				"resource.foo.bar": 799,
			},
			seatsExpected: 5,
		},
		{
			name:       "request verb is list, resource version match is NotOlderThan, limit not specified",
			requestURI: "http://server/apis/v1/foos/1?resourceVersion=foo&resourceVersionMatch=NotOlderThan",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			counts: map[string]int64{
				"resource.foo.bar": 799,
			},
			seatsExpected: 8,
		},
		{
			name:       "request verb is list, maximum is capped",
			requestURI: "http://server/apis/v1/foos/1?resourceVersion=foo",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			counts: map[string]int64{
				"resource.foo.bar": 1999,
			},
			seatsExpected: 10,
		},
		{
			name:       "request verb is list, list from cache, count not known",
			requestURI: "http://server/apis/v1/foos/1?resourceVersion=0&limit=799",
			requestInfo: &apirequest.RequestInfo{
				Verb:     "list",
				APIGroup: "foo.bar",
				Resource: "resource",
			},
			seatsExpected: 10,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			counts := test.counts
			if len(counts) == 0 {
				counts = map[string]int64{}
			}
			countsFn := func(key string) int64 {
				return counts[key]
			}
			estimator := NewWidthEstimator(countsFn)

			req, err := http.NewRequest("GET", test.requestURI, nil)
			if err != nil {
				t.Fatalf("Failed to create new HTTP request - %v", err)
			}

			if test.requestInfo != nil {
				req = req.WithContext(apirequest.WithRequestInfo(req.Context(), test.requestInfo))
			}

			widthGot := estimator.EstimateWidth(req)
			if test.seatsExpected != widthGot.Seats {
				t.Errorf("Expected request width to match: %d seats, but got: %d seats", test.seatsExpected, widthGot.Seats)
			}
		})
	}
}
