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
	"fmt"
	"net/http"

	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"
)

const (
	// the minimum number of seats a request must occupy
	minimumSeats = 1

	// the maximum number of seats a request can occupy
	maximumSeats = 10
)

type Width struct {
	// Seats represents the number of seats associated with this request
	Seats uint
}

// objectCountGetterFunc represents a function that gets the total
// number of objects for a given resource.
type objectCountGetterFunc func(string) int64

func (f objectCountGetterFunc) Get(key string) int64 {
	return f(key)
}

// NewWidthEstimator calculates the width of the given request, if no WidthEstimatorFunc
// matches the given request then the default width with '1' Seats is returned.
func NewWidthEstimator(countFn objectCountGetterFunc) WidthEstimatorFunc {
	estimator := &widthEstimator{
		listWidthEstimator: newListWidthEstimator(countFn),
	}
	return estimator.estimate
}

// WidthEstimatorFunc returns the estimated "width" of a given request.
// This function will be used by the Priority & Fairness filter to
// estimate the "width" of incoming requests.
type WidthEstimatorFunc func(*http.Request) Width

func (e WidthEstimatorFunc) EstimateWidth(r *http.Request) Width {
	return e(r)
}

type widthEstimator struct {
	// listWidthEstimator calculates the width of list request(s)
	listWidthEstimator WidthEstimatorFunc
}

func (e *widthEstimator) estimate(r *http.Request) Width {
	requestInfo, ok := apirequest.RequestInfoFrom(r.Context())
	if !ok {
		klog.ErrorS(fmt.Errorf("no RequestInfo found in context"), "Failed to estimate width for the request", "URI", r.RequestURI)
		// no RequestInfo should never happen, but to be on the safe side let's return maximumSeats
		return Width{Seats: maximumSeats}
	}

	switch requestInfo.Verb {
	case "list":
		return e.listWidthEstimator.EstimateWidth(r)
	}

	return Width{Seats: minimumSeats}
}
