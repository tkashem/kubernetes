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

package width

import (
	"net/http"

	"k8s.io/klog/v2"
)

// NewRequestWidthEstimator returns a RequestWidthEstimator that executes
// the given chain of RequestWidthEstimator(s) one at a time in the specified order
// and returns the "width" of a given request.
// It stops when a RequestWidthEstimator from the chain has returned the "width"
// of the given request.
// If no RequestWidthEstimator from the chain returned a "width" for the given request
// the the chain is exhausted and we fallback to the default finder which returns
// '1' as the "width" of the given request.
func NewRequestWidthEstimator(chain ...RequestWidthEstimator) RequestWidthEstimatorFunc {
	return func(r *http.Request) float64 {
		for _, estimator := range chain {
			width, ok, err := estimator.EstimateWidth(r)
			if err != nil {
				klog.ErrorS(err, "Ran into an error while estimating width", "name", estimator.Name())
				break
			}
			if ok {
				return width
			}
		}

		// return the default width
		return 1.0
	}
}

// RequestWidthEstimatorFunc returns the estimated "width" of a given request.
type RequestWidthEstimatorFunc func(*http.Request) float64

func (e RequestWidthEstimatorFunc) EstimateWidth(r *http.Request) float64 {
	return e(r)
}

// RequestWidthEstimator estimates the "width" of a given request.
type RequestWidthEstimator interface {
	// Name returns the name of the RequestWidthEstimator
	Name() string

	// EstimateWidth estimates the "width" of a given request.
	//
	// err is set when the function ran into an unrecoverable error
	// while estimating, this indicates
	// ok is 'true' when the function successfully estimates the
	// "width" of the request, otherwise it is set to 'false'
	// width would be set to a non-zero value when the function
	// successfully estimates the "width", otherwise it is set to zero.
	EstimateWidth(r *http.Request) (width float64, ok bool, err error)
}
