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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
	"math"
	"net/http"
	"net/url"
)

func newListWidthEstimator(countFn objectCountGetterFunc) WidthEstimatorFunc {
	estimator := &listWidthEstimator{
		countFn: countFn,
	}
	return estimator.estimate
}

type listWidthEstimator struct {
	countFn objectCountGetterFunc
}

func (e *listWidthEstimator) estimate(r *http.Request) Width {
	requestInfo, ok := apirequest.RequestInfoFrom(r.Context())
	if !ok {
		// no RequestInfo should never happen, but to be on the safe side
		// let's return minimumSeatsList
		return Width{Seats: maximumSeats}
	}

	query := r.URL.Query()
	listOptions := metav1.ListOptions{}
	if err := metav1.Convert_url_Values_To_v1_ListOptions(&query, &listOptions, nil); err != nil {
		klog.ErrorS(err, "Failed to convert options while calculating request width")
		return Width{Seats: minimumSeats}
	}

	count := e.countFn.Get(key(requestInfo))
	isListFromCache := !shouldListFromStorage(query, &listOptions)

	if (listOptions.Limit == 0 || isListFromCache) && count == 0 {
		// if object count is not known then we allocate maximum seats when:
		// - limit is zero, or
		// - we are listing from cache
		return Width{Seats: maximumSeats}
	}

	// TODO: For resources that implement indexes at the watchcache level,
	//  we need to adjust the cost accordingly
	var estimatedObjectsToBeProcessed int64
	switch {
	case isListFromCache:
		// if we are here, count is known
		estimatedObjectsToBeProcessed = count
	default:
		// Even if a selector is specified and we may need to list and go over more objects from etcd
		// to produce the result of size <limit>, each individual chunk will be of size at most <limit>.
		// As a result. the width of the request should be computed based on <limit> and the actual
		// cost of processing more elements will be hidden in the request processing latency.
		estimatedObjectsToBeProcessed = listOptions.Limit
		if estimatedObjectsToBeProcessed == 0 {
			// limit has not been specified, fall back to count
			estimatedObjectsToBeProcessed = count
		}
	}

	// for now, our rough estimate is to allocate one seat to each 100 obejcts that
	// will be processed by the list request.
	// we will come up with a different formula for the transformation function and/or
	// fine tune this number in future iteratons.
	seats := uint(math.Ceil(float64(estimatedObjectsToBeProcessed) / float64(100)))

	// make sure we never return a seat of zero
	if seats < minimumSeats {
		seats = minimumSeats
	}
	if seats > maximumSeats {
		seats = maximumSeats
	}
	return Width{Seats: seats}
}

func key(requestInfo *apirequest.RequestInfo) string {
	groupResource := &schema.GroupResource{
		Group:    requestInfo.APIGroup,
		Resource: requestInfo.Resource,
	}
	return groupResource.String()
}

// NOTICE: Keep in sync with shouldDelegateList function in
//  staging/src/k8s.io/apiserver/pkg/storage/cacher/cacher.go
func shouldListFromStorage(query url.Values, opts *metav1.ListOptions) bool {
	resourceVersion := opts.ResourceVersion
	pagingEnabled := utilfeature.DefaultFeatureGate.Enabled(features.APIListChunking)
	hasContinuation := pagingEnabled && len(opts.Continue) > 0
	hasLimit := pagingEnabled && opts.Limit > 0 && resourceVersion != "0"
	return resourceVersion == "" || hasContinuation || hasLimit || opts.ResourceVersionMatch == metav1.ResourceVersionMatchExact
}
