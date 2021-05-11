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
	"fmt"
	"net/http"

	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// responsible for estimating the "width" of LIST request(s)
type listWidthEstimator struct{}

func (f *listWidthEstimator) FindWidth(r *http.Request) (float64, bool, error) {
	requestInfo, ok := apirequest.RequestInfoFrom(r.Context())
	if !ok {
		return 0, false, fmt.Errorf("no RequestInfo found in context")
	}

	if requestInfo.Verb != "list" {
		return 0, false, nil
	}

	// we can inspect resource version or get information
	// from the watch cache to estimate the width
	return 1, true, nil
}
