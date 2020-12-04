package filters

import (
	"fmt"
	"net/http"
	"time"

	"k8s.io/apiserver/pkg/endpoints/metrics"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

func WithResponseWriteLatencyMetric(handler http.Handler, longRunning apirequest.LongRunningRequestCheck) http.Handler {
	if longRunning == nil {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		requestInfo, ok := apirequest.RequestInfoFrom(ctx)
		if !ok {
			handleError(w, req, fmt.Errorf("no RequestInfo found in context, handler chain must be wrong"))
			return
		}
		if longRunning(req, requestInfo) {
			handler.ServeHTTP(w, req)
			return
		}

		withMetric := &writerWithMetric{w: w, info: requestInfo}
		handler.ServeHTTP(withMetric, req)
	})
}

type writerWithMetric struct {
	w    http.ResponseWriter
	info *apirequest.RequestInfo
}

func (wm *writerWithMetric) Header() http.Header {
	return wm.w.Header()
}

func (wm *writerWithMetric) Write(p []byte) (int, error) {
	now := time.Now()
	defer func() {
		elapsed := time.Now().Sub(now)
		metrics.RecordResponseWriteLatency(wm.info, elapsed)
	}()
	return wm.w.Write(p)
}

func (wm *writerWithMetric) Flush() {
	if flusher, ok := wm.w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (wm *writerWithMetric) WriteHeader(code int) {
	wm.w.WriteHeader(code)
}
