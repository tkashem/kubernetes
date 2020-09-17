package request

import (
	"context"
	"time"
)

type requestReceiveTimeKeyType int

// requestReceiveTimeKey is the ReceiveTime key for the context. It's of private type here. Because
// keys are interfaces and interfaces are equal when the type and the value is equal, this
// does not conflict with the keys defined in pkg/api.
const requestReceiveTimeKey requestReceiveTimeKeyType = iota

// WithReceiveTime returns a copy of parent in which the request receive time is set
func WithReceiveTime(parent context.Context, receiveTime time.Time) context.Context {
	if receiveTime.IsZero() {
		return parent
	}
	return WithValue(parent, requestReceiveTimeKey, receiveTime)
}

// ReceiveTimeFrom returns the value of the RequestInfo key on the ctx
func ReceiveTimeFrom(ctx context.Context) (time.Time, bool) {
	info, ok := ctx.Value(requestReceiveTimeKey).(time.Time)
	return info, ok
}
