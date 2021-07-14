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
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

const (
	// type deletion (it applies mostly to CRD) is not a very frequent
	// operation so we can afford to prune the cache at a large interval.
	// at the same time, we also want to make sure that the scalability
	// tests hit this code path.
	pruneInterval = 1 * time.Hour
)

// StorageObjectCountTracker is an interface that is used to keep track of
// of the total number of objects for each resource.
// {group}.{resource} is used as the key name to update and retrieve
// the total number of objects for a given resource.
type StorageObjectCountTracker interface {
	// OnCount is invoked to update the current number of total
	// objects for the given resource
	OnCount(string, int64)

	// Get returns the total number of objects for the given resource.
	// If the given resource is not being tracked Get will return false.
	Get(string) (int64, bool)
}

// NewStorageObjectCountTracker returns an instance of
// StorageObjectCountTracker interface that can be used to
// keep track of the total number of objects for each resource.
func NewStorageObjectCountTracker(stopCh <-chan struct{}) StorageObjectCountTracker {
	tracker := &objectCountTracker{
		clock:  &clock.RealClock{},
		counts: map[string]*timestampedCount{},
	}
	go func() {
		wait.PollUntil(
			pruneInterval,
			func() (bool, error) {
				tracker.prune(pruneInterval)
				// always prune at every pruneInterval
				return false, nil
			}, stopCh)
		klog.InfoS("StorageObjectCountTracker pruner is exiting")
	}()

	return tracker
}

// timestampedCount stores the count of a given resource with a last updated
// timestamp so we can prune it after it goes stale for certain threshold.
type timestampedCount struct {
	count       int64
	lastUpdated time.Time
}

// objectCountTracker implements StorageObjectCountTracker with
// reader/writer mutual exclusion lock.
type objectCountTracker struct {
	clock clock.PassiveClock

	lock   sync.RWMutex
	counts map[string]*timestampedCount
}

func (t *objectCountTracker) OnCount(groupResource string, count int64) {
	if count == -1 {
		// a value of -1 indicates that the 'Count' call failed to contact
		// the storage layer, in most cases this error can be transient.
		// we will continue to work with the count that is in the cache,
		// in case this becomes a non transient error then the count for
		// given resource will go stale and will eventually be removed
		// from the cache by the pruner.
		// so we may work with stale count for at most pruneInterval.
		return
	}

	now := t.clock.Now()

	t.lock.Lock()
	defer t.lock.Unlock()

	if item, ok := t.counts[groupResource]; ok {
		item.count = count
		item.lastUpdated = now
		return
	}

	t.counts[groupResource] = &timestampedCount{
		count:       count,
		lastUpdated: now,
	}
}

func (t *objectCountTracker) Get(groupResource string) (int64, bool) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if item, ok := t.counts[groupResource]; ok {
		return item.count, true
	}
	return 0, false
}

func (t *objectCountTracker) prune(threshold time.Duration) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	oldestLastUpdatedAtAllowed := t.clock.Now().Add(-threshold)

	for groupResource, count := range t.counts {
		if count.lastUpdated.After(oldestLastUpdatedAtAllowed) {
			continue
		}
		delete(t.counts, groupResource)
	}
}
