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
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/clock"
)

func TestStorageObjectCountTracker(t *testing.T) {
	tracker := &objectCountTracker{
		clock:  &clock.RealClock{},
		counts: map[string]*timestampedCount{},
	}
	groupResource := &schema.GroupResource{
		Group:    "foo.bar",
		Resource: "resource",
	}

	var countExpected int64 = 799
	key := groupResource.String()
	tracker.OnCount(key, countExpected)

	if countGot, ok := tracker.Get(key); !ok || countExpected != countGot {
		t.Errorf("Expected count: %d, but got: (%d,%t)", countExpected, countGot, ok)
	}
}

func TestStorageObjectCountTrackerWithPrune(t *testing.T) {
	fakeClock := &clock.FakePassiveClock{}
	tracker := &objectCountTracker{
		clock:  fakeClock,
		counts: map[string]*timestampedCount{},
	}

	now := time.Now()
	fakeClock.SetTime(now.Add(-mustParseDuration(t, "1h1m")))
	tracker.OnCount("k1", 61)
	fakeClock.SetTime(now.Add(-mustParseDuration(t, "1h")))
	tracker.OnCount("k2", 60)
	// we are going to prune keys that are stale for >= 1h
	// so the above keys are expected to be pruned and the
	// key below should not be pruned.
	mostRecent := now.Add(-mustParseDuration(t, "59m"))
	fakeClock.SetTime(mostRecent)
	tracker.OnCount("k3", 59)
	expected := map[string]*timestampedCount{
		"k3": {
			count:       59,
			lastUpdated: mostRecent,
		},
	}

	fakeClock.SetTime(now)
	tracker.prune(time.Hour)

	// we expect only one entry in the map, so DeepEqual should work.
	if !reflect.DeepEqual(expected, tracker.counts) {
		t.Errorf("Expected prune to remove stale entries - diff: %s", cmp.Diff(expected, tracker.counts))
	}
}

func mustParseDuration(t *testing.T, s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("Failed to parse duration: %s - %v", s, err)
	}
	return d
}
