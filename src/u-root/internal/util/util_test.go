// Copyright 2026, Nitrokey GmbH
// SPDX-License-Identifier: EUPL-1.2

package util

import (
	"slices"
	"sync"
	"testing"
)

func TestRingKeepsNewestValuesInOrder(t *testing.T) {
	r := NewRing[int](3)
	if got := r.Collect(); len(got) != 0 {
		t.Errorf("new ring is not empty: %v", got)
	}
	for i := range 5 {
		r.Add(i)
	}
	if got, want := r.Collect(), []int{2, 3, 4}; !slices.Equal(got, want) {
		t.Errorf("got %v, wanted %v", got, want)
	}
}

func TestRingNil(t *testing.T) {
	var r *Ring[int]
	if got := r.Collect(); got != nil {
		t.Errorf("got %v, wanted nil", got)
	}
}

// Fails with the race detector if readers can see a value being written.
func TestRingConcurrentUse(t *testing.T) {
	r := NewRing[int](16)
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 1000 {
			r.Add(i)
		}
	})
	for range 1000 {
		r.Collect()
	}
	wg.Wait()
}
