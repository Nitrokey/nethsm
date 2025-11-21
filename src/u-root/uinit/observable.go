package main

import "sync/atomic"

type Observable[T comparable] struct {
	atomic.Pointer[observableData[T]]
}

type observableData[T comparable] struct {
	value  *T
	notify chan struct{}
}

func (v *Observable[T]) getData() *observableData[T] {
	snap := v.Load()
	if snap == nil {
		// Lazy initialization on first use
		firstSnapshot := &observableData[T]{
			value:  nil,
			notify: make(chan struct{}),
		}
		if v.CompareAndSwap(nil, firstSnapshot) {
			return firstSnapshot
		}
		// Another goroutine won the race, load again
		return v.Load()
	}
	return snap
}

func (v *Observable[T]) Get() (*T, <-chan struct{}) {
	data := v.getData()
	return data.value, data.notify
}

func (v *Observable[T]) Set(new *T) {
	for {
		oldData := v.getData()

		// Determine if value actually changed
		if new == nil {
			if oldData.value == nil {
				return
			}
		} else {
			cpy := *new
			if oldData.value != nil && *oldData.value == cpy {
				return
			}
			new = &cpy
		}

		newData := &observableData[T]{
			value:  new,
			notify: make(chan struct{}),
		}

		// Only close if we successfully swapped
		if v.CompareAndSwap(oldData, newData) {
			close(oldData.notify)
			return
		}
		// CAS failed, retry
	}
}
