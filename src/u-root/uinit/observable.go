package main

import "sync/atomic"

type Observable[T comparable] struct {
	p atomic.Pointer[observableData[T]]
}

type observableData[T comparable] struct {
	value  *T
	notify chan struct{}
}

func (v *Observable[T]) getData() *observableData[T] {
	snap := v.p.Load()
	if snap == nil {
		// Lazy initialization on first use
		firstSnapshot := &observableData[T]{
			value:  nil,
			notify: make(chan struct{}),
		}
		if v.p.CompareAndSwap(nil, firstSnapshot) {
			return firstSnapshot
		}
		// Another goroutine won the race, load again
		return v.p.Load()
	}
	return snap
}

func (v *Observable[T]) Get() (*T, <-chan struct{}) {
	data := *v.getData()
	value := data.value
	if data.value != nil {
		cpy := *value
		value = &cpy
	}
	return value, data.notify
}

func (v *Observable[T]) Set(new *T) <-chan struct{} {
	for {
		oldData := v.getData()

		// Determine if value actually changed
		if new == nil {
			if oldData.value == nil {
				return oldData.notify
			}
		} else {
			cpy := *new
			if oldData.value != nil && *oldData.value == cpy {
				return oldData.notify
			}
			new = &cpy
		}

		newData := &observableData[T]{
			value:  new,
			notify: make(chan struct{}),
		}

		// Only close if we successfully swapped
		if v.p.CompareAndSwap(oldData, newData) {
			close(oldData.notify)
			return newData.notify
		}
		// CAS failed, retry
	}
}
