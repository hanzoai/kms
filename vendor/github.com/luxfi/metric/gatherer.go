// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"fmt"
	"sort"
	"sync"
)

// Gatherer gathers metric families for exposition.
type Gatherer interface {
	Gather() ([]*MetricFamily, error)
}

// Gatherers is a helper type for slices of gatherers.
type Gatherers []Gatherer

// MultiGatherer extends the Gatherer interface by allowing additional gatherers
// to be registered and deregistered.
type MultiGatherer interface {
	Gatherer

	// Register adds the outputs of [gatherer] to the results of future calls to
	// Gather with the provided [namespace] added to the metrics.
	Register(namespace string, gatherer Gatherer) error

	// Deregister removes the outputs of a gatherer with [namespace] from the results
	// of future calls to Gather. Returns true if a gatherer with [namespace] was
	// found.
	Deregister(namespace string) bool
}

// NewMultiGatherer returns a new MultiGatherer that merges metrics by namespace.
func NewMultiGatherer() MultiGatherer {
	return &multiGatherer{
		gatherers: make(map[string]Gatherer),
	}
}

type multiGatherer struct {
	lock      sync.RWMutex
	gatherers map[string]Gatherer
}

func (g *multiGatherer) Gather() ([]*MetricFamily, error) {
	g.lock.RLock()
	defer g.lock.RUnlock()

	var result []*MetricFamily
	for _, gatherer := range g.gatherers {
		metrics, err := gatherer.Gather()
		if err != nil {
			return nil, err
		}
		result = append(result, metrics...)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}

func (g *multiGatherer) Register(namespace string, gatherer Gatherer) error {
	g.lock.Lock()
	defer g.lock.Unlock()

	if _, exists := g.gatherers[namespace]; exists {
		return fmt.Errorf("gatherer already registered for namespace: %s", namespace)
	}
	g.gatherers[namespace] = gatherer
	return nil
}

func (g *multiGatherer) Deregister(namespace string) bool {
	g.lock.Lock()
	defer g.lock.Unlock()

	_, exists := g.gatherers[namespace]
	delete(g.gatherers, namespace)
	return exists
}

// MakeAndRegister creates a new registry and registers it with the gatherer.
func MakeAndRegister(gatherer MultiGatherer, namespace string) (Registry, error) {
	reg := NewRegistry()
	if err := gatherer.Register(namespace, reg); err != nil {
		return nil, fmt.Errorf("couldn't register %q metrics: %w", namespace, err)
	}
	return reg, nil
}

// NewPrefixGatherer returns a new MultiGatherer that adds a prefix to all metrics.
func NewPrefixGatherer() MultiGatherer {
	return &prefixGatherer{
		multiGatherer: multiGatherer{
			gatherers: make(map[string]Gatherer),
		},
	}
}

type prefixGatherer struct {
	multiGatherer
}

func (g *prefixGatherer) Gather() ([]*MetricFamily, error) {
	g.lock.RLock()
	defer g.lock.RUnlock()

	var result []*MetricFamily
	for namespace, gatherer := range g.gatherers {
		metrics, err := gatherer.Gather()
		if err != nil {
			return nil, err
		}
		for _, mf := range metrics {
			prefixedName := namespace + "_" + mf.Name
			mf.Name = prefixedName
		}
		result = append(result, metrics...)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}
