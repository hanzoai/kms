// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

// Registerer is the minimal interface required to register and create metrics.
type Registerer interface {
	Metrics
	Register(Collector) error
	MustRegister(...Collector)
}

// Registry is a registerer that can also gather metric families.
type Registry interface {
	Registerer
	Gatherer
}
