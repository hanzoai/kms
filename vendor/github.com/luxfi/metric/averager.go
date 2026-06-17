// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import (
	"errors"
	"fmt"
)

var ErrFailedRegistering = errors.New("failed registering metric")

type Averager interface {
	Observe(float64)
}

type averager struct {
	count Counter
	sum   Gauge
}

func NewAverager(name, desc string, reg Registerer) (Averager, error) {
	errs := &Errs{}
	a := NewAveragerWithErrs(name, desc, reg, errs)
	return a, errs.Err
}

func NewAveragerWithErrs(name, desc string, reg Registerer, errs *Errs) Averager {
	a := averager{
		count: NewCounter(CounterOpts{
			Name: AppendNamespace(name, "count"),
			Help: "Total # of observations of " + desc,
		}),
		sum: NewGauge(GaugeOpts{
			Name: AppendNamespace(name, "sum"),
			Help: "Sum of " + desc,
		}),
	}

	if err := reg.Register(AsCollector(a.count)); err != nil {
		errs.Add(fmt.Errorf("%w: %w", ErrFailedRegistering, err))
	}
	if err := reg.Register(AsCollector(a.sum)); err != nil {
		errs.Add(fmt.Errorf("%w: %w", ErrFailedRegistering, err))
	}
	return &a
}

func (a *averager) Observe(v float64) {
	a.count.Inc()
	a.sum.Add(v)
}

type noAverager struct{}

func NewNoAverager() Averager {
	return noAverager{}
}

func (noAverager) Observe(float64) {}

// AppendNamespace appends a namespace to a metric name if needed
func AppendNamespace(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "_" + name
}
