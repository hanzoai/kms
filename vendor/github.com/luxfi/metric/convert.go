//go:build grpc

// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

import dto "github.com/luxfi/metric/client"

// DTOToNative converts wire MetricFamily slice to native MetricFamily slice.
// This is used at the RPC boundary when receiving metrics from gRPC.
func DTOToNative(dtoFamilies []*dto.MetricFamily) []*MetricFamily {
	if dtoFamilies == nil {
		return nil
	}
	result := make([]*MetricFamily, 0, len(dtoFamilies))
	for _, dtoMF := range dtoFamilies {
		if dtoMF == nil {
			continue
		}
		mf := &MetricFamily{
			Name: dtoMF.GetName(),
			Help: dtoMF.GetHelp(),
			Type: dtoTypeToNative(dtoMF.GetType()),
		}
		for _, dtoM := range dtoMF.GetMetric() {
			if dtoM == nil {
				continue
			}
			m := Metric{
				Labels: dtoLabelsToNative(dtoM.GetLabel()),
				Value:  dtoValueToNative(dtoM, mf.Type),
			}
			mf.Metrics = append(mf.Metrics, m)
		}
		result = append(result, mf)
	}
	return result
}

// NativeToDTO converts native MetricFamily slice to wire MetricFamily slice.
// This is used at the RPC boundary when sending metrics over gRPC.
func NativeToDTO(families []*MetricFamily) []*dto.MetricFamily {
	if families == nil {
		return nil
	}
	result := make([]*dto.MetricFamily, 0, len(families))
	for _, mf := range families {
		if mf == nil {
			continue
		}
		dtoMF := &dto.MetricFamily{
			Name: ptrStr(mf.Name),
			Help: ptrStr(mf.Help),
			Type: nativeTypeToDTo(mf.Type),
		}
		for _, m := range mf.Metrics {
			dtoM := nativeMetricToDTO(m, mf.Type)
			dtoMF.Metric = append(dtoMF.Metric, dtoM)
		}
		result = append(result, dtoMF)
	}
	return result
}

func dtoTypeToNative(t dto.MetricType) MetricType {
	switch t {
	case dto.MetricType_COUNTER:
		return MetricTypeCounter
	case dto.MetricType_GAUGE:
		return MetricTypeGauge
	case dto.MetricType_HISTOGRAM:
		return MetricTypeHistogram
	case dto.MetricType_SUMMARY:
		return MetricTypeSummary
	default:
		return MetricTypeUntyped
	}
}

func nativeTypeToDTo(t MetricType) *dto.MetricType {
	var dtoType dto.MetricType
	switch t {
	case MetricTypeCounter:
		dtoType = dto.MetricType_COUNTER
	case MetricTypeGauge:
		dtoType = dto.MetricType_GAUGE
	case MetricTypeHistogram:
		dtoType = dto.MetricType_HISTOGRAM
	case MetricTypeSummary:
		dtoType = dto.MetricType_SUMMARY
	default:
		dtoType = dto.MetricType_UNTYPED
	}
	return &dtoType
}

func dtoLabelsToNative(labels []*dto.LabelPair) []LabelPair {
	if labels == nil {
		return nil
	}
	result := make([]LabelPair, 0, len(labels))
	for _, lp := range labels {
		if lp == nil {
			continue
		}
		result = append(result, LabelPair{
			Name:  lp.GetName(),
			Value: lp.GetValue(),
		})
	}
	return result
}

func nativeLabelsToDTO(labels []LabelPair) []*dto.LabelPair {
	if labels == nil {
		return nil
	}
	result := make([]*dto.LabelPair, 0, len(labels))
	for _, lp := range labels {
		result = append(result, &dto.LabelPair{
			Name:  ptrStr(lp.Name),
			Value: ptrStr(lp.Value),
		})
	}
	return result
}

func dtoValueToNative(m *dto.Metric, t MetricType) MetricValue {
	var v MetricValue
	switch t {
	case MetricTypeCounter:
		if c := m.GetCounter(); c != nil {
			v.Value = c.GetValue()
		}
	case MetricTypeGauge:
		if g := m.GetGauge(); g != nil {
			v.Value = g.GetValue()
		}
	case MetricTypeHistogram:
		if h := m.GetHistogram(); h != nil {
			v.SampleCount = h.GetSampleCount()
			v.SampleSum = h.GetSampleSum()
			for _, b := range h.GetBucket() {
				if b != nil {
					v.Buckets = append(v.Buckets, Bucket{
						UpperBound:      b.GetUpperBound(),
						CumulativeCount: b.GetCumulativeCount(),
					})
				}
			}
		}
	case MetricTypeSummary:
		if s := m.GetSummary(); s != nil {
			v.SampleCount = s.GetSampleCount()
			v.SampleSum = s.GetSampleSum()
			for _, q := range s.GetQuantile() {
				if q != nil {
					v.Quantiles = append(v.Quantiles, Quantile{
						Quantile: q.GetQuantile(),
						Value:    q.GetValue(),
					})
				}
			}
		}
	default:
		// For untyped, try counter first, then gauge
		if c := m.GetCounter(); c != nil {
			v.Value = c.GetValue()
		} else if g := m.GetGauge(); g != nil {
			v.Value = g.GetValue()
		}
	}
	return v
}

func nativeMetricToDTO(m Metric, t MetricType) *dto.Metric {
	dtoM := &dto.Metric{
		Label: nativeLabelsToDTO(m.Labels),
	}
	switch t {
	case MetricTypeCounter:
		dtoM.Counter = &dto.Counter{
			Value: ptrFloat(m.Value.Value),
		}
	case MetricTypeGauge:
		dtoM.Gauge = &dto.Gauge{
			Value: ptrFloat(m.Value.Value),
		}
	case MetricTypeHistogram:
		h := &dto.Histogram{
			SampleCount: ptrUint64(m.Value.SampleCount),
			SampleSum:   ptrFloat(m.Value.SampleSum),
		}
		for _, b := range m.Value.Buckets {
			h.Bucket = append(h.Bucket, &dto.Bucket{
				UpperBound:      ptrFloat(b.UpperBound),
				CumulativeCount: ptrUint64(b.CumulativeCount),
			})
		}
		dtoM.Histogram = h
	case MetricTypeSummary:
		s := &dto.Summary{
			SampleCount: ptrUint64(m.Value.SampleCount),
			SampleSum:   ptrFloat(m.Value.SampleSum),
		}
		for _, q := range m.Value.Quantiles {
			s.Quantile = append(s.Quantile, &dto.Quantile{
				Quantile: ptrFloat(q.Quantile),
				Value:    ptrFloat(q.Value),
			})
		}
		dtoM.Summary = s
	default:
		// For untyped, use gauge
		dtoM.Gauge = &dto.Gauge{
			Value: ptrFloat(m.Value.Value),
		}
	}
	return dtoM
}

func ptrStr(s string) *string {
	return &s
}

func ptrFloat(f float64) *float64 {
	return &f
}

func ptrUint64(u uint64) *uint64 {
	return &u
}
