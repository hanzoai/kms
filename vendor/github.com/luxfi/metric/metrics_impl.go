// Package metric provides metrics collection.
// Designed for minimal allocations and standalone operation.
package metric

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// metricCounter provides a counter.
type metricCounter struct {
	value uint64 // atomic float64 bits
	name  string
	help  string
}

// newCounter creates a counter.
func newCounter(name, help string) *metricCounter {
	return &metricCounter{
		name: name,
		help: help,
	}
}

// Inc increments the counter by 1
func (vc *metricCounter) Inc() {
	vc.Add(1)
}

// Add adds a value to the counter
func (vc *metricCounter) Add(val float64) {
	for {
		oldBits := atomic.LoadUint64(&vc.value)
		oldVal := math.Float64frombits(oldBits)
		newVal := oldVal + val
		newBits := math.Float64bits(newVal)
		if atomic.CompareAndSwapUint64(&vc.value, oldBits, newBits) {
			return
		}
	}
}

// Value returns the current value
func (vc *metricCounter) Value() uint64 {
	return uint64(vc.Get())
}

// Get returns the current value as float64.
func (vc *metricCounter) Get() float64 {
	return math.Float64frombits(atomic.LoadUint64(&vc.value))
}

// String returns the counter in the metrics text format.
func (vc *metricCounter) String() string {
	return fmt.Sprintf("# HELP %s %s\n# TYPE %s counter\n%s %g", vc.name, vc.help, vc.name, vc.name, vc.Get())
}

// metricGauge provides a gauge.
type metricGauge struct {
	value int64 // Use int64 to handle negative values
	name  string
	help  string
}

// newGauge creates a gauge.
func newGauge(name, help string) *metricGauge {
	return &metricGauge{
		name: name,
		help: help,
	}
}

// Set sets the gauge value
func (vg *metricGauge) Set(val float64) {
	atomic.StoreInt64(&vg.value, int64(math.Float64bits(val)))
}

// Get returns the gauge value
func (vg *metricGauge) Get() float64 {
	return math.Float64frombits(uint64(atomic.LoadInt64(&vg.value)))
}

// Inc increments the gauge by 1
func (vg *metricGauge) Inc() {
	for {
		oldVal := vg.Get()
		newVal := oldVal + 1
		oldBits := math.Float64bits(oldVal)
		newBits := math.Float64bits(newVal)
		if atomic.CompareAndSwapInt64(&vg.value, int64(oldBits), int64(newBits)) {
			break
		}
	}
}

// Dec decrements the gauge by 1
func (vg *metricGauge) Dec() {
	for {
		oldVal := vg.Get()
		newVal := oldVal - 1
		oldBits := math.Float64bits(oldVal)
		newBits := math.Float64bits(newVal)
		if atomic.CompareAndSwapInt64(&vg.value, int64(oldBits), int64(newBits)) {
			break
		}
	}
}

// Add adds a value to the gauge
func (vg *metricGauge) Add(val float64) {
	for {
		oldVal := vg.Get()
		newVal := oldVal + val
		oldBits := math.Float64bits(oldVal)
		newBits := math.Float64bits(newVal)
		if atomic.CompareAndSwapInt64(&vg.value, int64(oldBits), int64(newBits)) {
			break
		}
	}
}

// Sub subtracts a value from the gauge
func (vg *metricGauge) Sub(val float64) {
	for {
		oldVal := vg.Get()
		newVal := oldVal - val
		oldBits := math.Float64bits(oldVal)
		newBits := math.Float64bits(newVal)
		if atomic.CompareAndSwapInt64(&vg.value, int64(oldBits), int64(newBits)) {
			break
		}
	}
}

// String returns the gauge in the metrics text format.
func (vg *metricGauge) String() string {
	return fmt.Sprintf("# HELP %s %s\n# TYPE %s gauge\n%s %f", vg.name, vg.help, vg.name, vg.name, vg.Get())
}

// Value returns the current value.
func (vg *metricGauge) Value() float64 {
	return vg.Get()
}

// metricHistogram provides a histogram.
type metricHistogram struct {
	name         string
	help         string
	buckets      []float64
	bucketCounts []uint64 // Count of values in each bucket
	count        uint64   // Total count of observations
	sum          float64  // Sum of all observations
	mu           sync.RWMutex
}

// newHistogram creates a histogram.
func newHistogram(name, help string, buckets []float64) *metricHistogram {
	if len(buckets) == 0 {
		buckets = DefBuckets
	}
	// Sort buckets to ensure they're in ascending order
	sortedBuckets := make([]float64, len(buckets))
	copy(sortedBuckets, buckets)
	sort.Float64s(sortedBuckets)

	return &metricHistogram{
		name:         name,
		help:         help,
		buckets:      sortedBuckets,
		bucketCounts: make([]uint64, len(sortedBuckets)+1), // +1 for +Inf bucket
	}
}

// Observe records a value in the histogram
func (vh *metricHistogram) Observe(val float64) {
	vh.mu.Lock()
	defer vh.mu.Unlock()

	// Find the appropriate bucket
	bucketIdx := len(vh.buckets) // Default to +Inf bucket
	for i, bucket := range vh.buckets {
		if val <= bucket {
			bucketIdx = i
			break
		}
	}

	// Increment the appropriate bucket count
	atomic.AddUint64(&vh.bucketCounts[bucketIdx], 1)

	// Increment total count
	atomic.AddUint64(&vh.count, 1)

	// Add to sum
	for {
		oldSum := vh.sum
		newSum := oldSum + val
		if atomic.CompareAndSwapUint64((*uint64)(unsafe.Pointer(&vh.sum)), math.Float64bits(oldSum), math.Float64bits(newSum)) {
			break
		}
	}
}

// GetBucketCounts returns the current bucket counts
func (vh *metricHistogram) GetBucketCounts() []uint64 {
	vh.mu.RLock()
	defer vh.mu.RUnlock()

	result := make([]uint64, len(vh.bucketCounts))
	for i := range vh.bucketCounts {
		result[i] = atomic.LoadUint64(&vh.bucketCounts[i])
	}
	return result
}

// GetCount returns the total count
func (vh *metricHistogram) GetCount() uint64 {
	return atomic.LoadUint64(&vh.count)
}

// GetSum returns the sum.
func (vh *metricHistogram) GetSum() float64 {
	return math.Float64frombits(atomic.LoadUint64((*uint64)(unsafe.Pointer(&vh.sum))))
}

// ToMetric returns a Metric representation for exposition.
func (vh *metricHistogram) ToMetric(labels []LabelPair) Metric {
	vh.mu.RLock()
	defer vh.mu.RUnlock()

	var buckets []Bucket
	var cumulative uint64
	for i, upper := range vh.buckets {
		cumulative += atomic.LoadUint64(&vh.bucketCounts[i])
		buckets = append(buckets, Bucket{UpperBound: upper, CumulativeCount: cumulative})
	}
	// +Inf bucket
	cumulative += atomic.LoadUint64(&vh.bucketCounts[len(vh.bucketCounts)-1])
	buckets = append(buckets, Bucket{UpperBound: math.Inf(1), CumulativeCount: cumulative})

	return Metric{
		Labels: labels,
		Value: MetricValue{
			SampleCount: atomic.LoadUint64(&vh.count),
			SampleSum:   math.Float64frombits(atomic.LoadUint64((*uint64)(unsafe.Pointer(&vh.sum)))),
			Buckets:     buckets,
		},
	}
}

// String returns the histogram in the metrics text format.
func (vh *metricHistogram) String() string {
	vh.mu.RLock()
	defer vh.mu.RUnlock()

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# HELP %s %s\n", vh.name, vh.help))
	sb.WriteString(fmt.Sprintf("# TYPE %s histogram\n", vh.name))

	// Write bucket counts
	cumulative := uint64(0)
	for i, bucket := range vh.buckets {
		cumulative += atomic.LoadUint64(&vh.bucketCounts[i])
		sb.WriteString(fmt.Sprintf("%s_bucket{le=\"%g\"} %d\n", vh.name, bucket, cumulative))
	}

	// Write +Inf bucket
	cumulative += atomic.LoadUint64(&vh.bucketCounts[len(vh.buckets)])
	sb.WriteString(fmt.Sprintf("%s_bucket{le=\"+Inf\"} %d\n", vh.name, cumulative))

	// Write count and sum
	sb.WriteString(fmt.Sprintf("%s_count %d\n", vh.name, atomic.LoadUint64(&vh.count)))
	sb.WriteString(fmt.Sprintf("%s_sum %g\n", vh.name, math.Float64frombits(atomic.LoadUint64((*uint64)(unsafe.Pointer(&vh.sum))))))

	return sb.String()
}

// metricSummary provides a summary.
type metricSummary struct {
	name       string
	help       string
	count      uint64
	sum        float64
	objectives []float64
	samples    []float64
	sampleIdx  int
	maxSamples int
	mu         sync.RWMutex
}

// newSummary creates a summary.
func newSummary(name, help string, objectives map[float64]float64) *metricSummary {
	objList := make([]float64, 0, len(objectives))
	for q := range objectives {
		objList = append(objList, q)
	}
	if len(objList) == 0 {
		objList = []float64{0.5, 0.9, 0.99}
	}
	sort.Float64s(objList)
	return &metricSummary{
		name:       name,
		help:       help,
		objectives: objList,
		maxSamples: 1024,
	}
}

// Observe records a value in the summary
func (vs *metricSummary) Observe(val float64) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	atomic.AddUint64(&vs.count, 1)

	// Add to sum atomically
	for {
		oldSum := vs.sum
		newSum := oldSum + val
		if atomic.CompareAndSwapUint64((*uint64)(unsafe.Pointer(&vs.sum)), math.Float64bits(oldSum), math.Float64bits(newSum)) {
			break
		}
	}

	if vs.maxSamples <= 0 {
		return
	}
	if len(vs.samples) < vs.maxSamples {
		vs.samples = append(vs.samples, val)
		return
	}
	vs.samples[vs.sampleIdx] = val
	vs.sampleIdx = (vs.sampleIdx + 1) % vs.maxSamples
}

// GetCount returns the total count
func (vs *metricSummary) GetCount() uint64 {
	return atomic.LoadUint64(&vs.count)
}

// GetSum returns the sum.
func (vs *metricSummary) GetSum() float64 {
	return math.Float64frombits(atomic.LoadUint64((*uint64)(unsafe.Pointer(&vs.sum))))
}

// ToMetric returns a Metric representation for exposition.
func (vs *metricSummary) ToMetric(labels []LabelPair) Metric {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	return Metric{
		Labels: labels,
		Value: MetricValue{
			SampleCount: atomic.LoadUint64(&vs.count),
			SampleSum:   math.Float64frombits(atomic.LoadUint64((*uint64)(unsafe.Pointer(&vs.sum)))),
			Quantiles:   quantilesFromSamples(vs.samples, vs.objectives),
		},
	}
}

func quantilesFromSamples(samples []float64, objectives []float64) []Quantile {
	if len(samples) == 0 || len(objectives) == 0 {
		return nil
	}
	data := append([]float64(nil), samples...)
	sort.Float64s(data)
	quantiles := make([]Quantile, 0, len(objectives))
	for _, q := range objectives {
		if q <= 0 {
			quantiles = append(quantiles, Quantile{Quantile: q, Value: data[0]})
			continue
		}
		if q >= 1 {
			quantiles = append(quantiles, Quantile{Quantile: q, Value: data[len(data)-1]})
			continue
		}
		idx := int(math.Ceil(q*float64(len(data)))) - 1
		if idx < 0 {
			idx = 0
		} else if idx >= len(data) {
			idx = len(data) - 1
		}
		quantiles = append(quantiles, Quantile{Quantile: q, Value: data[idx]})
	}
	return quantiles
}

// String returns the summary in the metrics text format.
func (vs *metricSummary) String() string {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# HELP %s %s\n", vs.name, vs.help))
	sb.WriteString(fmt.Sprintf("# TYPE %s summary\n", vs.name))

	// Write count and sum
	sb.WriteString(fmt.Sprintf("%s_count %d\n", vs.name, atomic.LoadUint64(&vs.count)))
	sb.WriteString(fmt.Sprintf("%s_sum %g\n", vs.name, math.Float64frombits(atomic.LoadUint64((*uint64)(unsafe.Pointer(&vs.sum))))))

	// Write quantiles
	for _, q := range quantilesFromSamples(vs.samples, vs.objectives) {
		sb.WriteString(fmt.Sprintf("%s{quantile=\"%g\"} %g\n", vs.name, q.Quantile, q.Value))
	}

	return sb.String()
}

// timingMetric provides timing functionality for histogram-backed timing.
type timingMetric struct {
	histogram Histogram
	start     time.Time
}

// newTimingMetric creates a new timing metric.
func newTimingMetric(histogram Histogram) *timingMetric {
	return &timingMetric{
		histogram: histogram,
		start:     time.Now(),
	}
}

// Stop stops the timing and records the duration
func (vtm *timingMetric) Stop() {
	duration := time.Since(vtm.start).Seconds()
	vtm.histogram.Observe(duration)
}

// Reset resets the timing
func (vtm *timingMetric) Reset() {
	vtm.start = time.Now()
}

// Duration returns the current duration
func (vtm *timingMetric) Duration() time.Duration {
	return time.Since(vtm.start)
}

// Start starts the timer and returns a function to stop it
func (vtm *timingMetric) Start() func() {
	vtm.start = time.Now()
	return vtm.Stop
}

// ObserveTime observes the given duration
func (vtm *timingMetric) ObserveTime(d time.Duration) {
	vtm.histogram.Observe(d.Seconds())
}

// factory creates metrics.
type factory struct {
	registry Registry
}

// NewFactory creates a factory that produces metrics.
func NewFactory() Factory {
	return &factory{registry: NewRegistry()}
}

// NewFactoryWithRegistry creates a factory using an existing registry when possible.
func NewFactoryWithRegistry(reg Registry) Factory {
	if reg == nil {
		return NewFactory()
	}
	return &factory{registry: reg}
}

// New creates a new metrics instance with the given namespace.
func (hpf *factory) New(namespace string) Metrics {
	return &metrics{
		namespace: namespace,
		registry:  hpf.registry,
	}
}

// NewWithRegistry creates a new metrics instance using the provided registry when possible.
func (hpf *factory) NewWithRegistry(namespace string, registry Registry) Metrics {
	if registry == nil {
		registry = hpf.registry
	}
	return &metrics{
		namespace: namespace,
		registry:  registry,
	}
}

// NewCounter creates a counter.
func (hpf *factory) NewCounter(name, help string) Counter {
	return hpf.registry.NewCounter(name, help)
}

// NewGauge creates a gauge.
func (hpf *factory) NewGauge(name, help string) Gauge {
	return hpf.registry.NewGauge(name, help)
}

// NewHistogram creates a histogram.
func (hpf *factory) NewHistogram(name, help string, buckets []float64) Histogram {
	return hpf.registry.NewHistogram(name, help, buckets)
}

// NewSummary creates a summary.
func (hpf *factory) NewSummary(name, help string, objectives map[float64]float64) Summary {
	return hpf.registry.NewSummary(name, help, objectives)
}

type metrics struct {
	namespace string
	registry  Registry
}

func (m *metrics) NewCounter(name, help string) Counter {
	return m.registry.NewCounter(prefixedName(m.namespace, name), help)
}

func (m *metrics) NewCounterVec(name, help string, labelNames []string) CounterVec {
	return m.registry.NewCounterVec(prefixedName(m.namespace, name), help, labelNames)
}

func (m *metrics) NewGauge(name, help string) Gauge {
	return m.registry.NewGauge(prefixedName(m.namespace, name), help)
}

func (m *metrics) NewGaugeVec(name, help string, labelNames []string) GaugeVec {
	return m.registry.NewGaugeVec(prefixedName(m.namespace, name), help, labelNames)
}

func (m *metrics) NewHistogram(name, help string, buckets []float64) Histogram {
	return m.registry.NewHistogram(prefixedName(m.namespace, name), help, buckets)
}

func (m *metrics) NewHistogramVec(name, help string, labelNames []string, buckets []float64) HistogramVec {
	return m.registry.NewHistogramVec(prefixedName(m.namespace, name), help, labelNames, buckets)
}

func (m *metrics) NewSummary(name, help string, objectives map[float64]float64) Summary {
	return m.registry.NewSummary(prefixedName(m.namespace, name), help, objectives)
}

func (m *metrics) NewSummaryVec(name, help string, labelNames []string, objectives map[float64]float64) SummaryVec {
	return m.registry.NewSummaryVec(prefixedName(m.namespace, name), help, labelNames, objectives)
}

func (m *metrics) Registry() Registry {
	return m.registry
}

func prefixedName(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "_" + name
}

// registry collects metrics and exposes them via Gather.
type registry struct {
	mu         sync.RWMutex
	counters   map[string]map[string]*labeledCounter
	gauges     map[string]map[string]*labeledGauge
	histograms map[string]map[string]*labeledHistogram
	summaries  map[string]map[string]*labeledSummary
	registered map[string]MetricType
}

type labeledCounter struct {
	labels  Labels
	counter *metricCounter
}

type labeledGauge struct {
	labels Labels
	gauge  *metricGauge
}

type labeledHistogram struct {
	labels    Labels
	histogram *metricHistogram
}

type labeledSummary struct {
	labels  Labels
	summary *metricSummary
}

// newRegistry creates an empty registry.
func newRegistry() *registry {
	return &registry{
		counters:   make(map[string]map[string]*labeledCounter),
		gauges:     make(map[string]map[string]*labeledGauge),
		histograms: make(map[string]map[string]*labeledHistogram),
		summaries:  make(map[string]map[string]*labeledSummary),
		registered: make(map[string]MetricType),
	}
}

// RegisterCounter registers a counter without labels.
func (hpr *registry) RegisterCounter(name string, counter *metricCounter) {
	hpr.RegisterLabeledCounter(name, nil, counter)
}

// RegisterGauge registers a gauge without labels.
func (hpr *registry) RegisterGauge(name string, gauge *metricGauge) {
	hpr.RegisterLabeledGauge(name, nil, gauge)
}

// RegisterHistogram registers a histogram without labels.
func (hpr *registry) RegisterHistogram(name string, histogram *metricHistogram) {
	hpr.RegisterLabeledHistogram(name, nil, histogram)
}

// RegisterSummary registers a summary without labels.
func (hpr *registry) RegisterSummary(name string, summary *metricSummary) {
	hpr.RegisterLabeledSummary(name, nil, summary)
}

// RegisterLabeledCounter registers a counter with labels.
func (hpr *registry) RegisterLabeledCounter(name string, labels Labels, counter *metricCounter) {
	hpr.mu.Lock()
	defer hpr.mu.Unlock()
	key := labelsKeyFromLabels(labels)
	if hpr.counters[name] == nil {
		hpr.counters[name] = make(map[string]*labeledCounter)
	}
	hpr.counters[name][key] = &labeledCounter{labels: cloneLabels(labels), counter: counter}
}

// RegisterLabeledGauge registers a gauge with labels.
func (hpr *registry) RegisterLabeledGauge(name string, labels Labels, gauge *metricGauge) {
	hpr.mu.Lock()
	defer hpr.mu.Unlock()
	key := labelsKeyFromLabels(labels)
	if hpr.gauges[name] == nil {
		hpr.gauges[name] = make(map[string]*labeledGauge)
	}
	hpr.gauges[name][key] = &labeledGauge{labels: cloneLabels(labels), gauge: gauge}
}

// RegisterLabeledHistogram registers a histogram with labels.
func (hpr *registry) RegisterLabeledHistogram(name string, labels Labels, histogram *metricHistogram) {
	hpr.mu.Lock()
	defer hpr.mu.Unlock()
	key := labelsKeyFromLabels(labels)
	if hpr.histograms[name] == nil {
		hpr.histograms[name] = make(map[string]*labeledHistogram)
	}
	hpr.histograms[name][key] = &labeledHistogram{labels: cloneLabels(labels), histogram: histogram}
}

// RegisterLabeledSummary registers a summary with labels.
func (hpr *registry) RegisterLabeledSummary(name string, labels Labels, summary *metricSummary) {
	hpr.mu.Lock()
	defer hpr.mu.Unlock()
	key := labelsKeyFromLabels(labels)
	if hpr.summaries[name] == nil {
		hpr.summaries[name] = make(map[string]*labeledSummary)
	}
	hpr.summaries[name][key] = &labeledSummary{labels: cloneLabels(labels), summary: summary}
}

// NewCounter creates and registers a counter.
func (hpr *registry) NewCounter(name, help string) Counter {
	counter := newCounter(name, help)
	hpr.RegisterCounter(name, counter)
	return counter
}

// NewCounterVec creates and registers a counter vec.
func (hpr *registry) NewCounterVec(name, help string, labelNames []string) CounterVec {
	return newCounterVec(hpr, name, help, labelNames)
}

// NewGauge creates and registers a gauge.
func (hpr *registry) NewGauge(name, help string) Gauge {
	gauge := newGauge(name, help)
	hpr.RegisterGauge(name, gauge)
	return gauge
}

// NewGaugeVec creates and registers a gauge vec.
func (hpr *registry) NewGaugeVec(name, help string, labelNames []string) GaugeVec {
	return newGaugeVec(hpr, name, help, labelNames)
}

// NewHistogram creates and registers a histogram.
func (hpr *registry) NewHistogram(name, help string, buckets []float64) Histogram {
	histogram := newHistogram(name, help, buckets)
	hpr.RegisterHistogram(name, histogram)
	return histogram
}

// NewHistogramVec creates and registers a histogram vec.
func (hpr *registry) NewHistogramVec(name, help string, labelNames []string, buckets []float64) HistogramVec {
	return newHistogramVec(hpr, name, help, labelNames, buckets)
}

// NewSummary creates and registers a summary.
func (hpr *registry) NewSummary(name, help string, objectives map[float64]float64) Summary {
	summary := newSummary(name, help, objectives)
	hpr.RegisterSummary(name, summary)
	return summary
}

// NewSummaryVec creates and registers a summary vec.
func (hpr *registry) NewSummaryVec(name, help string, labelNames []string, objectives map[float64]float64) SummaryVec {
	return newSummaryVec(hpr, name, help, labelNames, objectives)
}

// Registry returns the registry itself.
func (hpr *registry) Registry() Registry {
	return hpr
}

// Register is a compatibility no-op. Metrics are registered on creation.
func (hpr *registry) Register(c Collector) error {
	name, typ, ok := collectorIdentity(c)
	if !ok {
		return fmt.Errorf("unsupported collector type %T", c)
	}
	if err := hpr.registerName(name, typ); err != nil {
		return err
	}
	switch v := c.(type) {
	case *metricCounter:
		hpr.RegisterCounter(name, v)
	case *metricGauge:
		hpr.RegisterGauge(name, v)
	case *metricHistogram:
		hpr.RegisterHistogram(name, v)
	case *metricSummary:
		hpr.RegisterSummary(name, v)
	case *counterVec:
		v.registry = hpr
	case *gaugeVec:
		v.registry = hpr
	case *histogramVec:
		v.registry = hpr
	case *summaryVec:
		v.registry = hpr
	}
	return nil
}

// MustRegister registers collectors and panics on error.
func (hpr *registry) MustRegister(cs ...Collector) {
	for _, c := range cs {
		if err := hpr.Register(c); err != nil {
			panic(err)
		}
	}
}

// Gather returns metric families for all registered metrics.
func (hpr *registry) Gather() ([]*MetricFamily, error) {
	hpr.mu.RLock()
	defer hpr.mu.RUnlock()

	var families []*MetricFamily
	for name, entries := range hpr.counters {
		help := ""
		for _, entry := range entries {
			help = entry.counter.help
			break
		}
		family := &MetricFamily{Name: name, Help: help, Type: MetricTypeCounter}
		for _, entry := range entries {
			family.Metrics = append(family.Metrics, Metric{
				Labels: labelsToLabelPairs(entry.labels),
				Value:  MetricValue{Value: entry.counter.Get()},
			})
		}
		families = append(families, family)
	}
	for name, entries := range hpr.gauges {
		help := ""
		for _, entry := range entries {
			help = entry.gauge.help
			break
		}
		family := &MetricFamily{Name: name, Help: help, Type: MetricTypeGauge}
		for _, entry := range entries {
			family.Metrics = append(family.Metrics, Metric{
				Labels: labelsToLabelPairs(entry.labels),
				Value:  MetricValue{Value: entry.gauge.Get()},
			})
		}
		families = append(families, family)
	}
	for name, entries := range hpr.histograms {
		help := ""
		for _, entry := range entries {
			help = entry.histogram.help
			break
		}
		family := &MetricFamily{Name: name, Help: help, Type: MetricTypeHistogram}
		for _, entry := range entries {
			family.Metrics = append(family.Metrics, entry.histogram.ToMetric(labelsToLabelPairs(entry.labels)))
		}
		families = append(families, family)
	}
	for name, entries := range hpr.summaries {
		help := ""
		for _, entry := range entries {
			help = entry.summary.help
			break
		}
		family := &MetricFamily{Name: name, Help: help, Type: MetricTypeSummary}
		for _, entry := range entries {
			family.Metrics = append(family.Metrics, entry.summary.ToMetric(labelsToLabelPairs(entry.labels)))
		}
		families = append(families, family)
	}
	return families, nil
}

// counterVec is a labeled counter collection.
type counterVec struct {
	registry   *registry
	name       string
	help       string
	labelNames []string
	mu         sync.Mutex
	counters   map[string]Counter
}

func newCounterVec(registry *registry, name, help string, labelNames []string) *counterVec {
	return &counterVec{
		registry:   registry,
		name:       name,
		help:       help,
		labelNames: append([]string(nil), labelNames...),
		counters:   make(map[string]Counter),
	}
}

func (v *counterVec) With(labels Labels) Counter {
	return v.getOrCreate(labels)
}

func (v *counterVec) WithLabelValues(values ...string) Counter {
	labels := labelsFromValues(v.labelNames, values)
	return v.getOrCreate(labels)
}

func (v *counterVec) getOrCreate(labels Labels) Counter {
	key := labelsKeyFromLabels(labels)
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok := v.counters[key]; ok {
		return c
	}
	counter := newCounter(v.name, v.help)
	v.registry.RegisterLabeledCounter(v.name, labels, counter)
	v.counters[key] = counter
	return counter
}

// gaugeVec is a labeled gauge collection.
type gaugeVec struct {
	registry   *registry
	name       string
	help       string
	labelNames []string
	mu         sync.Mutex
	gauges     map[string]Gauge
}

func newGaugeVec(registry *registry, name, help string, labelNames []string) *gaugeVec {
	return &gaugeVec{
		registry:   registry,
		name:       name,
		help:       help,
		labelNames: append([]string(nil), labelNames...),
		gauges:     make(map[string]Gauge),
	}
}

func (v *gaugeVec) With(labels Labels) Gauge {
	return v.getOrCreate(labels)
}

func (v *gaugeVec) WithLabelValues(values ...string) Gauge {
	labels := labelsFromValues(v.labelNames, values)
	return v.getOrCreate(labels)
}

func (v *gaugeVec) getOrCreate(labels Labels) Gauge {
	key := labelsKeyFromLabels(labels)
	v.mu.Lock()
	defer v.mu.Unlock()
	if g, ok := v.gauges[key]; ok {
		return g
	}
	gauge := newGauge(v.name, v.help)
	v.registry.RegisterLabeledGauge(v.name, labels, gauge)
	v.gauges[key] = gauge
	return gauge
}

// histogramVec is a labeled histogram collection.
type histogramVec struct {
	registry   *registry
	name       string
	help       string
	labelNames []string
	buckets    []float64
	mu         sync.Mutex
	histograms map[string]Histogram
}

func newHistogramVec(registry *registry, name, help string, labelNames []string, buckets []float64) *histogramVec {
	return &histogramVec{
		registry:   registry,
		name:       name,
		help:       help,
		labelNames: append([]string(nil), labelNames...),
		buckets:    append([]float64(nil), buckets...),
		histograms: make(map[string]Histogram),
	}
}

func (v *histogramVec) With(labels Labels) Histogram {
	return v.getOrCreate(labels)
}

func (v *histogramVec) WithLabelValues(values ...string) Histogram {
	labels := labelsFromValues(v.labelNames, values)
	return v.getOrCreate(labels)
}

func (v *histogramVec) getOrCreate(labels Labels) Histogram {
	key := labelsKeyFromLabels(labels)
	v.mu.Lock()
	defer v.mu.Unlock()
	if h, ok := v.histograms[key]; ok {
		return h
	}
	histogram := newHistogram(v.name, v.help, v.buckets)
	v.registry.RegisterLabeledHistogram(v.name, labels, histogram)
	v.histograms[key] = histogram
	return histogram
}

// summaryVec is a labeled summary collection.
type summaryVec struct {
	registry   *registry
	name       string
	help       string
	labelNames []string
	objectives map[float64]float64
	mu         sync.Mutex
	summaries  map[string]Summary
}

func newSummaryVec(registry *registry, name, help string, labelNames []string, objectives map[float64]float64) *summaryVec {
	objCopy := make(map[float64]float64, len(objectives))
	for k, v := range objectives {
		objCopy[k] = v
	}
	return &summaryVec{
		registry:   registry,
		name:       name,
		help:       help,
		labelNames: append([]string(nil), labelNames...),
		objectives: objCopy,
		summaries:  make(map[string]Summary),
	}
}

func (v *summaryVec) With(labels Labels) Summary {
	return v.getOrCreate(labels)
}

func (v *summaryVec) WithLabelValues(values ...string) Summary {
	labels := labelsFromValues(v.labelNames, values)
	return v.getOrCreate(labels)
}

func (v *summaryVec) getOrCreate(labels Labels) Summary {
	key := labelsKeyFromLabels(labels)
	v.mu.Lock()
	defer v.mu.Unlock()
	if s, ok := v.summaries[key]; ok {
		return s
	}
	summary := newSummary(v.name, v.help, v.objectives)
	v.registry.RegisterLabeledSummary(v.name, labels, summary)
	v.summaries[key] = summary
	return summary
}

func labelsFromValues(labelNames []string, values []string) Labels {
	labels := make(Labels, len(labelNames))
	for i, name := range labelNames {
		if i < len(values) {
			labels[name] = values[i]
		}
	}
	return labels
}

func labelsKeyFromLabels(labels Labels) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(k)
		sb.WriteString("=\"")
		sb.WriteString(labels[k])
		sb.WriteString("\"")
	}
	sb.WriteString("}")
	return sb.String()
}

func cloneLabels(labels Labels) Labels {
	if len(labels) == 0 {
		return nil
	}
	clone := make(Labels, len(labels))
	for k, v := range labels {
		clone[k] = v
	}
	return clone
}

func labelsToLabelPairs(labels Labels) []LabelPair {
	if len(labels) == 0 {
		return nil
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res := make([]LabelPair, 0, len(keys))
	for _, k := range keys {
		res = append(res, LabelPair{Name: k, Value: labels[k]})
	}
	return res
}

func (hpr *registry) registerName(name string, typ MetricType) error {
	hpr.mu.Lock()
	defer hpr.mu.Unlock()
	if existing, ok := hpr.registered[name]; ok {
		return fmt.Errorf("metric %q already registered as %s", name, existing.String())
	}
	hpr.registered[name] = typ
	return nil
}

func collectorIdentity(c Collector) (string, MetricType, bool) {
	switch v := c.(type) {
	case *metricCounter:
		return v.name, MetricTypeCounter, true
	case *metricGauge:
		return v.name, MetricTypeGauge, true
	case *metricHistogram:
		return v.name, MetricTypeHistogram, true
	case *metricSummary:
		return v.name, MetricTypeSummary, true
	case *counterVec:
		return v.name, MetricTypeCounter, true
	case *gaugeVec:
		return v.name, MetricTypeGauge, true
	case *histogramVec:
		return v.name, MetricTypeHistogram, true
	case *summaryVec:
		return v.name, MetricTypeSummary, true
	default:
		return "", MetricTypeUntyped, false
	}
}
