/*
 * SPDX-FileCopyrightText: © 2017-2025 Istari Digital, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package y

import (
	"expvar"
	"sync"
)

const (
	BADGER_METRIC_PREFIX = "badger_"
)

var (
	// lsmSize has size of the LSM in bytes
	lsmSize *expvar.Map
	// vlogSize has size of the value log in bytes
	vlogSize *expvar.Map
	// pendingWrites tracks the number of pending writes.
	pendingWrites *expvar.Map

	// These are cumulative

	// VLOG METRICS
	// numReads has cumulative number of reads from vlog
	numReadsVlog *expvar.Int
	// numWrites has cumulative number of writes into vlog
	numWritesVlog *expvar.Int
	// numBytesRead has cumulative number of bytes read from VLOG
	numBytesReadVlog *expvar.Int
	// numBytesVlogWritten has cumulative number of bytes written into VLOG
	numBytesVlogWritten *expvar.Int

	// LSM METRICS
	// numBytesRead has cumulative number of bytes read from LSM tree
	numBytesReadLSM *expvar.Int
	// numBytesWrittenToL0 has cumulative number of bytes written into LSM Tree
	numBytesWrittenToL0 *expvar.Int
	// numLSMGets is number of LSM gets
	numLSMGets *expvar.Map
	// numBytesCompactionWritten is the number of bytes written in the lsm tree due to compaction
	numBytesCompactionWritten *expvar.Map
	// numLSMBloomHits is number of LMS bloom hits
	numLSMBloomHits *expvar.Map

	// DB METRICS
	// numGets is number of gets -> Number of get requests made
	numGets *expvar.Int
	// number of get queries in which we actually get a result
	numGetsWithResults *expvar.Int
	// number of iterators created, these would be the number of range queries
	numIteratorsCreated *expvar.Int
	// numPuts is number of puts -> Number of puts requests made
	numPuts *expvar.Int
	// numMemtableGets is number of memtable gets -> Number of get requests made on memtable
	numMemtableGets *expvar.Int
	// numCompactionTables is the number of tables being compacted
	numCompactionTables *expvar.Int
	// Total writes by a user in bytes
	numBytesWrittenUser *expvar.Int

	// metricsOnce ensures metrics are only initialized once
	metricsOnce sync.Once
)

// getOrCreateInt returns an existing expvar.Int or creates a new one
func getOrCreateInt(name string) *expvar.Int {
	if v := expvar.Get(name); v != nil {
		return v.(*expvar.Int)
	}
	return expvar.NewInt(name)
}

// getOrCreateMap returns an existing expvar.Map or creates a new one
func getOrCreateMap(name string) *expvar.Map {
	if v := expvar.Get(name); v != nil {
		return v.(*expvar.Map)
	}
	return expvar.NewMap(name)
}

// initMetrics initializes all metrics (called once via sync.Once)
func initMetrics() {
	numReadsVlog = getOrCreateInt(BADGER_METRIC_PREFIX + "read_num_vlog")
	numBytesReadVlog = getOrCreateInt(BADGER_METRIC_PREFIX + "read_bytes_vlog")
	numWritesVlog = getOrCreateInt(BADGER_METRIC_PREFIX + "write_num_vlog")
	numBytesVlogWritten = getOrCreateInt(BADGER_METRIC_PREFIX + "write_bytes_vlog")

	numBytesReadLSM = getOrCreateInt(BADGER_METRIC_PREFIX + "read_bytes_lsm")
	numBytesWrittenToL0 = getOrCreateInt(BADGER_METRIC_PREFIX + "write_bytes_l0")
	numBytesCompactionWritten = getOrCreateMap(BADGER_METRIC_PREFIX + "write_bytes_compaction")

	numLSMGets = getOrCreateMap(BADGER_METRIC_PREFIX + "get_num_lsm")
	numLSMBloomHits = getOrCreateMap(BADGER_METRIC_PREFIX + "hit_num_lsm_bloom_filter")
	numMemtableGets = getOrCreateInt(BADGER_METRIC_PREFIX + "get_num_memtable")

	// User operations
	numGets = getOrCreateInt(BADGER_METRIC_PREFIX + "get_num_user")
	numPuts = getOrCreateInt(BADGER_METRIC_PREFIX + "put_num_user")
	numBytesWrittenUser = getOrCreateInt(BADGER_METRIC_PREFIX + "write_bytes_user")

	// Required for Enabled
	numGetsWithResults = getOrCreateInt(BADGER_METRIC_PREFIX + "get_with_result_num_user")
	numIteratorsCreated = getOrCreateInt(BADGER_METRIC_PREFIX + "iterator_num_user")

	// Sizes
	lsmSize = getOrCreateMap(BADGER_METRIC_PREFIX + "size_bytes_lsm")
	vlogSize = getOrCreateMap(BADGER_METRIC_PREFIX + "size_bytes_vlog")

	pendingWrites = getOrCreateMap(BADGER_METRIC_PREFIX + "write_pending_num_memtable")
	numCompactionTables = getOrCreateInt(BADGER_METRIC_PREFIX + "compaction_current_num_lsm")
}

// These variables are global and have cumulative values for all kv stores.
// Naming convention of metrics: {badger_version}_{singular operation}_{granularity}_{component}
func init() {
	metricsOnce.Do(initMetrics)
}

func NumIteratorsCreatedAdd(enabled bool, val int64) {
	addInt(enabled, numIteratorsCreated, val)
}

func NumGetsWithResultsAdd(enabled bool, val int64) {
	addInt(enabled, numGetsWithResults, val)
}

func NumReadsVlogAdd(enabled bool, val int64) {
	addInt(enabled, numReadsVlog, val)
}

func NumBytesWrittenUserAdd(enabled bool, val int64) {
	addInt(enabled, numBytesWrittenUser, val)
}

func NumWritesVlogAdd(enabled bool, val int64) {
	addInt(enabled, numWritesVlog, val)
}

func NumBytesReadsVlogAdd(enabled bool, val int64) {
	addInt(enabled, numBytesReadVlog, val)
}

func NumBytesReadsLSMAdd(enabled bool, val int64) {
	addInt(enabled, numBytesReadLSM, val)
}

func NumBytesWrittenVlogAdd(enabled bool, val int64) {
	addInt(enabled, numBytesVlogWritten, val)
}

func NumBytesWrittenToL0Add(enabled bool, val int64) {
	addInt(enabled, numBytesWrittenToL0, val)
}

func NumBytesCompactionWrittenAdd(enabled bool, key string, val int64) {
	addToMap(enabled, numBytesCompactionWritten, key, val)
}

func NumGetsAdd(enabled bool, val int64) {
	addInt(enabled, numGets, val)
}

func NumPutsAdd(enabled bool, val int64) {
	addInt(enabled, numPuts, val)
}

func NumMemtableGetsAdd(enabled bool, val int64) {
	addInt(enabled, numMemtableGets, val)
}

func NumCompactionTablesAdd(enabled bool, val int64) {
	addInt(enabled, numCompactionTables, val)
}

func LSMSizeSet(enabled bool, key string, val expvar.Var) {
	storeToMap(enabled, lsmSize, key, val)
}

func VlogSizeSet(enabled bool, key string, val expvar.Var) {
	storeToMap(enabled, vlogSize, key, val)
}

func PendingWritesSet(enabled bool, key string, val expvar.Var) {
	storeToMap(enabled, pendingWrites, key, val)
}

func NumLSMBloomHitsAdd(enabled bool, key string, val int64) {
	addToMap(enabled, numLSMBloomHits, key, val)
}

func NumLSMGetsAdd(enabled bool, key string, val int64) {
	addToMap(enabled, numLSMGets, key, val)
}

func LSMSizeGet(enabled bool, key string) expvar.Var {
	return getFromMap(enabled, lsmSize, key)
}

func VlogSizeGet(enabled bool, key string) expvar.Var {
	return getFromMap(enabled, vlogSize, key)
}

func addInt(enabled bool, metric *expvar.Int, val int64) {
	if !enabled {
		return
	}

	metric.Add(val)
}

func addToMap(enabled bool, metric *expvar.Map, key string, val int64) {
	if !enabled {
		return
	}

	metric.Add(key, val)
}

func storeToMap(enabled bool, metric *expvar.Map, key string, val expvar.Var) {
	if !enabled {
		return
	}

	metric.Set(key, val)
}

func getFromMap(enabled bool, metric *expvar.Map, key string) expvar.Var {
	if !enabled {
		return nil
	}

	return metric.Get(key)
}
