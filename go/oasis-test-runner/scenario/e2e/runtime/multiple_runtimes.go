package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const (
	// cfgNumComputeRuntimes is the number of runtimes, all with common runtimeBinary registered.
	cfgNumComputeRuntimes = "num_compute_runtimes"
	// cfgNumComputeRuntimeTxns is the number of insert test transactions sent to each runtime.
	cfgNumComputeRuntimeTxns = "num_compute_runtime_txns"
	// cfgNumComputeWorkers is the number of compute workers.
	cfgNumComputeWorkers = "num_compute_workers"
	// cfgExecutorGroupSize is the number of executor nodes.
	cfgExecutorGroupSize = "executor_group_size"
)

// MultipleRuntimes is a scenario which tests running multiple runtimes on one node.
var MultipleRuntimes = func() scenario.Scenario {
	sc := &multipleRuntimesImpl{
		runtimeImpl: *newRuntimeImpl("multiple-runtimes", "simple-keyvalue-client", nil),
	}
	sc.Flags.Int(cfgNumComputeRuntimes, 2, "number of compute runtimes per worker")
	sc.Flags.Int(cfgNumComputeRuntimeTxns, 2, "number of transactions to perform")
	sc.Flags.Int(cfgNumComputeWorkers, 2, "number of workers to initiate")
	sc.Flags.Int(cfgExecutorGroupSize, 2, "number of executor workers in committee")

	return sc
}()

type multipleRuntimesImpl struct {
	runtimeImpl
}

func (sc *multipleRuntimesImpl) Clone() scenario.Scenario {
	return &multipleRuntimesImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *multipleRuntimesImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Remove existing compute runtimes from fixture, remember RuntimeID and
	// binary from the first one.
	var id common.Namespace
	var runtimeBinary string
	var rts []oasis.RuntimeFixture
	for _, rt := range f.Runtimes {
		if rt.Kind == registry.KindCompute {
			if runtimeBinary == "" {
				copy(id[:], rt.ID[:])
				runtimeBinary = rt.Binaries[0]
			}
		} else {
			rts = append(rts, rt)
		}
	}
	f.Runtimes = rts

	// Avoid unexpected blocks.
	f.Network.EpochtimeMock = true

	// Add some more consecutive runtime IDs with the same binary.
	numComputeRuntimes, _ := sc.Flags.GetInt(cfgNumComputeRuntimes)
	executorGroupSize, _ := sc.Flags.GetInt(cfgExecutorGroupSize)
	for i := 1; i <= numComputeRuntimes; i++ {
		// Increase LSB by 1.
		id[len(id)-1]++

		newRtFixture := oasis.RuntimeFixture{
			ID:         id,
			Kind:       registry.KindCompute,
			Entity:     0,
			Keymanager: 0,
			Binaries:   []string{runtimeBinary},
			Executor: registry.ExecutorParameters{
				GroupSize:       uint64(executorGroupSize),
				GroupBackupSize: 0,
				RoundTimeout:    10 * time.Second,
			},
			Merge: registry.MergeParameters{
				GroupSize:       1,
				GroupBackupSize: 0,
				RoundTimeout:    10 * time.Second,
			},
			TxnScheduler: registry.TxnSchedulerParameters{
				Algorithm:         registry.TxnSchedulerAlgorithmBatching,
				GroupSize:         1,
				MaxBatchSize:      1,
				MaxBatchSizeBytes: 1000,
				BatchFlushTimeout: 1 * time.Second,
			},
			Storage: registry.StorageParameters{
				GroupSize:               1,
				MinWriteReplication:     1,
				MaxApplyWriteLogEntries: 100_000,
				MaxApplyOps:             2,
				MaxMergeRoots:           8,
				MaxMergeOps:             2,
			},
			AdmissionPolicy: registry.RuntimeAdmissionPolicy{
				AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
			},
		}

		f.Runtimes = append(f.Runtimes, newRtFixture)
	}

	// Use numComputeWorkers compute worker fixtures.
	numComputeWorkers, _ := sc.Flags.GetInt(cfgNumComputeWorkers)
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}
	for i := 0; i < numComputeWorkers; i++ {
		f.ComputeWorkers = append(f.ComputeWorkers, oasis.ComputeWorkerFixture{Entity: 1})
	}

	return f, nil
}

func (sc *multipleRuntimesImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	// Wait for the nodes.
	if err := sc.initialEpochTransitions(); err != nil {
		return err
	}

	ctx := context.Background()

	// Submit transactions.
	epoch := epochtime.EpochTime(3)
	numComputeRuntimeTxns, _ := sc.Flags.GetInt(cfgNumComputeRuntimeTxns)
	for _, r := range sc.Net.Runtimes() {
		rt := r.ToRuntimeDescriptor()
		if rt.Kind == registry.KindCompute {
			for i := 0; i < numComputeRuntimeTxns; i++ {
				sc.Logger.Info("submitting transaction to runtime",
					"seq", i,
					"runtime_id", rt.ID,
				)

				if err := sc.submitKeyValueRuntimeInsertTx(ctx, rt.ID, "hello", fmt.Sprintf("world at iteration %d from %s", i, rt.ID)); err != nil {
					return err
				}

				sc.Logger.Info("triggering epoch transition",
					"epoch", epoch,
				)
				if err := sc.Net.Controller().SetEpoch(context.Background(), epoch); err != nil {
					return fmt.Errorf("failed to set epoch: %w", err)
				}
				sc.Logger.Info("epoch transition done")
				epoch++
			}
		}
	}

	return nil
}
