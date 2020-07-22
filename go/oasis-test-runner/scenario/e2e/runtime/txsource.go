package runtime

import (
	"context"
	"crypto"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"os/exec"
	"strings"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	commonGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/txsource"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/txsource/workload"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	timeLimitShort = 3 * time.Minute
	timeLimitLong  = 6 * time.Hour

	nodeRestartIntervalLong = 2 * time.Minute
	livenessCheckInterval   = 1 * time.Minute
	txSourceGasPrice        = 1
)

// TxSourceMultiShort uses multiple workloads for a short time.
var TxSourceMultiShort scenario.Scenario = &txSourceImpl{
	runtimeImpl: *newRuntimeImpl("txsource-multi-short", "", nil),
	workloads: []string{
		workload.NameCommission,
		workload.NameDelegation,
		workload.NameOversized,
		workload.NameParallel,
		workload.NameQueries,
		workload.NameRegistration,
		workload.NameRuntime,
		workload.NameTransfer,
	},
	timeLimit:                         timeLimitShort,
	nodeRestartInterval:               nodeRestartIntervalLong,
	livenessCheckInterval:             livenessCheckInterval,
	consensusPruneDisabledProbability: 0.1,
	consensusPruneMinKept:             100,
	consensusPruneMaxKept:             200,
}

// TxSourceMulti uses multiple workloads.
var TxSourceMulti scenario.Scenario = &txSourceImpl{
	runtimeImpl: *newRuntimeImpl("txsource-multi", "", nil),
	workloads: []string{
		workload.NameCommission,
		workload.NameDelegation,
		workload.NameOversized,
		workload.NameParallel,
		workload.NameQueries,
		workload.NameRegistration,
		workload.NameRuntime,
		workload.NameTransfer,
	},
	timeLimit:                         timeLimitLong,
	nodeRestartInterval:               nodeRestartIntervalLong,
	livenessCheckInterval:             livenessCheckInterval,
	consensusPruneDisabledProbability: 0.1,
	consensusPruneMinKept:             100,
	consensusPruneMaxKept:             1000,
	// Nodes getting killed commonly result in corrupted tendermint WAL when the
	// node is restarted. Enable automatic corrupted WAL recovery for validator
	// nodes.
	tendermintRecoverCorruptedWAL: true,
}

type txSourceImpl struct { // nolint: maligned
	runtimeImpl

	workloads             []string
	timeLimit             time.Duration
	nodeRestartInterval   time.Duration
	livenessCheckInterval time.Duration

	consensusPruneDisabledProbability float32
	consensusPruneMinKept             int64
	consensusPruneMaxKept             int64

	tendermintRecoverCorruptedWAL bool

	rng  *rand.Rand
	seed string
}

func (sc *txSourceImpl) PreInit(childEnv *env.Env) error {
	// Generate a new random seed and log it so we can reproduce the run.
	// Use existing seed, if it already exists.
	if sc.seed == "" {
		rawSeed := make([]byte, 16)
		_, err := cryptoRand.Read(rawSeed)
		if err != nil {
			return fmt.Errorf("failed to generate random seed: %w", err)
		}
		sc.seed = hex.EncodeToString(rawSeed)

		sc.Logger.Info("using random seed",
			"seed", sc.seed,
		)
	}

	// Set up the deterministic random source.
	hash := crypto.SHA512
	src, err := drbg.New(hash, []byte(sc.seed), nil, []byte("txsource scenario"))
	if err != nil {
		return fmt.Errorf("failed to create random source: %w", err)
	}
	sc.rng = rand.New(mathrand.New(src))

	return nil
}

func (sc *txSourceImpl) generateConsensusFixture(f *oasis.ConsensusFixture) {
	// Randomize pruning configuration.
	p := sc.rng.Float32()
	switch {
	case p < sc.consensusPruneDisabledProbability:
		f.PruneNumKept = 0
	default:
		// [sc.consensusPruneMinKept, sc.consensusPruneMaxKept]
		f.PruneNumKept = uint64(sc.rng.Int63n(sc.consensusPruneMaxKept-sc.consensusPruneMinKept+1) + sc.consensusPruneMinKept)
	}
}

func (sc *txSourceImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}
	// Use deterministic identities as we need to allocate funds to nodes.
	f.Network.DeterministicIdentities = true
	f.Network.StakingGenesis = "tests/fixture-data/txsource/staking-genesis.json"

	if sc.nodeRestartInterval > 0 {
		// If node restarts enabled, do not enable round timeouts and
		// discrepancy log watchers.
		f.Network.DefaultLogWatcherHandlerFactories = []log.WatcherHandlerFactory{
			oasis.LogAssertNoRoundFailures(),
		}
	}

	// Disable CheckTx on the client node so we can submit invalid transactions.
	f.Clients[0].Consensus.DisableCheckTx = true

	// Use at least 4 validators so that consensus can keep making progress
	// when a node is being killed and restarted.
	f.Validators = []oasis.ValidatorFixture{
		{Entity: 1},
		{Entity: 1},
		{Entity: 1},
		{Entity: 1},
	}
	f.Keymanagers = []oasis.KeymanagerFixture{
		{Runtime: 0, Entity: 1},
		{Runtime: 0, Entity: 1},
	}

	// Update validators to require fee payments.
	for i := range f.Validators {
		f.Validators[i].Consensus.MinGasPrice = txSourceGasPrice
		f.Validators[i].Consensus.SubmissionGasPrice = txSourceGasPrice
		f.Validators[i].Consensus.TendermintRecoverCorruptedWAL = sc.tendermintRecoverCorruptedWAL
		sc.generateConsensusFixture(&f.Validators[i].Consensus)
	}
	// Update all other nodes to use a specific gas price.
	for i := range f.Keymanagers {
		f.Keymanagers[i].Consensus.SubmissionGasPrice = txSourceGasPrice
		sc.generateConsensusFixture(&f.Keymanagers[i].Consensus)
	}
	for i := range f.StorageWorkers {
		f.StorageWorkers[i].Consensus.SubmissionGasPrice = txSourceGasPrice
		sc.generateConsensusFixture(&f.StorageWorkers[i].Consensus)
	}
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].Consensus.SubmissionGasPrice = txSourceGasPrice
		sc.generateConsensusFixture(&f.ComputeWorkers[i].Consensus)
	}
	for i := range f.ByzantineNodes {
		f.ByzantineNodes[i].Consensus.SubmissionGasPrice = txSourceGasPrice
		sc.generateConsensusFixture(&f.ByzantineNodes[i].Consensus)
	}

	return f, nil
}

func (sc *txSourceImpl) manager(env *env.Env, errCh chan error) {
	// Make sure we exit when the environment gets torn down.
	stopCh := make(chan struct{})
	env.AddOnCleanup(func() { close(stopCh) })

	if sc.nodeRestartInterval > 0 {
		sc.Logger.Info("random node restarts enabled",
			"restart_interval", sc.nodeRestartInterval,
		)
	} else {
		sc.nodeRestartInterval = math.MaxInt64
	}

	// Randomize node order.
	var nodes []*oasis.Node
	// Keep one of each types of nodes always running.
	for _, v := range sc.Net.Validators()[1:] {
		nodes = append(nodes, &v.Node)
	}
	for _, s := range sc.Net.StorageWorkers()[1:] {
		nodes = append(nodes, &s.Node)
	}
	for _, c := range sc.Net.ComputeWorkers()[1:] {
		nodes = append(nodes, &c.Node)
	}
	for _, c := range sc.Net.Keymanagers()[1:] {
		nodes = append(nodes, &c.Node)
	}

	restartTicker := time.NewTicker(sc.nodeRestartInterval)
	defer restartTicker.Stop()

	livenessTicker := time.NewTicker(sc.livenessCheckInterval)
	defer livenessTicker.Stop()

	var nodeIndex int
	var lastHeight int64
	for {
		select {
		case <-stopCh:
			return
		case <-restartTicker.C:
			// Reshuffle nodes each time the counter wraps around.
			if nodeIndex == 0 {
				sc.rng.Shuffle(len(nodes), func(i, j int) {
					nodes[i], nodes[j] = nodes[j], nodes[i]
				})
			}

			// Choose a random node and restart it.
			node := nodes[nodeIndex]
			sc.Logger.Info("restarting node",
				"node", node.Name,
			)

			if err := node.Restart(); err != nil {
				sc.Logger.Error("failed to restart node",
					"node", node.Name,
					"err", err,
				)
				errCh <- err
				return
			}

			nodeIndex = (nodeIndex + 1) % len(nodes)
		case <-livenessTicker.C:
			// Check if consensus has made any progress.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			blk, err := sc.Net.Controller().Consensus.GetBlock(ctx, consensus.HeightLatest)
			cancel()
			if err != nil {
				sc.Logger.Warn("failed to query latest consensus block",
					"err", err,
				)
				continue
			}

			if blk.Height <= lastHeight {
				sc.Logger.Error("consensus hasn't made any progress since last liveness check",
					"last_height", lastHeight,
					"height", blk.Height,
				)
				errCh <- fmt.Errorf("consensus is dead")
				return
			}

			sc.Logger.Info("current consensus height",
				"height", blk.Height,
			)
			lastHeight = blk.Height
		}
	}
}

func (sc *txSourceImpl) startWorkload(childEnv *env.Env, errCh chan error, name string) error {
	sc.Logger.Info("starting workload",
		"name", name,
	)

	d, err := childEnv.NewSubDir(fmt.Sprintf("workload-%s", name))
	if err != nil {
		return err
	}

	w, err := d.NewLogWriter(fmt.Sprintf("workload-%s.log", name))
	if err != nil {
		return err
	}

	logFmt := logging.FmtJSON
	logLevel := logging.LevelDebug

	args := []string{
		"debug", "txsource",
		"--address", "unix:" + sc.Net.Clients()[0].SocketPath(),
		"--" + common.CfgDebugAllowTestKeys,
		"--" + common.CfgDataDir, d.String(),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--log.format", logFmt.String(),
		"--log.level", logLevel.String(),
		"--" + commonGrpc.CfgLogDebug,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
		"--" + workload.CfgRuntimeID, runtimeID.String(),
		"--" + txsource.CfgWorkload, name,
		"--" + txsource.CfgTimeLimit, sc.timeLimit.String(),
		"--" + txsource.CfgSeed, sc.seed,
	}
	nodeBinary := sc.Net.Config().NodeBinary

	cmd := exec.Command(nodeBinary, args...)
	cmd.SysProcAttr = env.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	sc.Logger.Info("launching workload binary",
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return err
	}

	go func() {
		errCh <- cmd.Wait()

		sc.Logger.Info("workload finished",
			"name", name,
		)
	}()

	return nil
}

func (sc *txSourceImpl) Clone() scenario.Scenario {
	return &txSourceImpl{
		runtimeImpl:                       *sc.runtimeImpl.Clone().(*runtimeImpl),
		workloads:                         sc.workloads,
		timeLimit:                         sc.timeLimit,
		nodeRestartInterval:               sc.nodeRestartInterval,
		livenessCheckInterval:             sc.livenessCheckInterval,
		consensusPruneDisabledProbability: sc.consensusPruneDisabledProbability,
		consensusPruneMinKept:             sc.consensusPruneMinKept,
		consensusPruneMaxKept:             sc.consensusPruneMaxKept,
		tendermintRecoverCorruptedWAL:     sc.tendermintRecoverCorruptedWAL,
		seed:                              sc.seed,
		// rng must always be reinitialized from seed by calling PreInit().
	}
}

func (sc *txSourceImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return fmt.Errorf("scenario net Start: %w", err)
	}

	// Wait for all nodes to be synced before we proceed.
	if err := sc.waitNodesSynced(); err != nil {
		return err
	}

	ctx := context.Background()

	sc.Logger.Info("waiting for network to come up")
	if err := sc.Net.Controller().WaitNodesRegistered(ctx, sc.Net.NumRegisterNodes()); err != nil {
		return fmt.Errorf("WaitNodesRegistered: %w", err)
	}

	// Start all configured workloads.
	errCh := make(chan error, len(sc.workloads)+2)
	for _, name := range sc.workloads {
		if err := sc.startWorkload(childEnv, errCh, name); err != nil {
			return fmt.Errorf("failed to start workload %s: %w", name, err)
		}
	}
	// Start background scenario manager.
	go sc.manager(childEnv, errCh)

	// Wait for any workload to terminate.
	var err error
	select {
	case err = <-sc.Net.Errors():
	case err = <-errCh:
	}
	if err != nil {
		return err
	}

	if err = sc.Net.CheckLogWatchers(); err != nil {
		return err
	}

	return nil
}
