// Package staking implements the tendermint backed staking backend.
package staking

import (
	"bytes"
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/service"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
)

// ServiceClient is the scheduler service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type serviceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	service service.TendermintService
	querier *app.QueryFactory

	transferNotifier *pubsub.Broker
	burnNotifier     *pubsub.Broker
	escrowNotifier   *pubsub.Broker
	eventNotifier    *pubsub.Broker
}

func (sc *serviceClient) TokenSymbol(ctx context.Context) (string, error) {
	genesis, err := sc.service.GetGenesisDocument(ctx)
	if err != nil {
		return "", err
	}

	return genesis.Staking.TokenSymbol, nil
}

func (sc *serviceClient) TokenValueExponent(ctx context.Context) (uint8, error) {
	genesis, err := sc.service.GetGenesisDocument(ctx)
	if err != nil {
		return 0, err
	}

	return genesis.Staking.TokenValueExponent, nil
}

func (sc *serviceClient) TotalSupply(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.TotalSupply(ctx)
}

func (sc *serviceClient) CommonPool(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.CommonPool(ctx)
}

func (sc *serviceClient) LastBlockFees(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.LastBlockFees(ctx)
}

func (sc *serviceClient) Threshold(ctx context.Context, query *api.ThresholdQuery) (*quantity.Quantity, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Threshold(ctx, query.Kind)
}

func (sc *serviceClient) Addresses(ctx context.Context, height int64) ([]api.Address, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Addresses(ctx)
}

func (sc *serviceClient) Account(ctx context.Context, query *api.OwnerQuery) (*api.Account, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Account(ctx, query.Owner)
}

func (sc *serviceClient) Delegations(ctx context.Context, query *api.OwnerQuery) (map[api.Address]*api.Delegation, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Delegations(ctx, query.Owner)
}

func (sc *serviceClient) DebondingDelegations(ctx context.Context, query *api.OwnerQuery) (map[api.Address][]*api.DebondingDelegation, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.DebondingDelegations(ctx, query.Owner)
}

func (sc *serviceClient) WatchTransfers(ctx context.Context) (<-chan *api.TransferEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.TransferEvent)
	sub := sc.transferNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) WatchBurns(ctx context.Context) (<-chan *api.BurnEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.BurnEvent)
	sub := sc.burnNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) WatchEscrows(ctx context.Context) (<-chan *api.EscrowEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.EscrowEvent)
	sub := sc.escrowNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	// Query the staking genesis state.
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}
	genesis, err := q.Genesis(ctx)
	if err != nil {
		return nil, err
	}

	// Add static values to the genesis document.
	genesis.TokenSymbol, err = sc.TokenSymbol(ctx)
	if err != nil {
		return nil, err
	}
	genesis.TokenValueExponent, err = sc.TokenValueExponent(ctx)
	if err != nil {
		return nil, err
	}

	return genesis, nil
}

func (sc *serviceClient) GetEvents(ctx context.Context, height int64) ([]*api.Event, error) {
	// Get block results at given height.
	var results *tmrpctypes.ResultBlockResults
	results, err := sc.service.GetBlockResults(height)
	if err != nil {
		sc.logger.Error("failed to get tendermint block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	// Get transactions at given height.
	txns, err := sc.service.GetTransactions(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get tendermint transactions",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	var events []*api.Event
	// Decode events from block results.
	blockEvs, err := EventsFromTendermint(nil, results.Height, results.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	blockEvs, err = EventsFromTendermint(nil, results.Height, results.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for txIdx, txResult := range results.TxsResults {
		// The order of transactions in txns and results.TxsResults is
		// supposed to match, so the same index in both slices refers to the
		// same transaction.
		evs, txErr := EventsFromTendermint(txns[txIdx], results.Height, txResult.Events)
		if txErr != nil {
			return nil, txErr
		}
		events = append(events, evs...)
	}

	return events, nil
}

func (sc *serviceClient) WatchEvents(ctx context.Context) (<-chan *api.Event, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.Event)
	sub := sc.eventNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ConsensusParameters(ctx)
}

func (sc *serviceClient) Cleanup() {
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []tmpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(ctx context.Context, height int64, tx tmtypes.Tx, ev *tmabcitypes.Event) error {
	events, err := EventsFromTendermint(tx, height, []tmabcitypes.Event{*ev})
	if err != nil {
		return fmt.Errorf("staking: failed to process tendermint events: %w", err)
	}

	// Notify subscribers of events.
	for _, ev := range events {
		if ev.Transfer != nil {
			sc.transferNotifier.Broadcast(ev.Transfer)
		}
		if ev.Escrow != nil {
			sc.escrowNotifier.Broadcast(ev.Escrow)
		}
		if ev.Burn != nil {
			sc.burnNotifier.Broadcast(ev.Burn)
		}
		sc.eventNotifier.Broadcast(ev)
	}

	return nil
}

// EventsFromTendermint extracts staking events from tendermint events.
func EventsFromTendermint(
	tx tmtypes.Tx,
	height int64,
	tmEvents []tmabcitypes.Event,
) ([]*api.Event, error) {
	var txHash hash.Hash
	switch tx {
	case nil:
		txHash.Empty()
	default:
		txHash = hash.NewFromBytes(tx)
	}

	var events []*api.Event
	var errs error
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the staking app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case bytes.Equal(key, app.KeyTakeEscrow):
				// Take escrow event.
				var e api.TakeEscrowEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt TakeEscrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{Take: &e}}
				events = append(events, evt)
			case bytes.Equal(key, app.KeyTransfer):
				// Transfer event.
				var e api.TransferEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt Transfer event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Transfer: &e}
				events = append(events, evt)
			case bytes.Equal(key, app.KeyReclaimEscrow):
				// Reclaim escrow event.
				var e api.ReclaimEscrowEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt ReclaimEscrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{Reclaim: &e}}
				events = append(events, evt)
			case bytes.Equal(key, app.KeyAddEscrow):
				// Add escrow event.
				var e api.AddEscrowEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt AddEscrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{Add: &e}}
				events = append(events, evt)
			case bytes.Equal(key, app.KeyBurn):
				// Burn event.
				var e api.BurnEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("staking: corrupt Burn event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Burn: &e}
				events = append(events, evt)
			default:
				errs = multierror.Append(errs, fmt.Errorf("staking: unknown event type: key: %s, val: %s", key, val))
			}
		}
	}

	return events, errs
}

// New constructs a new tendermint backed staking Backend instance.
func New(ctx context.Context, service service.TendermintService) (ServiceClient, error) {
	// Initialize and register the tendermint service component.
	a := app.New()
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	// Configure the staking application as a fee handler.
	if err := service.SetTransactionAuthHandler(a.(abci.TransactionAuthHandler)); err != nil {
		return nil, err
	}

	return &serviceClient{
		logger:           logging.GetLogger("staking/tendermint"),
		service:          service,
		querier:          a.QueryFactory().(*app.QueryFactory),
		transferNotifier: pubsub.NewBroker(false),
		burnNotifier:     pubsub.NewBroker(false),
		escrowNotifier:   pubsub.NewBroker(false),
		eventNotifier:    pubsub.NewBroker(false),
	}, nil
}
