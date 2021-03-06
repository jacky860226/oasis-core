package committee

import (
	"context"
	"fmt"

	"github.com/opentracing/opentracing-go"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

// unresolvedBatch is a batch that may still need to be resolved (fetched from storage).
type unresolvedBatch struct {
	// ioRoot is the I/O root from the transaction scheduler containing the inputs.
	ioRoot storage.Root
	// txnSchedSignatures is the transaction scheduler signature of the dispatched batch.
	txnSchedSignature signature.Signature
	// storageSignatures are the storage node signatures of storage receipts for the I/O root.
	storageSignatures []signature.Signature

	batch   transaction.RawBatch
	spanCtx opentracing.SpanContext
}

func (ub *unresolvedBatch) String() string {
	return fmt.Sprintf("UnresolvedBatch{ioRoot: %s}", ub.ioRoot)
}

func (ub *unresolvedBatch) resolve(ctx context.Context, storage storage.Backend) (transaction.RawBatch, error) {
	if ub.batch != nil {
		// In case we already have a resolved batch, just return it.
		return ub.batch, nil
	}

	txs := transaction.NewTree(storage, ub.ioRoot)
	defer txs.Close()

	batch, err := txs.GetInputBatch(ctx)
	if err != nil || len(batch) == 0 {
		return nil, fmt.Errorf("failed to fetch inputs from storage: %w", err)
	}
	if len(batch) == 0 {
		return nil, fmt.Errorf("failed to fetch inputs from storage: batch is empty")
	}
	return batch, nil
}
