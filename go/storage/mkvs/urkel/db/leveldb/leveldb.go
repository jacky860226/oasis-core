// Package leveldb provides a LevelDB-backed node database.
package leveldb

import (
	"context"
	"errors"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

var (
	_ api.NodeDB = (*leveldbNodeDB)(nil)

	nodeKeyPrefix     = []byte{'N'}
	writeLogKeyPrefix = []byte{'L'}
)

func makeWriteLogKey(startRoot node.Root, endRoot node.Root) []byte {
	return append(append(writeLogKeyPrefix, startRoot.Hash[:]...), endRoot.Hash[:]...)
}

type leveldbNodeDB struct {
	db *leveldb.DB

	closeOnce sync.Once
}

// New creates a new LevelDB-backed node database.
func New(dirname string) (api.NodeDB, error) {
	db, err := leveldb.OpenFile(dirname, nil)
	if err != nil {
		return nil, err
	}

	return &leveldbNodeDB{db: db}, nil
}

func (d *leveldbNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel/db/leveldb: attempted to get invalid pointer from node database")
	}

	bytes, err := d.db.Get(append(nodeKeyPrefix, ptr.Hash[:]...), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			err = api.ErrNodeNotFound
		}
		return nil, err
	}

	return node.UnmarshalBinary(bytes)
}

func (d *leveldbNodeDB) GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (api.WriteLogIterator, error) {
	if !endRoot.Follows(&startRoot) {
		return nil, errors.New("urkel/db/leveldb: end root must follow start root")
	}

	bytes, err := d.db.Get(makeWriteLogKey(startRoot, endRoot), nil)
	if err != nil {
		return nil, err
	}

	var log api.HashedDBWriteLog
	if err := cbor.Unmarshal(bytes, &log); err != nil {
		return nil, err
	}

	return api.ReviveHashedDBWriteLog(ctx, log, func(h hash.Hash) (*node.LeafNode, error) {
		leaf, err := d.GetNode(endRoot, &node.Pointer{Hash: h, Clean: true})
		if err != nil {
			return nil, err
		}
		return leaf.(*node.LeafNode), nil
	})
}

func (d *leveldbNodeDB) HasRoot(root node.Root) bool {
	_, err := d.GetNode(root, &node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	})
	return err != api.ErrNodeNotFound
}

func (d *leveldbNodeDB) Close() {
	d.closeOnce.Do(func() {
		_ = d.db.Close()
	})
}

type leveldbBatch struct {
	api.BaseBatch

	db  *leveldbNodeDB
	bat *leveldb.Batch
}

func (d *leveldbNodeDB) NewBatch() api.Batch {
	return &leveldbBatch{
		db:  d,
		bat: new(leveldb.Batch),
	}
}

func (b *leveldbBatch) MaybeStartSubtree(subtree api.Subtree, depth uint8, subtreeRoot *node.Pointer) api.Subtree {
	if subtree == nil {
		return &leveldbSubtree{batch: b}
	}
	return subtree
}

func (b *leveldbBatch) PutWriteLog(
	startRoot node.Root,
	endRoot node.Root,
	writeLog writelog.WriteLog,
	annotations writelog.WriteLogAnnotations,
) error {
	if !endRoot.Follows(&startRoot) {
		return errors.New("urkel/db/leveldb: end root must follow start root")
	}

	log := api.MakeHashedDBWriteLog(writeLog, annotations)
	bytes := cbor.Marshal(log)
	b.bat.Put(makeWriteLogKey(startRoot, endRoot), bytes)
	return nil
}

func (b *leveldbBatch) Commit(root node.Root) error {
	if err := b.db.db.Write(b.bat, &opt.WriteOptions{Sync: true}); err != nil {
		return err
	}

	b.Reset()

	return b.BaseBatch.Commit(root)
}

func (b *leveldbBatch) Reset() {
	b.bat.Reset()
}

type leveldbSubtree struct {
	batch *leveldbBatch
}

func (s *leveldbSubtree) PutNode(depth uint8, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	h := ptr.Node.GetHash()
	s.batch.bat.Put(append(nodeKeyPrefix, h[:]...), data)
	return nil
}

func (s *leveldbSubtree) VisitCleanNode(depth uint8, ptr *node.Pointer) error {
	return nil
}

func (s *leveldbSubtree) Commit() error {
	return nil
}