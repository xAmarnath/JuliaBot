package mongostore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrBucketNotFound = errors.New("bucket not found")
var ErrReadOnly = errors.New("read-only transaction")

type DB struct {
	client     *mongo.Client
	collection *mongo.Collection
	writeMu    sync.Mutex
	cacheMu    sync.RWMutex
	records    map[string]Record
	children   map[string]map[string]struct{}
	cacheErr   error
	closed     bool
	commit     func(context.Context, []mongo.WriteModel) (bool, error)
}
type Record struct {
	ID       string `bson:"_id"`
	Parent   string `bson:"parent"`
	Key      []byte `bson:"key"`
	Value    []byte `bson:"value,omitempty"`
	Bucket   bool   `bson:"bucket"`
	Sequence uint64 `bson:"sequence,omitempty"`
}
type Tx struct {
	db       *DB
	ctx      context.Context
	writable bool
	err      error
	changes  map[string]*Record // nil entries delete records; published only after commit.
}
type Bucket struct {
	tx   *Tx
	path string
}
type BucketStats struct{ KeyN int }
type Cursor struct {
	bucket  *Bucket
	records []Record
	index   int
}

func Open(uri, name, collection string) (*DB, error) {
	if uri == "" {
		return nil, errors.New("MONGODB_URI is required")
	}
	if name == "" || strings.ContainsAny(name, " /\\.\"$\x00") {
		return nil, errors.New("invalid MongoDB database name")
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetAppName("juliabot").SetServerSelectionTimeout(10 * time.Second).SetConnectTimeout(10 * time.Second).SetTimeout(20 * time.Second))
	if err != nil {
		return nil, errors.New("invalid MongoDB connection configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("MongoDB connection failed: %w", err)
	}
	d := &DB{client: client, collection: client.Database(name).Collection(collection)}
	_, err = d.collection.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "parent", Value: 1}}})
	if err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}
	d.commit = d.persist
	if err := d.reload(ctx); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("load MongoDB cache: %w", err)
	}
	return d, nil
}
func (d *DB) Close() error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	d.cacheMu.Lock()
	d.closed = true
	d.cacheMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.client.Disconnect(ctx)
}
func (d *DB) View(fn func(*Tx) error) error   { return d.run(false, fn) }
func (d *DB) Update(fn func(*Tx) error) error { return d.run(true, fn) }
func (d *DB) run(write bool, fn func(*Tx) error) error {
	if !write {
		d.cacheMu.RLock()
		defer d.cacheMu.RUnlock()
		if err := d.available(); err != nil {
			return err
		}
		tx := &Tx{db: d}
		err := fn(tx)
		if tx.err != nil {
			return tx.err
		}
		return err
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Do not resume from an uncertain commit using a potentially stale read.
	// Stop serving cached records until the process is restarted.
	if d.closed {
		return errors.New("database closed")
	}
	if d.cacheErr != nil {
		return d.cacheErr
	}
	tx := &Tx{db: d, ctx: ctx, writable: true, changes: make(map[string]*Record)}
	if err := fn(tx); err != nil {
		return err
	}
	if tx.err != nil {
		return tx.err
	}
	if len(tx.changes) == 0 {
		return nil
	}
	models := make([]mongo.WriteModel, 0, len(tx.changes))
	for id, r := range tx.changes {
		if r == nil {
			models = append(models, mongo.NewDeleteOneModel().SetFilter(bson.M{"_id": id}))
		} else {
			models = append(models, mongo.NewReplaceOneModel().SetFilter(bson.M{"_id": id}).SetReplacement(r).SetUpsert(true))
		}
	}
	uncertain, err := d.commit(ctx, models)
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	if err != nil {
		if uncertain {
			d.cacheErr = fmt.Errorf("MongoDB commit outcome unknown; restart required: %w", err)
		}
		return err
	}
	for id, r := range tx.changes {
		if old, ok := d.records[id]; ok {
			delete(d.children[old.Parent], id)
		}
		if r == nil {
			delete(d.records, id)
			delete(d.children, id)
		} else {
			d.records[id] = *r
			if d.children[r.Parent] == nil {
				d.children[r.Parent] = make(map[string]struct{})
			}
			d.children[r.Parent][id] = struct{}{}
		}
	}
	return nil
}

// The cache belongs to one bot process. Start-up loads MongoDB;
// ordinary reads never perform network I/O. External edits require a restart.
func (d *DB) available() error {
	if d.closed {
		return errors.New("database closed")
	}
	return d.cacheErr
}

func (d *DB) reload(ctx context.Context) error {
	cur, err := d.collection.Find(ctx, bson.M{})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	records := make(map[string]Record)
	children := make(map[string]map[string]struct{})
	for cur.Next(ctx) {
		var r Record
		if err := cur.Decode(&r); err != nil {
			return err
		}
		records[r.ID] = r
		if children[r.Parent] == nil {
			children[r.Parent] = make(map[string]struct{})
		}
		children[r.Parent][r.ID] = struct{}{}
	}
	if err := cur.Err(); err != nil {
		return err
	}
	d.cacheMu.Lock()
	d.records, d.children, d.cacheErr = records, children, nil
	d.cacheMu.Unlock()
	return nil
}

func (d *DB) persist(ctx context.Context, models []mongo.WriteModel) (bool, error) {
	s, err := d.client.StartSession()
	if err != nil {
		return false, err
	}
	defer s.EndSession(ctx)
	uncertain := false
	err = mongo.WithSession(ctx, s, func(ctx context.Context) error {
		if err := s.StartTransaction(options.Transaction().SetReadConcern(readconcern.Snapshot()).SetWriteConcern(writeconcern.Majority())); err != nil {
			return err
		}
		defer s.AbortTransaction(ctx)
		if _, err := d.collection.BulkWrite(ctx, models); err != nil {
			return err
		}
		uncertain = true
		for {
			err = s.CommitTransaction(ctx)
			var se mongo.ServerError
			if !errors.As(err, &se) || !se.HasErrorLabel("UnknownTransactionCommitResult") || ctx.Err() != nil {
				return err
			}
		}
	})
	return uncertain && err != nil, err
}
func Path(parent string, key []byte) string { return parent + "/" + hex.EncodeToString(key) }
func (tx *Tx) fail(err error) error {
	if err != nil && tx.err == nil {
		tx.err = err
	}
	return err
}
func (tx *Tx) root() *Bucket             { return &Bucket{tx: tx} }
func (tx *Tx) Bucket(key []byte) *Bucket { return tx.root().Bucket(key) }
func (tx *Tx) CreateBucketIfNotExists(key []byte) (*Bucket, error) {
	return tx.root().CreateBucketIfNotExists(key)
}
func (tx *Tx) DeleteBucket(key []byte) error { return tx.root().DeleteBucket(key) }
func (b *Bucket) record(key []byte) (*Record, error) {
	if b.tx.err != nil {
		return nil, b.tx.err
	}
	return b.tx.record(Path(b.path, key)), nil
}
func (tx *Tx) record(id string) *Record {
	if r, ok := tx.changes[id]; ok {
		return r
	}
	r, ok := tx.db.records[id]
	if !ok {
		return nil
	}
	return &r
}
func (b *Bucket) Bucket(key []byte) *Bucket {
	r, err := b.record(key)
	if err != nil {
		return &Bucket{tx: b.tx, path: Path(b.path, key)}
	}
	if r == nil || !r.Bucket {
		return nil
	}
	return &Bucket{tx: b.tx, path: r.ID}
}
func (b *Bucket) CreateBucketIfNotExists(key []byte) (*Bucket, error) {
	if !b.tx.writable {
		return nil, ErrReadOnly
	}
	if len(key) == 0 {
		return nil, errors.New("empty bucket name")
	}
	r, err := b.record(key)
	if err != nil {
		return nil, err
	}
	if r != nil {
		if !r.Bucket {
			return nil, errors.New("key contains a value")
		}
		return &Bucket{tx: b.tx, path: r.ID}, nil
	}
	r = &Record{ID: Path(b.path, key), Parent: b.path, Key: bytes.Clone(key), Bucket: true}
	b.tx.changes[r.ID] = r
	return &Bucket{tx: b.tx, path: r.ID}, nil
}
func (b *Bucket) Get(key []byte) []byte {
	r, err := b.record(key)
	if err != nil || r == nil || r.Bucket {
		return nil
	}
	if r.Value == nil {
		return []byte{}
	}
	return bytes.Clone(r.Value)
}
func (b *Bucket) Put(key, value []byte) error {
	if !b.tx.writable {
		return ErrReadOnly
	}
	if len(key) == 0 {
		return errors.New("empty key")
	}
	r, err := b.record(key)
	if err != nil {
		return err
	}
	if r != nil && r.Bucket {
		return errors.New("key contains a bucket")
	}
	id := Path(b.path, key)
	b.tx.changes[id] = &Record{ID: id, Parent: b.path, Key: bytes.Clone(key), Value: bytes.Clone(value)}
	return nil
}
func (b *Bucket) Delete(key []byte) error {
	if !b.tx.writable {
		return ErrReadOnly
	}
	r, err := b.record(key)
	if err != nil {
		return err
	}
	if r != nil && r.Bucket {
		return errors.New("key contains a bucket")
	}
	b.tx.changes[Path(b.path, key)] = nil
	return nil
}
func (b *Bucket) DeleteBucket(key []byte) error {
	if !b.tx.writable {
		return ErrReadOnly
	}
	child := b.Bucket(key)
	if b.tx.err != nil {
		return b.tx.err
	}
	if child == nil {
		return ErrBucketNotFound
	}
	for id := range b.tx.db.records {
		if id == child.path || strings.HasPrefix(id, child.path+"/") {
			b.tx.changes[id] = nil
		}
	}
	for id := range b.tx.changes {
		if id == child.path || strings.HasPrefix(id, child.path+"/") {
			b.tx.changes[id] = nil
		}
	}
	return nil
}
func (b *Bucket) Sequence() uint64 {
	r := b.tx.record(b.path)
	if r == nil {
		b.tx.fail(ErrBucketNotFound)
		return 0
	}
	return r.Sequence
}
func (b *Bucket) SetSequence(n uint64) error {
	if !b.tx.writable {
		return ErrReadOnly
	}
	if n > math.MaxInt64 {
		return errors.New("sequence exceeds MongoDB integer range")
	}
	r := b.tx.record(b.path)
	if r == nil {
		return b.tx.fail(ErrBucketNotFound)
	}
	cp := *r
	cp.Sequence = n
	b.tx.changes[b.path] = &cp
	return nil
}
func (b *Bucket) NextSequence() (uint64, error) {
	n := b.Sequence()
	if b.tx.err != nil {
		return 0, b.tx.err
	}
	if n >= math.MaxInt64 {
		return 0, errors.New("sequence exhausted")
	}
	return n + 1, b.SetSequence(n + 1)
}
func (b *Bucket) Cursor() *Cursor {
	c := &Cursor{bucket: b, index: -1}
	if b.tx.err != nil {
		return c
	}
	for id := range b.tx.db.children[b.path] {
		if _, changed := b.tx.changes[id]; !changed {
			c.records = append(c.records, b.tx.db.records[id])
		}
	}
	for _, r := range b.tx.changes {
		if r != nil && r.Parent == b.path {
			c.records = append(c.records, *r)
		}
	}
	sort.Slice(c.records, func(i, j int) bool { return bytes.Compare(c.records[i].Key, c.records[j].Key) < 0 })
	return c
}
func (c *Cursor) at(n int) ([]byte, []byte) {
	c.index = n
	if n < 0 || n >= len(c.records) {
		return nil, nil
	}
	r := c.records[n]
	if r.Bucket {
		return bytes.Clone(r.Key), nil
	}
	if r.Value == nil {
		return bytes.Clone(r.Key), []byte{}
	}
	return bytes.Clone(r.Key), bytes.Clone(r.Value)
}
func (c *Cursor) First() ([]byte, []byte) { return c.at(0) }
func (c *Cursor) Last() ([]byte, []byte)  { return c.at(len(c.records) - 1) }
func (c *Cursor) Next() ([]byte, []byte)  { return c.at(c.index + 1) }
func (c *Cursor) Prev() ([]byte, []byte)  { return c.at(c.index - 1) }
func (c *Cursor) Seek(key []byte) ([]byte, []byte) {
	return c.at(sort.Search(len(c.records), func(i int) bool { return bytes.Compare(c.records[i].Key, key) >= 0 }))
}
func (c *Cursor) Delete() error {
	if c.index < 0 || c.index >= len(c.records) {
		return nil
	}
	return c.bucket.Delete(c.records[c.index].Key)
}
func (b *Bucket) ForEach(fn func([]byte, []byte) error) error {
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return b.tx.err
}
func (b *Bucket) Stats() BucketStats {
	n := len(b.tx.db.children[b.path])
	for id, r := range b.tx.changes {
		if old, ok := b.tx.db.records[id]; ok && old.Parent == b.path {
			n--
		}
		if r != nil && r.Parent == b.path {
			n++
		}
	}
	return BucketStats{KeyN: n}
}
