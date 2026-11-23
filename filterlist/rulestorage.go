package filterlist

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/c2h5oh/datasize"
)

// defaultRuleCacheSize is the maximum number of parsed rules retained in
// [RuleStorage.cache].  Bounding the cache prevents unbounded heap growth over
// long uptimes caused by shortcut false positives.
const defaultRuleCacheSize = 8192

// ruleCacheEntry is a single slot in [ruleCache].
type ruleCacheEntry struct {
	rule    rules.Rule
	id      StorageID
	visited atomic.Bool
}

// ruleCache is a bounded, concurrency-safe CLOCK cache mapping [StorageID] to
// parsed [rules.Rule] values.  Cache hits take only a read lock and perform
// zero allocations.
type ruleCache struct {
	index   map[StorageID]int
	entries []ruleCacheEntry
	mu      sync.RWMutex
	hand    int
	cap     int
}

// newRuleCache creates a bounded rule cache with the given capacity.  Returns
// nil if capacity <= 0.
func newRuleCache(capacity int) (c *ruleCache) {
	if capacity <= 0 {
		return nil
	}

	return &ruleCache{
		index: map[StorageID]int{},
		cap:   capacity,
	}
}

// load returns the cached rule for id, if present.
func (c *ruleCache) load(id StorageID) (r rules.Rule, ok bool) {
	c.mu.RLock()
	idx, ok := c.index[id]
	if ok {
		e := &c.entries[idx]
		r = e.rule
		if !e.visited.Load() {
			e.visited.Store(true)
		}
	}
	c.mu.RUnlock()

	return r, ok
}

// store inserts r under id, evicting an unvisited entry if the cache is full.
func (c *ruleCache) store(id StorageID, r rules.Rule) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if idx, ok := c.index[id]; ok {
		c.entries[idx].rule = r
		c.entries[idx].visited.Store(true)

		return
	}

	if len(c.entries) < c.cap {
		if c.entries == nil {
			// Allocate to exact capacity lazily so atomic.Bool elements in
			// ruleCacheEntry are never copied by slice growth.
			c.entries = make([]ruleCacheEntry, 0, c.cap)
		}

		idx := len(c.entries)
		c.entries = append(c.entries, ruleCacheEntry{
			rule: r,
			id:   id,
		})
		c.entries[idx].visited.Store(true)
		c.index[id] = idx

		return
	}

	for c.entries[c.hand].visited.Swap(false) {
		c.hand++
		if c.hand == c.cap {
			c.hand = 0
		}
	}

	evict := &c.entries[c.hand]
	delete(c.index, evict.id)

	evict.id = id
	evict.rule = r
	evict.visited.Store(true)
	c.index[id] = c.hand

	c.hand++
	if c.hand == c.cap {
		c.hand = 0
	}
}

// RuleStorage is an abstraction that combines several rule lists.  It can be
// scanned using a [RuleStorageScanner], and also it allows retrieving rules by
// its index.
//
// The idea is to keep rules in a serialized format (even original format in the
// case of [File]) and create them in a lazy manner only when we really need
// them.  When the filtering engine is being initialized, we need to scan the
// rule lists once in order to fill up the index.  We use rule indexes as a
// unique rule identifier instead of the rule itself.  The rule is created (see
// [RuleStorage.RetrieveRule]) only when there's a chance that it's needed.
type RuleStorage struct {
	// cache with the rules which were retrieved.  The key is the storage index
	// and the value is the rule.  cache can be nil only in tests.
	cache *ruleCache

	// listIdxByListID is the index of lists by their indexes in
	// [RuleStorage.lists].
	listIdxByListID map[rules.ListID]uint64

	// lists is an array of rules lists which can be accessed using this
	// RuleStorage.
	lists []Interface

	// sizeEst is the size estimate of all rule-lists in the storage.
	sizeEst datasize.ByteSize
}

// NewRuleStorage creates a new instance of the [*RuleStorage] and validates the
// list of rules specified.
func NewRuleStorage(lists []Interface) (s *RuleStorage, err error) {
	var sizeEst datasize.ByteSize
	index := make(map[rules.ListID]uint64, len(lists))
	for i, l := range lists {
		id := l.ListID()
		if _, ok := index[id]; ok {
			return nil, fmt.Errorf("at index %d: id: %w: %d", i, errors.ErrDuplicated, id)
		}

		// #nosec G115 -- Slice indexes cannot be negative.
		index[id] = uint64(i)
		sizeEst += l.SizeEstimate()
	}

	return &RuleStorage{
		cache:           newRuleCache(defaultRuleCacheSize),
		listIdxByListID: index,
		lists:           lists,
		sizeEst:         sizeEst,
	}, nil
}

// NewRuleStorageScanner creates a new instance of RuleStorageScanner.  It can
// be used to read and parse all the storage contents.
func (s *RuleStorage) NewRuleStorageScanner() (sc *RuleStorageScanner) {
	var scanners []*RuleScanner
	for _, list := range s.lists {
		scanner := list.NewScanner()
		scanners = append(scanners, scanner)
	}

	return &RuleStorageScanner{
		Scanners: scanners,
	}
}

// RetrieveRule looks for the filtering rule in this storage.  id is the storage
// ID as received from the scanner.
func (s *RuleStorage) RetrieveRule(id StorageID) (r rules.Rule, err error) {
	if s.cache != nil {
		var ok bool
		r, ok = s.cache.load(id)
		if ok {
			return r, nil
		}
	}

	listIdx, ok := s.listIdxByListID[id.listID]
	if !ok {
		return nil, fmt.Errorf("list %d does not exist", id.listID)
	}

	list := s.lists[listIdx]
	r, err = list.RetrieveRule(id.ruleIdx)
	if r != nil && s.cache != nil {
		s.cache.store(id, r)
	}

	return r, err
}

// RetrieveNetworkRule is a helper method that retrieves a network rule from the
// storage.  It returns a pointer to the rule or nil in any other case (not
// found or error).
//
// TODO(a.garipov):  Rewrite into a helper function instead of a method and
// return the error.
func (s *RuleStorage) RetrieveNetworkRule(id StorageID) (nr *rules.NetworkRule) {
	r, err := s.RetrieveRule(id)
	if err != nil {
		// TODO(a.garipov):  Add better support for log/slog.
		slog.Error("cannot retrieve network rule", "id", id, slogutil.KeyError, err)

		return nil
	}

	nr, _ = r.(*rules.NetworkRule)

	return nr
}

// RetrieveHostRule is a helper method that retrieves a host rule from the
// storage.  It returns a pointer to the rule or nil in any other case (not
// found or error).
//
// TODO(a.garipov):  Rewrite into a helper function instead of a method and
// return the error.
func (s *RuleStorage) RetrieveHostRule(id StorageID) (hr *rules.HostRule) {
	r, err := s.RetrieveRule(id)
	if err != nil {
		// TODO(a.garipov):  Add better support for log/slog.
		slog.Error("cannot retrieve host rule", "id", id, slogutil.KeyError, err)

		return nil
	}

	hr, _ = r.(*rules.HostRule)

	return hr
}

// SizeEstimate returns the size estimate of all rule-lists in the storage.
func (s *RuleStorage) SizeEstimate() (est datasize.ByteSize) {
	return s.sizeEst
}

// Close closes the storage instance.
func (s *RuleStorage) Close() (err error) {
	if len(s.lists) == 0 {
		return nil
	}

	var errs []error
	for _, l := range s.lists {
		err = l.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Annotate(errors.Join(errs...), "closing rule lists: %w")
}
