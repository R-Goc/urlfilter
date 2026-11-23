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

// DefaultRuleCacheSize is the default maximum number of parsed rules retained
// in [RuleStorage.cache].  Bounding the cache prevents unbounded heap growth
// over long uptimes while keeping hot rules in memory.
const DefaultRuleCacheSize = 16384

const (
	// ruleCacheWays is the associativity of each set in [ruleCache].
	ruleCacheWays    = 8
	ruleCacheWayMask = ruleCacheWays - 1

	// maxRuleCacheSets caps the number of 8-way sets to prevent int overflow on
	// 32-bit platforms (1<<20 sets = 8,388,608 entries).
	maxRuleCacheSets = 1 << 20

	ruleCacheHashMul1 = uint64(0x9e3779b97f4a7c15)
	ruleCacheHashMul2 = uint64(0xbf58476d1ce4e5b9)
)

// ruleCacheSet is an 8-way set-associative CLOCK cache set with its own lock
// so concurrent lookups across different sets do not contend.
type ruleCacheSet struct {
	ids     [ruleCacheWays]StorageID
	rules   [ruleCacheWays]rules.Rule
	visited [ruleCacheWays]atomic.Bool
	mu      sync.RWMutex
	hand    uint8
}

// ruleCache is a bounded, concurrency-safe 8-way set-associative CLOCK cache
// mapping [StorageID] to parsed [rules.Rule] values without a Go map.
type ruleCache struct {
	sets     atomic.Pointer[[]ruleCacheSet]
	initOnce sync.Once
	mask     uint64
	numSets  int
}

// newRuleCache creates a bounded 8-way set-associative rule cache sized to at
// least capacity entries (rounded up to a power-of-2 number of 8-way sets).
// Returns nil if capacity <= 0.
func newRuleCache(capacity int) (c *ruleCache) {
	if capacity <= 0 {
		return nil
	}

	numSets := 1
	for numSets < maxRuleCacheSets && numSets*ruleCacheWays < capacity {
		numSets <<= 1
	}

	// #nosec G115 -- numSets is a positive power of two >= 1.
	return &ruleCache{
		mask:    uint64(numSets - 1),
		numSets: numSets,
	}
}

func (c *ruleCache) ensureSets() (sets []ruleCacheSet) {
	if ptr := c.sets.Load(); ptr != nil {
		return *ptr
	}

	c.initOnce.Do(func() {
		s := make([]ruleCacheSet, c.numSets)
		c.sets.Store(&s)
	})

	return *c.sets.Load()
}

func hashStorageID(id StorageID) (h uint64) {
	// #nosec G115 -- Mixing bits of non-negative ruleIdx for hash distribution.
	h = uint64(id.listID)*ruleCacheHashMul1 ^ uint64(id.ruleIdx)*ruleCacheHashMul2
	h ^= h >> 33

	return h
}

// load returns the cached rule for id, if present.
func (c *ruleCache) load(id StorageID) (r rules.Rule, ok bool) {
	ptr := c.sets.Load()
	if ptr == nil {
		return nil, false
	}

	set := &(*ptr)[hashStorageID(id)&c.mask]
	set.mu.RLock()
	for i := range ruleCacheWays {
		if set.ids[i] == id && set.rules[i] != nil {
			r = set.rules[i]
			if !set.visited[i].Load() {
				set.visited[i].Store(true)
			}
			set.mu.RUnlock()

			return r, true
		}
	}
	set.mu.RUnlock()

	return nil, false
}

// store inserts r under id, evicting an unvisited entry in its set if full.
func (c *ruleCache) store(id StorageID, r rules.Rule) {
	sets := c.ensureSets()
	set := &sets[hashStorageID(id)&c.mask]

	set.mu.Lock()
	emptyIdx := -1
	for i := range ruleCacheWays {
		if set.rules[i] == nil {
			if emptyIdx < 0 {
				emptyIdx = i
			}

			continue
		}

		if set.ids[i] == id {
			set.rules[i] = r
			set.visited[i].Store(true)
			set.mu.Unlock()

			return
		}
	}

	if emptyIdx >= 0 {
		set.ids[emptyIdx] = id
		set.rules[emptyIdx] = r
		set.visited[emptyIdx].Store(true)
		set.mu.Unlock()

		return
	}

	for set.visited[set.hand].Swap(false) {
		set.hand = (set.hand + 1) & ruleCacheWayMask
	}

	set.ids[set.hand] = id
	set.rules[set.hand] = r
	set.visited[set.hand].Store(true)
	set.hand = (set.hand + 1) & ruleCacheWayMask
	set.mu.Unlock()
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
	// and the value is the rule.  cache is nil when caching is disabled.
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

// RuleStorageConfig is the configuration for [NewRuleStorageWithConfig].
type RuleStorageConfig struct {
	// Lists is the slice of rule lists managed by the storage.
	Lists []Interface

	// CacheSize is the approximate maximum number of parsed rules retained in
	// the internal 8-way set-associative CLOCK cache (rounded up to a
	// power-of-2 number of 8-way sets, capped at 8,388,608 entries).  Zero uses
	// [DefaultRuleCacheSize]; a negative value disables caching.
	CacheSize int
}

// NewRuleStorage creates a new instance of the [*RuleStorage] and validates the
// list of rules specified.
func NewRuleStorage(lists []Interface) (s *RuleStorage, err error) {
	return NewRuleStorageWithConfig(&RuleStorageConfig{
		Lists:     lists,
		CacheSize: DefaultRuleCacheSize,
	})
}

// NewRuleStorageWithConfig creates a new [*RuleStorage] from conf.  conf must
// not be nil.
func NewRuleStorageWithConfig(conf *RuleStorageConfig) (s *RuleStorage, err error) {
	lists := conf.Lists
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

	cacheSize := conf.CacheSize
	if cacheSize == 0 {
		cacheSize = DefaultRuleCacheSize
	}

	return &RuleStorage{
		cache:           newRuleCache(cacheSize),
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
	if err == nil && r != nil && s.cache != nil {
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

// ListCount returns the number of rule lists in the storage.
func (s *RuleStorage) ListCount() (n int) {
	return len(s.lists)
}

// MaxListSizeEstimate returns the maximum size estimate among all rule lists in
// the storage.
func (s *RuleStorage) MaxListSizeEstimate() (est datasize.ByteSize) {
	for _, l := range s.lists {
		if lEst := l.SizeEstimate(); lEst > est {
			est = lEst
		}
	}

	return est
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
