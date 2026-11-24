package lookup

import (
	"encoding/binary"
	"math"
	"math/bits"
	"slices"
	"strings"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/c2h5oh/datasize"
)

// SimpleDomainIndex is a compact, pointer-free (noscan) open-addressed hash
// table for pure domain-blocking rules (such as "||example.com^" and
// "@@||example.com^").
//
// It uses a Structure-of-Arrays (SoA) layout with parallel tags ([]uint16) and
// ruleIdx ([]uint32) slices so misses only touch the dense 2-byte tag array.
// In compact mode (<=16 lists and <256 MiB per list), the 4-bit list index is
// packed into the upper bits of ruleIdx (6 bytes/slot).  Otherwise, a parallel
// slotListIdx ([]uint8) stores the list index (7 bytes/slot).  Callers MUST
// verify every returned [filterlist.StorageID] against [filterlist.RuleStorage]
// to guarantee zero false positives and exact rule/list attribution.
type SimpleDomainIndex struct {
	// tags stores the 16-bit hash tag for each slot.  0 means empty; tag 0 is
	// remapped to 1.
	tags []uint16

	// ruleIdx stores either (listIdx4 << 28) | ruleIdx28 in compact mode
	// (slotListIdx == nil), or the full uint32 rule byte offset in fallback
	// mode (slotListIdx != nil).
	ruleIdx []uint32

	// slotListIdx stores the dense index into listIDs in fallback mode, and is
	// nil in compact mode.
	slotListIdx []uint8

	// listIDs maps dense list indexes back to full [rules.ListID] values.
	listIDs []rules.ListID

	// count is the number of occupied slots.
	count int
}

const (
	simpleDomainInitialCap = 64

	// simpleDomainMaxLoadNum / simpleDomainMaxLoadDen sizes the table at 80%
	// load (4/5) to keep linear-probing chains short while staying compact.
	simpleDomainMaxLoadNum = 4
	simpleDomainMaxLoadDen = 5

	// Compact 6 B/slot mode: 4-bit list index + 28-bit rule offset (< 256 MiB).
	compactRuleIdxBits          = 28
	compactMaxRuleOffset        = 1 << compactRuleIdxBits
	compactRuleIdxMask          = compactMaxRuleOffset - 1
	compactMaxSimpleDomainLists = 1 << (32 - compactRuleIdxBits)

	// Fallback 7 B/slot mode: 8-bit list index + 32-bit rule offset (< 4 GiB).
	maxSimpleDomainLists = math.MaxUint8 + 1

	wySecret0 = 0xa0761d6478bd642f
	wySecret1 = 0xe7037ed1a0b428db
)

func NewSimpleDomainIndex(
	expectedCount int,
	listCount int,
	maxListSize datasize.ByteSize,
) (idx *SimpleDomainIndex) {
	if expectedCount <= 0 {
		return &SimpleDomainIndex{}
	}

	// #nosec G115 -- expectedCount is positive.
	capSlotsU64 := (uint64(expectedCount)*simpleDomainMaxLoadDen + simpleDomainMaxLoadNum - 1) / simpleDomainMaxLoadNum
	if capSlotsU64 > math.MaxInt {
		return &SimpleDomainIndex{}
	}

	capSlots := int(capSlotsU64)
	if capSlots < simpleDomainInitialCap {
		capSlots = simpleDomainInitialCap
	}

	idx = &SimpleDomainIndex{
		tags:    make([]uint16, capSlots),
		ruleIdx: make([]uint32, capSlots),
	}

	if listCount > compactMaxSimpleDomainLists || maxListSize >= datasize.ByteSize(compactMaxRuleOffset) {
		idx.slotListIdx = make([]uint8, capSlots)
	}

	return idx
}

// AddBytes inserts a pure domain rule into idx.  domain must contain ASCII
// domain bytes (case-insensitive).  If ruleIdx, the distinct list count, or
// table capacity exceeds the supported limits, AddBytes returns false and the
// caller should fall back to the general index.
func (idx *SimpleDomainIndex) AddBytes(
	domain []byte,
	listID rules.ListID,
	ruleIdx int64,
) (ok bool) {
	if len(domain) == 0 || ruleIdx < 0 || idx.count+1 >= len(idx.tags) {
		return false
	}

	compact := idx.slotListIdx == nil
	if compact {
		if ruleIdx > compactRuleIdxMask {
			return false
		}
	} else if ruleIdx > math.MaxUint32 {
		return false
	}

	listIdx := slices.Index(idx.listIDs, listID)
	if listIdx < 0 {
		maxLists := maxSimpleDomainLists
		if compact {
			maxLists = compactMaxSimpleDomainLists
		}
		if len(idx.listIDs) >= maxLists {
			return false
		}

		listIdx = len(idx.listIDs)
		idx.listIDs = append(idx.listIDs, listID)
	}

	hv := hashDomainBytes(domain)
	tag := hashTag(hv)
	n := uint64(len(idx.tags))
	// #nosec G115 -- Lower 32 bits of the 64-bit hash.
	pos := lemireRange(uint32(hv), n)
	for idx.tags[pos] != 0 {
		pos++
		if pos == n {
			pos = 0
		}
	}

	idx.tags[pos] = tag
	if compact {
		// #nosec G115 -- listIdx (< 16) and ruleIdx (< 2^28) are validated above.
		idx.ruleIdx[pos] = (uint32(listIdx) << compactRuleIdxBits) | uint32(ruleIdx)
	} else {
		// #nosec G115 -- ruleIdx (<= MaxUint32) and listIdx (< 256) are validated above.
		idx.ruleIdx[pos] = uint32(ruleIdx)
		// #nosec G115 -- listIdx (< 256) is validated above.
		idx.slotListIdx[pos] = uint8(listIdx)
	}
	idx.count++

	return true
}

// AppendMatching appends candidate [filterlist.StorageID] values matching
// hostname or any of its parent domains to orig.
func (idx *SimpleDomainIndex) AppendMatching(
	orig []filterlist.StorageID,
	hostname string,
) (res []filterlist.StorageID) {
	res = orig
	n := uint64(len(idx.tags))
	if n == 0 || hostname == "" {
		return res
	}

	tags := idx.tags
	h := hostname
	for {
		hv := hashDomainString(h)
		tag := hashTag(hv)
		// #nosec G115 -- Lower 32 bits of the 64-bit hash.
		pos := lemireRange(uint32(hv), n)
		for {
			t := tags[pos]
			if t == 0 {
				break
			}

			if t == tag {
				res = append(res, idx.storageIDAt(pos))
			}

			pos++
			if pos == n {
				pos = 0
			}
		}

		dot := strings.IndexByte(h, '.')
		if dot < 0 || dot+1 >= len(h) {
			break
		}

		h = h[dot+1:]
	}

	return res
}

func (idx *SimpleDomainIndex) storageIDAt(pos uint64) (id filterlist.StorageID) {
	if idx.slotListIdx == nil {
		packed := idx.ruleIdx[pos]
		listID := idx.listIDs[packed>>compactRuleIdxBits]

		return filterlist.NewStorageID(listID, int64(packed&compactRuleIdxMask))
	}

	listID := idx.listIDs[idx.slotListIdx[pos]]

	return filterlist.NewStorageID(listID, int64(idx.ruleIdx[pos]))
}

// Len returns the number of rules stored in idx.
func (idx *SimpleDomainIndex) Len() (n int) {
	return idx.count
}

// hashDomainBytes computes a case-insensitive 64-bit wyhash-style hash over
// ASCII domain bytes without allocating.
func hashDomainBytes(b []byte) (h uint64) {
	n := len(b)
	seed := uint64(wySecret0)
	var x, y uint64

	switch {
	case n > 16:
		p := b
		for len(p) > 16 {
			w0 := lowerASCII64(binary.LittleEndian.Uint64(p))
			w1 := lowerASCII64(binary.LittleEndian.Uint64(p[8:]))
			seed = wymix(w0^wySecret1, w1^seed)
			p = p[16:]
		}
		x = lowerASCII64(binary.LittleEndian.Uint64(b[n-16:]))
		y = lowerASCII64(binary.LittleEndian.Uint64(b[n-8:]))
	case n > 8:
		x = lowerASCII64(binary.LittleEndian.Uint64(b))
		y = lowerASCII64(binary.LittleEndian.Uint64(b[n-8:]))
	case n >= 4:
		x = lowerASCII64(uint64(binary.LittleEndian.Uint32(b)))
		y = lowerASCII64(uint64(binary.LittleEndian.Uint32(b[n-4:])))
	case n > 0:
		x = lowerASCII64(uint64(b[0])<<16 | uint64(b[n>>1])<<8 | uint64(b[n-1]))
	}

	// #nosec G115 -- n is non-negative.
	return wymix(wySecret1^uint64(n), wymix(x^wySecret1, y^seed))
}

// hashDomainString computes the same case-insensitive 64-bit hash over a
// string without allocating.
func hashDomainString(s string) (h uint64) {
	n := len(s)
	seed := uint64(wySecret0)
	var x, y uint64

	switch {
	case n > 16:
		p := s
		for len(p) > 16 {
			w0 := lowerASCII64(readU64String(p))
			w1 := lowerASCII64(readU64String(p[8:]))
			seed = wymix(w0^wySecret1, w1^seed)
			p = p[16:]
		}
		x = lowerASCII64(readU64String(s[n-16:]))
		y = lowerASCII64(readU64String(s[n-8:]))
	case n > 8:
		x = lowerASCII64(readU64String(s))
		y = lowerASCII64(readU64String(s[n-8:]))
	case n >= 4:
		x = lowerASCII64(readU32String(s))
		y = lowerASCII64(readU32String(s[n-4:]))
	case n > 0:
		x = lowerASCII64(uint64(s[0])<<16 | uint64(s[n>>1])<<8 | uint64(s[n-1]))
	}

	// #nosec G115 -- n is non-negative.
	return wymix(wySecret1^uint64(n), wymix(x^wySecret1, y^seed))
}

// lowerASCII64 converts ASCII uppercase bytes ('A'..'Z') in w to lowercase
// without affecting any other byte values.
func lowerASCII64(w uint64) (l uint64) {
	m := w & 0x7f7f7f7f7f7f7f7f
	a := m + 0x3f3f3f3f3f3f3f3f
	z := m + 0x2525252525252525
	mask := (a &^ z &^ w) & 0x8080808080808080

	return w | (mask >> 2)
}

func readU64String(s string) (v uint64) {
	return uint64(s[0]) |
		uint64(s[1])<<8 |
		uint64(s[2])<<16 |
		uint64(s[3])<<24 |
		uint64(s[4])<<32 |
		uint64(s[5])<<40 |
		uint64(s[6])<<48 |
		uint64(s[7])<<56
}

func readU32String(s string) (v uint64) {
	return uint64(s[0]) |
		uint64(s[1])<<8 |
		uint64(s[2])<<16 |
		uint64(s[3])<<24
}

func wymix(a, b uint64) (h uint64) {
	hi, lo := bits.Mul64(a, b)

	return hi ^ lo
}

// hashTag extracts a non-zero 16-bit tag from the upper bits of h (0 is
// reserved for empty slots).
func hashTag(h uint64) (tag uint16) {
	// #nosec G115 -- Intentional extraction of the upper 16 bits.
	tag = uint16(h >> 48)
	if tag == 0 {
		return 1
	}

	return tag
}

// lemireRange maps a 32-bit hash x uniformly into [0, n) using one multiply
// and shift (no division).
func lemireRange(x uint32, n uint64) (pos uint64) {
	return (uint64(x) * n) >> 32
}
