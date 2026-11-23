package lookup

import (
	"encoding"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/ufcbor"
	"github.com/AdguardTeam/urlfilter/internal/ufencoding"
	"github.com/AdguardTeam/urlfilter/rules"
)

// shortcutLength is the fixed length used to form URL "shortcuts".
const shortcutLength = 5

// shortcut is a fixed-length 5-byte shortcut packed big-endian into the lower
// 40 bits of a uint64.  Using uint64 enables Go's mapaccess2_fast64 fast path,
// keeps the map completely pointer-free (noscan), and preserves lexicographical
// byte ordering under numeric comparison.
type shortcut uint64

// packShortcut packs 5 bytes from s[i:i+5] big-endian into a [shortcut].
// Callers must ensure i+shortcutLength <= len(s).
func packShortcut(s string, i int) (sc shortcut) {
	return shortcut(uint64(s[i])<<32 |
		uint64(s[i+1])<<24 |
		uint64(s[i+2])<<16 |
		uint64(s[i+3])<<8 |
		uint64(s[i+4]))
}

// packShortcutBytes packs a 5-byte slice big-endian into a [shortcut].
func packShortcutBytes(b []byte) (sc shortcut) {
	return shortcut(uint64(b[0])<<32 |
		uint64(b[1])<<24 |
		uint64(b[2])<<16 |
		uint64(b[3])<<8 |
		uint64(b[4]))
}

// bytes unpacks sc into a 5-byte array.
func (sc shortcut) bytes() (b [shortcutLength]byte) {
	// #nosec G115 -- Intentional byte extraction from packed 40-bit value.
	return [shortcutLength]byte{
		byte(sc >> 32),
		byte(sc >> 24),
		byte(sc >> 16),
		byte(sc >> 8),
		byte(sc),
	}
}

// Bit-packing layout for entries stored in [ShortcutIndex.shortcuts]:
//
//   - Bit 63 == 0 (single inline rule, the common case):
//     bits 47..62: 16-bit dense index into [ShortcutIndex.listIDs]
//     bits  0..46: 47-bit non-negative rule offset
//   - Bit 63 == 1 (multi-rule bucket in [ShortcutIndex.nodes]):
//     bits 32..62: 31-bit bucket length
//     bits  0..31: 32-bit 1-based head index into [ShortcutIndex.nodes]
const (
	multiEntryFlag = uint64(1) << 63

	ruleIdxBits  = 47
	ruleIdxMask  = (uint64(1) << ruleIdxBits) - 1
	listIdxBits  = 16
	listIdxMask  = (uint64(1) << listIdxBits) - 1
	maxRuleIdx   = int64(ruleIdxMask)
	maxListCount = 1 << listIdxBits
)

// shortcutNode is a 12-byte, pointer-free linked-list node stored in
// [ShortcutIndex.nodes] for shortcuts that map to more than one rule.
// Splitting the packed 64-bit ID into two uint32 fields keeps the struct
// 4-byte aligned (12 bytes instead of 16 bytes on 64-bit platforms).
type shortcutNode struct {
	idLo uint32
	idHi uint32
	next uint32
}

// ShortcutIndex is an index that relies on the rule shortcuts to quickly find
// matching rules:
//
//  1. From the rule, it extracts the longest substring without special
//     characters; this string is the [shortcut].
//  2. It uses a sliding window of [shortcutLength] and puts it into its map.
//  3. When it matches a request, it takes all substrings of length
//     [shortcutLength] from it and checks if there are any rules in the map.
//
// NOTE: only the rules with a shortcut are eligible for this index.
//
// TODO(a.garipov):  Consider all non-regexp rules as having shortcuts?
type ShortcutIndex struct {
	// shortcutsPool contains slices of shortcuts for reuse.
	shortcutsPool *syncutil.Pool[[]shortcut]

	// shortcuts maps a 5-byte shortcut to either an inline packed StorageID
	// (when bit 63 is 0) or a (count, head) descriptor into nodes (when bit 63
	// is 1).  Both key and value are pointer-free so Go's GC marks the map
	// noscan.
	shortcuts map[shortcut]uint64

	// nodes is a flat, pointer-free arena of linked-list nodes for shortcuts
	// that hold more than one rule.
	nodes []shortcutNode

	// listIDs maps compact 16-bit list indexes back to full [rules.ListID]
	// values.
	listIDs []rules.ListID
}

// shortcutsInARuleEst is the estimate for the number of shortcuts in a rule
// based on an analysis of the AdGuard DNS filtering-rule list.
const shortcutsInARuleEst = 16

// NewShortcutIndex creates a new instance of *ShortcutIndex.
func NewShortcutIndex() (idx *ShortcutIndex) {
	return &ShortcutIndex{
		shortcutsPool: syncutil.NewSlicePool[shortcut](shortcutsInARuleEst),
		shortcuts:     map[shortcut]uint64{},
	}
}

// packID packs id into a 63-bit representation (bit 63 is always 0).
func (idx *ShortcutIndex) packID(id filterlist.StorageID) (packed uint64, err error) {
	ruleIdx := id.RuleIdx()
	if ruleIdx < 0 || ruleIdx > maxRuleIdx {
		return 0, fmt.Errorf("rule index %d out of range [0, %d]", ruleIdx, maxRuleIdx)
	}

	listID := id.ListID()
	listIdx := slices.Index(idx.listIDs, listID)
	if listIdx < 0 {
		listIdx = len(idx.listIDs)
		if listIdx >= maxListCount {
			return 0, fmt.Errorf("too many distinct list IDs (max %d)", maxListCount)
		}

		idx.listIDs = append(idx.listIDs, listID)
	}

	// #nosec G115 -- Bounds are validated above.
	return (uint64(listIdx) << ruleIdxBits) | uint64(ruleIdx), nil
}

// unpackID unpacks a 63-bit packed ID back into a [filterlist.StorageID].
func (idx *ShortcutIndex) unpackID(packed uint64) (id filterlist.StorageID) {
	listIdx := (packed >> ruleIdxBits) & listIdxMask
	// #nosec G115 -- ruleIdx fits in 47 bits and is non-negative.
	ruleIdx := int64(packed & ruleIdxMask)

	return filterlist.NewStorageID(idx.listIDs[listIdx], ruleIdx)
}

// bucketLen returns the number of rules stored for a map value v.
func bucketLen(v uint64) (n uint64) {
	if v&multiEntryFlag == 0 {
		return 1
	}

	return (v &^ multiEntryFlag) >> 32
}

// insertPacked inserts packed into the bucket for sc.
func (idx *ShortcutIndex) insertPacked(sc shortcut, packed uint64) {
	v, ok := idx.shortcuts[sc]
	if !ok {
		idx.shortcuts[sc] = packed

		return
	}

	if v&multiEntryFlag == 0 {
		// Promote inline single entry into a 2-node list in idx.nodes.
		// #nosec G115 -- Bit-splitting a uint64 into two uint32 halves.
		idx.nodes = append(idx.nodes, shortcutNode{
			idLo: uint32(v),
			idHi: uint32(v >> 32),
			next: 0,
		})
		// #nosec G115 -- Node count is bounded by memory and checked by uint32.
		firstIdx := uint32(len(idx.nodes))

		// #nosec G115 -- Bit-splitting a uint64 into two uint32 halves.
		idx.nodes = append(idx.nodes, shortcutNode{
			idLo: uint32(packed),
			idHi: uint32(packed >> 32),
			next: firstIdx,
		})
		// #nosec G115 -- Node count is bounded by memory and checked by uint32.
		headIdx := uint32(len(idx.nodes))

		idx.shortcuts[sc] = multiEntryFlag | (uint64(2) << 32) | uint64(headIdx)

		return
	}

	count := (v &^ multiEntryFlag) >> 32
	// #nosec G115 -- Lower 32 bits store the 1-based head index.
	headIdx := uint32(v)

	// #nosec G115 -- Bit-splitting a uint64 into two uint32 halves.
	idx.nodes = append(idx.nodes, shortcutNode{
		idLo: uint32(packed),
		idHi: uint32(packed >> 32),
		next: headIdx,
	})
	// #nosec G115 -- Node count is bounded by memory and checked by uint32.
	newHead := uint32(len(idx.nodes))

	idx.shortcuts[sc] = multiEntryFlag | ((count + 1) << 32) | uint64(newHead)
}

// Add adds r to the index if r is eligible.  r must not be nil.
func (idx *ShortcutIndex) Add(r *rules.NetworkRule, id filterlist.StorageID) (ok bool) {
	shortcutsPtr := idx.shortcutsPool.Get()
	defer idx.shortcutsPool.Put(shortcutsPtr)

	*shortcutsPtr = appendRuleShortcuts((*shortcutsPtr)[:0], r)
	if len(*shortcutsPtr) == 0 {
		return false
	}

	var minSC shortcut
	minLen := uint64(math.MaxUint64)
	for _, sc := range *shortcutsPtr {
		v, exists := idx.shortcuts[sc]
		if !exists {
			minSC = sc
			break
		}

		lenSCIds := bucketLen(v)
		if lenSCIds < minLen {
			minLen = lenSCIds
			minSC = sc
		}
	}

	packed, err := idx.packID(id)
	if err != nil {
		return false
	}

	idx.insertPacked(minSC, packed)

	return true
}

// appendRuleShortcuts appends shortcuts to orig and returns them.  r must not
// be nil.
func appendRuleShortcuts(orig []shortcut, r *rules.NetworkRule) (res []shortcut) {
	res = orig

	if len(r.Shortcut) < shortcutLength {
		return res
	}

	if isAnyURLShortcut(r) {
		return res
	}

	s := r.Shortcut
	for i := range len(s) - shortcutLength {
		res = append(res, packShortcut(s, i))
	}

	return res
}

// isAnyURLShortcut checks if the rule potentially matches too many URLs.  It is
// better use another type of index for these kinds of rules.
//
// TODO(a.garipov):  Inspect and optimize.
func isAnyURLShortcut(r *rules.NetworkRule) (ok bool) {
	switch scLen := len(r.Shortcut); {
	case
		scLen < len("ws://")+1 && strings.HasPrefix(r.Shortcut, "ws:"),
		scLen < len("wss://")+1 && strings.HasPrefix(r.Shortcut, "wss:"),
		scLen < len("|wss://")+1 && strings.HasPrefix(r.Shortcut, "|ws"),
		scLen < len("https://")+1 && strings.HasPrefix(r.Shortcut, "http"),
		scLen < len("|https://")+1 && strings.HasPrefix(r.Shortcut, "|http"):
		return true
	default:
		return false
	}
}

// type check
var _ encoding.BinaryAppender = (*ShortcutIndex)(nil)

// AppendBinary implements the [encoding.BinaryAppender] interface for
// *ShortcutIndex.  The only guarantee with regards to the backwards
// compatibility is the following: when the result of AppendBinary is fed into
// [ShortcutIndex.UnmarshalBinary] of an empty or reset *ShortcutIndex, the
// results of [ShortcutIndex.AppendMatching] of this new table are the same as
// those of the original one; all of this being within one version of the
// module.
func (idx *ShortcutIndex) AppendBinary(orig []byte) (res []byte, err error) {
	// Pseudo-JSON of the CBOR output:
	//
	//	{
	//	  "domai": [
	//	    [ 1, 0 ],
	//	    [ 1, 1 ],
	//	    // …
	//	  ],
	//	  "omain": [
	//	    [ 1, 1 ],
	//	    [ 1, 2 ],
	//	    // …
	//	  ],
	//	  // …
	//	}
	//

	res = orig

	enc := ufcbor.NewEncoder()

	res = enc.EncodeMapStart(res, uint64(len(idx.shortcuts)))
	for _, sc := range slices.Sorted(maps.Keys(idx.shortcuts)) {
		scBytes := sc.bytes()
		res = enc.EncodeBytes(res, scBytes[:])

		v := idx.shortcuts[sc]
		res = enc.EncodeArrayStart(res, bucketLen(v))

		if v&multiEntryFlag == 0 {
			res, err = idx.unpackID(v).AppendBinary(res)
			if err != nil {
				return res, fmt.Errorf("shortcut %q: encoding id at index 0: %w", scBytes[:], err)
			}

			continue
		}

		i := 0
		// #nosec G115 -- Lower 32 bits store the 1-based head index.
		for nodeIdx := uint32(v); nodeIdx != 0; i++ {
			n := idx.nodes[nodeIdx-1]
			packed := uint64(n.idLo) | (uint64(n.idHi) << 32)
			res, err = idx.unpackID(packed).AppendBinary(res)
			if err != nil {
				return res, fmt.Errorf("shortcut %q: encoding id at index %d: %w", scBytes[:], i, err)
			}

			nodeIdx = n.next
		}
	}

	return res, nil
}

// AppendMatching appends the IDs of the rules matching r to orig and returns
// it.  r must not be nil.
func (idx *ShortcutIndex) AppendMatching(
	orig []filterlist.StorageID,
	r *rules.Request,
) (res []filterlist.StorageID) {
	res = orig

	s := r.URLLowerCase
	l := len(s)
	if l < shortcutLength {
		return res
	}

	for i := range l - shortcutLength {
		v, ok := idx.shortcuts[packShortcut(s, i)]
		if !ok {
			continue
		}

		if v&multiEntryFlag == 0 {
			res = append(res, idx.unpackID(v))

			continue
		}

		start := len(res)
		// #nosec G115 -- Lower 32 bits store the 1-based head index.
		for nodeIdx := uint32(v); nodeIdx != 0; {
			n := idx.nodes[nodeIdx-1]
			packed := uint64(n.idLo) | (uint64(n.idHi) << 32)
			res = append(res, idx.unpackID(packed))
			nodeIdx = n.next
		}
		slices.Reverse(res[start:])
	}

	return res
}

// Reset prepares idx for reuse.
func (idx *ShortcutIndex) Reset() {
	clear(idx.shortcuts)
	idx.nodes = idx.nodes[:0]
	idx.listIDs = idx.listIDs[:0]
}

// type check
var _ encoding.BinaryUnmarshaler = (*ShortcutIndex)(nil)

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface for
// *ShortcutIndex.  b should be data that has been encoded by
// [ShortcutIndex.AppendBinary].
func (idx *ShortcutIndex) UnmarshalBinary(b []byte) (err error) {
	_, err = idx.UnmarshalBinaryRest(b)

	return err
}

// type check
var _ ufencoding.BinaryUnmarshalerRest = (*ShortcutIndex)(nil)

// UnmarshalBinaryRest implements the [ufencoding.BinaryUnmarshalerRest]
// interface for *ShortcutIndex.  b should be data that has been encoded by
// [ShortcutIndex.AppendBinary].
func (idx *ShortcutIndex) UnmarshalBinaryRest(b []byte) (rest []byte, err error) {
	rest = b

	dec := ufcbor.NewDecoder()

	l, rest := dec.DecodeMapStart(rest)

	var keyBuffer []byte
	var idsBuf []uint64
	idx.shortcuts = make(map[shortcut]uint64, l)
	idx.nodes = idx.nodes[:0]
	idx.listIDs = idx.listIDs[:0]

	for range l {
		keyBuffer, rest = dec.AppendBytes(keyBuffer[:0], rest)
		if err = dec.Err(); err != nil {
			return b, err
		}

		if len(keyBuffer) != shortcutLength {
			return b, fmt.Errorf("decoding shortcut %q: invalid length %d", keyBuffer, len(keyBuffer))
		}

		sc := packShortcutBytes(keyBuffer)

		var idsLen uint64
		idsLen, rest = dec.DecodeArrayStart(rest)
		if err = dec.Err(); err != nil {
			return b, err
		}

		if idsLen == 0 {
			delete(idx.shortcuts, sc)

			continue
		}

		if idsLen == 1 {
			var id filterlist.StorageID
			rest, err = id.UnmarshalBinaryRest(rest)
			if err != nil {
				return b, fmt.Errorf("decoding shortcut %q: id at index 0: %w", keyBuffer, err)
			}

			var packed uint64
			packed, err = idx.packID(id)
			if err != nil {
				return b, fmt.Errorf("decoding shortcut %q: id at index 0: %w", keyBuffer, err)
			}

			idx.shortcuts[sc] = packed

			continue
		}

		idsBuf = idsBuf[:0]
		for i := range idsLen {
			var id filterlist.StorageID
			rest, err = id.UnmarshalBinaryRest(rest)
			if err != nil {
				return b, fmt.Errorf("decoding shortcut %q: id at index %d: %w", keyBuffer, i, err)
			}

			var packed uint64
			packed, err = idx.packID(id)
			if err != nil {
				return b, fmt.Errorf("decoding shortcut %q: id at index %d: %w", keyBuffer, i, err)
			}

			idsBuf = append(idsBuf, packed)
		}

		// Overwrite any prior bucket for duplicate keys, and insert in reverse
		// so head-to-tail traversal matches the encoded order.
		delete(idx.shortcuts, sc)
		for i := len(idsBuf) - 1; i >= 0; i-- {
			idx.insertPacked(sc, idsBuf[i])
		}
	}

	err = dec.Err()
	if err != nil {
		return b, err
	}

	return rest, nil
}
