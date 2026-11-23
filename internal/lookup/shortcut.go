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
// 40 bits of a uint64.  Using uint64 avoids pinning the original rule string,
// enables Go's mapaccess2_fast64 fast path, and preserves lexicographical byte
// ordering under numeric comparison.
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

// shortcutBucket stores the head index and length of a shortcut's rule list
// inside [ShortcutIndex.nodes].
type shortcutBucket struct {
	// head is the 1-based index of the first node in [ShortcutIndex.nodes].
	head uint32

	// len is the number of rules in this bucket.
	len uint32
}

// shortcutNode is a single pointer-free entry in [ShortcutIndex.nodes].
type shortcutNode struct {
	id   filterlist.StorageID
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

	// shortcuts maps a 5-byte shortcut to its bucket in nodes.  Both key and
	// value are pointer-free so Go's GC marks the map noscan.
	shortcuts map[shortcut]shortcutBucket

	// nodes is a flat, pointer-free arena of linked-list nodes holding rule
	// IDs.
	nodes []shortcutNode
}

// shortcutsInARuleEst is the estimate for the number of shortcuts in a rule
// based on an analysis of the AdGuard DNS filtering-rule list.
const shortcutsInARuleEst = 16

// NewShortcutIndex creates a new instance of *ShortcutIndex.
func NewShortcutIndex() (idx *ShortcutIndex) {
	return &ShortcutIndex{
		shortcutsPool: syncutil.NewSlicePool[shortcut](shortcutsInARuleEst),
		shortcuts:     map[shortcut]shortcutBucket{},
	}
}

// insertID prepends id to the bucket for sc.
func (idx *ShortcutIndex) insertID(sc shortcut, id filterlist.StorageID) {
	b := idx.shortcuts[sc]
	idx.nodes = append(idx.nodes, shortcutNode{
		id:   id,
		next: b.head,
	})
	// #nosec G115 -- Node count is bounded by memory.
	idx.shortcuts[sc] = shortcutBucket{
		head: uint32(len(idx.nodes)),
		len:  b.len + 1,
	}
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
	minLen := uint32(math.MaxUint32)
	for _, sc := range *shortcutsPtr {
		b, exists := idx.shortcuts[sc]
		if !exists {
			minSC = sc
			break
		}

		if b.len < minLen {
			minLen = b.len
			minSC = sc
		}
	}

	idx.insertID(minSC, id)

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

		b := idx.shortcuts[sc]
		res = enc.EncodeArrayStart(res, uint64(b.len))

		i := 0
		for nodeIdx := b.head; nodeIdx != 0; i++ {
			n := idx.nodes[nodeIdx-1]
			res, err = n.id.AppendBinary(res)
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
		b, ok := idx.shortcuts[packShortcut(s, i)]
		if !ok {
			continue
		}

		start := len(res)
		for nodeIdx := b.head; nodeIdx != 0; {
			n := idx.nodes[nodeIdx-1]
			res = append(res, n.id)
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
	var idsBuf []filterlist.StorageID
	idx.shortcuts = make(map[shortcut]shortcutBucket, l)
	idx.nodes = idx.nodes[:0]

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

		idsBuf = idsBuf[:0]
		for i := range idsLen {
			var id filterlist.StorageID
			rest, err = id.UnmarshalBinaryRest(rest)
			if err != nil {
				return b, fmt.Errorf("decoding shortcut %q: id at index %d: %w", keyBuffer, i, err)
			}

			idsBuf = append(idsBuf, id)
		}

		// Overwrite any prior bucket for duplicate keys, and insert in reverse
		// so head-to-tail traversal matches the encoded order.
		delete(idx.shortcuts, sc)
		for i := len(idsBuf) - 1; i >= 0; i-- {
			idx.insertID(sc, idsBuf[i])
		}
	}

	err = dec.Err()
	if err != nil {
		return b, err
	}

	return rest, nil
}
