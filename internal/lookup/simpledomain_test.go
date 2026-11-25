package lookup_test

import (
	"math"
	"strings"
	"testing"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimpleDomainIndex_AppendMatching(t *testing.T) {
	t.Parallel()

	idx := lookup.NewSimpleDomainIndex(16, 2, 1*datasize.MB)
	require.True(t, idx.AddBytes([]byte("example.org"), uftest.ListID1, 10))
	require.True(t, idx.AddBytes([]byte("sub.example.org"), uftest.ListID2, 42))
	require.True(t, idx.AddBytes([]byte("MixedCase.Test"), uftest.ListID1, 99))
	require.True(t, idx.AddBytes([]byte("a"), uftest.ListID1, 1))
	require.True(t, idx.AddBytes([]byte("ab.c"), uftest.ListID1, 2))
	require.True(t, idx.AddBytes([]byte("long-domain-name-over-16-bytes.example.org"), uftest.ListID2, 123))

	// Exact match.
	got := idx.AppendMatching(nil, "example.org")
	assert.Equal(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID1, 10),
	}, got)

	// Subdomain matches both child and parent rules.
	got = idx.AppendMatching(nil, "a.sub.example.org")
	assert.ElementsMatch(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID1, 10),
		filterlist.NewStorageID(uftest.ListID2, 42),
	}, got)

	// Case-insensitive match across short, medium, and >16-byte domains.
	got = idx.AppendMatching(nil, "www.mixedcase.test")
	assert.Equal(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID1, 99),
	}, got)

	got = idx.AppendMatching(nil, "A")
	assert.Equal(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID1, 1),
	}, got)

	got = idx.AppendMatching(nil, "AB.C")
	assert.Equal(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID1, 2),
	}, got)

	got = idx.AppendMatching(nil, "LONG-DOMAIN-NAME-OVER-16-BYTES.EXAMPLE.ORG")
	assert.ElementsMatch(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID1, 10),
		filterlist.NewStorageID(uftest.ListID2, 123),
	}, got)

	// Non-matching domain.
	got = idx.AppendMatching(nil, "notexample.org")
	assert.Empty(t, got)
}

func TestSimpleDomainIndex_AppendExactMatching(t *testing.T) {
	t.Parallel()

	idx := lookup.NewSimpleDomainIndex(16, 2, 1*datasize.MB)
	require.True(t, idx.AddBytes([]byte("example.org"), uftest.ListID1, 10))
	require.True(t, idx.AddBytes([]byte("example.org"), uftest.ListID2, 20))
	require.True(t, idx.AddBytes([]byte("sub.example.org"), uftest.ListID1, 30))

	// Exact match returns both rules in insertion order.
	got := idx.AppendExactMatching(nil, "example.org")
	assert.Equal(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID1, 10),
		filterlist.NewStorageID(uftest.ListID2, 20),
	}, got)

	// Subdomain does not match parent rule.
	got = idx.AppendExactMatching(nil, "a.sub.example.org")
	assert.Empty(t, got)

	got = idx.AppendExactMatching(nil, "sub.example.org")
	assert.Equal(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID1, 30),
	}, got)
}

func TestSimpleDomainIndex_bulk(t *testing.T) {
	t.Parallel()

	const n = 5000
	idx := lookup.NewSimpleDomainIndex(n, 1, 1*datasize.MB)
	for i := range n {
		dom := []byte{
			'd',
			byte('a' + i%26),
			byte('a' + (i/26)%26),
			byte('a' + (i/676)%26),
			'.', 't', 'e', 's', 't',
		}
		require.True(t, idx.AddBytes(dom, uftest.ListID1, int64(i*20)))
	}

	assert.Equal(t, n, idx.Len())

	for i := range n {
		dom := string([]byte{
			'd',
			byte('a' + i%26),
			byte('a' + (i/26)%26),
			byte('a' + (i/676)%26),
			'.', 't', 'e', 's', 't',
		})
		got := idx.AppendMatching(nil, dom)
		assert.Contains(t, got, filterlist.NewStorageID(uftest.ListID1, int64(i*20)))
	}
}

func TestSimpleDomainIndex_compactMode(t *testing.T) {
	t.Parallel()

	const maxCompactOffset = (1 << 28) - 1

	idx := lookup.NewSimpleDomainIndex(32, 16, maxCompactOffset)

	// Max offset and 16 distinct lists succeed in compact mode.
	for i := range 16 {
		dom := []byte{byte('a' + i), '.', 't', 'e', 's', 't'}
		offset := int64(i)
		if i == 15 {
			offset = maxCompactOffset
		}
		require.True(t, idx.AddBytes(dom, rules.ListID(i+1), offset))
	}

	for i := range 16 {
		dom := string([]byte{byte('a' + i), '.', 't', 'e', 's', 't'})
		offset := int64(i)
		if i == 15 {
			offset = maxCompactOffset
		}
		got := idx.AppendMatching(nil, dom)
		assert.Contains(t, got, filterlist.NewStorageID(rules.ListID(i+1), offset))
	}

	// 17th distinct list and offset >= 256 MiB return false in compact mode.
	assert.False(t, idx.AddBytes([]byte("extra.test"), rules.ListID(17), 0))
	assert.False(t, idx.AddBytes([]byte("big.test"), rules.ListID(1), maxCompactOffset+1))
}

func TestSimpleDomainIndex_fallbackMode_lists(t *testing.T) {
	t.Parallel()

	idx := lookup.NewSimpleDomainIndex(300, 256, 1*datasize.MB)

	for i := range 256 {
		require.True(t, idx.AddBytes([]byte("example.org"), rules.ListID(i+1), int64(i)))
	}

	// 257th distinct list returns false.
	assert.False(t, idx.AddBytes([]byte("example.org"), rules.ListID(257), 256))

	got := idx.AppendMatching(nil, "example.org")
	assert.Len(t, got, 256)
	assert.Contains(t, got, filterlist.NewStorageID(rules.ListID(1), 0))
	assert.Contains(t, got, filterlist.NewStorageID(rules.ListID(256), 255))
}

func TestSimpleDomainIndex_fallbackMode_largeOffset(t *testing.T) {
	t.Parallel()

	const largeOffset = 1 << 28

	idx := lookup.NewSimpleDomainIndex(16, 1, largeOffset)
	require.True(t, idx.AddBytes([]byte("big1.test"), uftest.ListID1, largeOffset))
	require.True(t, idx.AddBytes([]byte("big2.test"), uftest.ListID2, math.MaxUint32))
	assert.False(t, idx.AddBytes([]byte("too-big.test"), uftest.ListID1, int64(math.MaxUint32)+1))

	assert.Equal(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID1, largeOffset),
	}, idx.AppendMatching(nil, "big1.test"))

	assert.Equal(t, []filterlist.StorageID{
		filterlist.NewStorageID(uftest.ListID2, math.MaxUint32),
	}, idx.AppendMatching(nil, "big2.test"))
}

func TestSimpleDomainIndex_AddBytes_fallback(t *testing.T) {
	t.Parallel()

	// Zero-capacity index rejects all inserts.
	empty := lookup.NewSimpleDomainIndex(0, 1, 0)
	assert.False(t, empty.AddBytes([]byte("example.org"), uftest.ListID1, 0))
	assert.Empty(t, empty.AppendMatching(nil, "example.org"))

	// Invalid arguments.
	idx := lookup.NewSimpleDomainIndex(16, 1, 1*datasize.MB)
	assert.False(t, idx.AddBytes(nil, uftest.ListID1, 0))
	assert.False(t, idx.AddBytes([]byte("example.org"), uftest.ListID1, -1))

	// Table full returns false instead of looping forever.
	full := lookup.NewSimpleDomainIndex(1, 1, 1*datasize.MB)
	inserted := 0
	for i := range 100 {
		dom := []byte(strings.Repeat("a", i%10+1) + ".test")
		if full.AddBytes(dom, uftest.ListID1, int64(i)) {
			inserted++
		} else {
			break
		}
	}
	assert.Equal(t, 63, inserted)
	assert.False(t, full.AddBytes([]byte("overflow.test"), uftest.ListID1, 999))
}
