package filterlist_test

import (
	"os"
	"strings"
	"testing"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleScanner_stringReader(t *testing.T) {
	t.Parallel()

	r := strings.NewReader(testRuleText)
	scanner := filterlist.NewRuleScanner(r, uftest.ListID1, false)

	assert.True(t, scanner.Scan())
	f, idx := scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, uftest.RuleHost, f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())
	assert.Equal(t, int64(0), idx)

	assert.True(t, scanner.Scan())
	f, idx = scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())
	assert.Equal(t, cosmeticRuleIndex, idx)

	assert.False(t, scanner.Scan())
	assert.False(t, scanner.Scan())
}

func TestRuleScanner_fileReader(t *testing.T) {
	t.Parallel()

	file, err := os.Open(hostsPath)
	require.NoError(t, err)

	scanner := filterlist.NewRuleScanner(file, uftest.ListID1, true)
	rulesCount := 0
	for scanner.Scan() {
		f, id := scanner.Rule()
		assert.NotNil(t, f)
		assert.Positive(t, id)

		rulesCount++
	}

	assert.Equal(t, hostsRulesCount, rulesCount)
	assert.False(t, scanner.Scan())
}

func TestRuleScanner_longLine(t *testing.T) {
	t.Parallel()

	longRule := "||" + strings.Repeat("a", 5000) + ".example^"
	nextRule := "||next.example^"
	r := strings.NewReader(longRule + "\n" + nextRule)
	scanner := filterlist.NewRuleScanner(r, uftest.ListID1, false)

	require.True(t, scanner.Scan())
	f, idx := scanner.Rule()
	assert.Equal(t, longRule, f.Text())
	assert.Equal(t, int64(0), idx)

	require.True(t, scanner.Scan())
	f, idx = scanner.Rule()
	assert.Equal(t, nextRule, f.Text())
	assert.Equal(t, int64(len(longRule)+1), idx)

	assert.False(t, scanner.Scan())
}

func TestRuleScanner_ScanFast(t *testing.T) {
	t.Parallel()

	content := strings.Join([]string{
		"! comment",
		"# hash comment",
		"  ||simple.example^  ",
		"@@||allow.example^",
		"||unsupported.example^$all",
		"example.org##.ad",
		"||modifier.example^$important",
	}, "\n")

	s := filterlist.NewRuleScanner(strings.NewReader(content), uftest.ListID1, true)

	var simpleDomains []string
	var parsedRules []string
	for {
		dom, r, listID, _, ok := s.ScanFast()
		if !ok {
			break
		}
		assert.Equal(t, uftest.ListID1, listID)
		if dom != nil {
			simpleDomains = append(simpleDomains, string(dom))
		} else {
			parsedRules = append(parsedRules, r.Text())
		}
	}

	assert.Equal(t, []string{"simple.example", "allow.example"}, simpleDomains)
	assert.Equal(t, []string{"||modifier.example^$important"}, parsedRules)
}

func BenchmarkRuleScanner_Scan(b *testing.B) {
	r := strings.NewReader(testRuleText)
	s := filterlist.NewRuleScanner(r, uftest.ListID1, false)

	var rule rules.Rule
	b.ReportAllocs()
	for b.Loop() {
		for s.Scan() {
			rule, _ = s.Rule()
		}
	}

	require.NotNil(b, rule)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/filterlist
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkRuleScanner_Scan-16       	31260648	        36.32 ns/op	       0 B/op	       0 allocs/op
}
