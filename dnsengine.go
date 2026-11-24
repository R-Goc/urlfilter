package urlfilter

import (
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/lookup"
	"github.com/AdguardTeam/urlfilter/rules"
)

// DNSEngine combines host rules and network rules and is supposed to quickly find
// matching rules for hostnames.
// First, it looks over network rules and returns first rule found.
// Then, if nothing found, it looks up the host rules.
type DNSEngine struct {
	// ruleIndex is a map for hosts mapped to the list of rule indexes.
	ruleIndex map[string][]filterlist.StorageID

	// simpleDomains indexes pure domain rules ("||domain^", "@@||domain^") in a
	// compact pointer-free hash table.
	simpleDomains *lookup.SimpleDomainIndex

	// simpleIDsPool reuses candidate StorageID slices for simpleDomains
	// lookups.
	simpleIDsPool *syncutil.Pool[[]filterlist.StorageID]

	// networkEngine is the network engine constructed from the network rules.
	networkEngine *NetworkEngine

	// rulesStorage is the storage of all rules.
	rulesStorage *filterlist.RuleStorage

	// reqPool is the pool of [rules.Request] values.
	reqPool *syncutil.Pool[rules.Request]

	// rulesPool contains slices of rules for reuse.
	rulesPool *syncutil.Pool[[]*rules.HostRule]

	// rulesCount is the number of rules loaded to the engine.
	rulesCount uint64
}

// NewDNSEngine parses the specified filter lists and returns a *DNSEngine built
// from them.  s must not be nil.
func NewDNSEngine(s *filterlist.RuleStorage) (e *DNSEngine) {
	e = &DNSEngine{
		rulesStorage:  s,
		simpleIDsPool: syncutil.NewSlicePool[filterlist.StorageID](1),
		rulesCount:    0,
		reqPool:       syncutil.NewPool(func() (v *rules.Request) { return &rules.Request{} }),
		rulesPool:     syncutil.NewSlicePool[*rules.HostRule](1),
	}

	// Pass 1: count simple domain rules without allocating so SimpleDomainIndex
	// can be allocated once at its exact final size.
	if simpleCount := s.NewRuleStorageScanner().CountSimpleDomains(); simpleCount > 0 {
		e.simpleDomains = lookup.NewSimpleDomainIndex(
			simpleCount,
			s.ListCount(),
			s.MaxListSizeEstimate(),
		)
	}

	netEng := NewNetworkEngineSkipStorageScan(s)
	set := container.NewMapSet[string]()

	scanner := s.NewRuleStorageScanner()
	for {
		dom, f, listID, ruleIdx, ok := scanner.ScanFast()
		if !ok {
			break
		}

		if dom != nil {
			if e.simpleDomains != nil && e.simpleDomains.AddBytes(dom, listID, ruleIdx) {
				e.rulesCount++

				continue
			}

			// Fallback if ruleIdx, list count, or capacity exceeds
			// SimpleDomainIndex limits.
			var err error
			f, err = s.RetrieveRule(filterlist.NewStorageID(listID, ruleIdx))
			if err != nil || f == nil {
				continue
			}
		}

		id := filterlist.NewStorageID(listID, ruleIdx)
		switch f := f.(type) {
		case *rules.HostRule:
			e.addRule(f, id)
		case *rules.NetworkRule:
			if f.IsHostLevelNetworkRule() {
				netEng.addRule(f, id, set)
			}
		}
	}

	e.rulesCount += netEng.rulesCount
	e.networkEngine = netEng

	return e
}

// Match finds a matching rule for the specified hostname.  It returns true and
// the list of rules found or false and nil.  A list of rules is returned when
// there are multiple host rules matching the same domain, for example:
//
//	192.168.0.1 example.local
//	2000::1 example.local
func (e *DNSEngine) Match(hostname string) (res *DNSResult, matched bool) {
	return e.MatchRequest(&DNSRequest{Hostname: hostname})
}

// getRequestFromPool returns an instance of request from the engine's pool.
// Fills it's properties to match the given DNS request.
func (e *DNSEngine) getRequestFromPool(dReq *DNSRequest) (req *rules.Request) {
	req = e.reqPool.Get()

	req.SourceDomain = ""
	req.SourceHostname = ""
	req.SourceURL = ""

	req.ClientTags = dReq.ClientTags
	req.ClientIP = dReq.ClientIP
	req.ResponseCountry = dReq.ResponseCountry
	req.ResponseASN = dReq.ResponseASN
	req.ClientIdentifiers = dReq.ClientIdentifiers
	req.DNSType = dReq.DNSType
	req.IsAnswer = dReq.Answer

	rules.FillRequestForHostname(req, dReq.Hostname)

	return req
}

// MatchRequestInto matches the specified DNS request and puts the result into
// res.  ok is true if the result has a basic network rule or some host rules.
// req and res must not be nil.  res should be empty or reset using
// [DNSResult.Reset].
//
// NOTE:  For compatibility reasons, it is also false when there are DNS rewrite
// and other kinds of special network rules, so users who need those will need
// to ignore the matched return parameter and instead inspect the results of the
// corresponding DNSResult getters.
//
// TODO(a.garipov):  Refactor the result and remove the exception above.
func (e *DNSEngine) MatchRequestInto(req *DNSRequest, res *DNSResult) (matched bool) {
	if req.Hostname == "" {
		return false
	}

	var idsPtr *[]filterlist.StorageID
	var simpleIDs []filterlist.StorageID
	if e.simpleDomains != nil {
		idsPtr = e.simpleIDsPool.Get()
		*idsPtr = e.simpleDomains.AppendMatching((*idsPtr)[:0], req.Hostname)
		simpleIDs = *idsPtr
	}

	if len(simpleIDs) > 0 || e.networkEngine.RulesCount() > 0 {
		r := e.getRequestFromPool(req)
		defer e.reqPool.Put(r)

		for _, id := range simpleIDs {
			nr := e.rulesStorage.RetrieveNetworkRule(id)
			if nr != nil && nr.Match(r) {
				res.NetworkRules = append(res.NetworkRules, nr)
			}
		}

		if idsPtr != nil {
			e.simpleIDsPool.Put(idsPtr)
			idsPtr = nil
		}

		if e.networkEngine.RulesCount() > 0 {
			res.NetworkRules = e.networkEngine.AppendAllMatching(res.NetworkRules, r)
		}

		resultRule := rules.GetDNSBasicRule(res.NetworkRules)
		if resultRule != nil {
			res.NetworkRule = resultRule

			return true
		}
	} else if idsPtr != nil {
		e.simpleIDsPool.Put(idsPtr)
	}

	if len(e.ruleIndex) == 0 {
		return false
	}

	hostRulesPtr := e.rulesPool.Get()
	defer e.rulesPool.Put(hostRulesPtr)

	*hostRulesPtr = e.appendFromIndex((*hostRulesPtr)[:0], req.Hostname)
	if len(*hostRulesPtr) == 0 {
		return false
	}

	for _, rule := range *hostRulesPtr {
		if rule.IP.Is4() {
			res.HostRulesV4 = append(res.HostRulesV4, rule)
		} else {
			res.HostRulesV6 = append(res.HostRulesV6, rule)
		}
	}

	return true
}

// MatchRequest is like [MatchRequestInto] but returns a new result.  req must
// not be nil.
func (e *DNSEngine) MatchRequest(dReq *DNSRequest) (res *DNSResult, matched bool) {
	res = &DNSResult{}
	matched = e.MatchRequestInto(dReq, res)

	return res, matched
}

// appendFromIndex appends matching rules to matching.
func (e *DNSEngine) appendFromIndex(
	matching []*rules.HostRule,
	hostname string,
) (res []*rules.HostRule) {
	res = matching

	ids := e.ruleIndex[hostname]
	for _, id := range ids {
		res = append(res, e.rulesStorage.RetrieveHostRule(id))
	}

	return res
}

// addRule adds rule to the index.
func (e *DNSEngine) addRule(hostRule *rules.HostRule, id filterlist.StorageID) {
	if e.ruleIndex == nil {
		e.ruleIndex = map[string][]filterlist.StorageID{}
	}

	for _, hostname := range hostRule.Hostnames {
		e.ruleIndex[hostname] = append(e.ruleIndex[hostname], id)
	}

	e.rulesCount++
}

// RulesCount returns the number of rules added to the engine.
func (e *DNSEngine) RulesCount() (n uint64) {
	return e.rulesCount
}
