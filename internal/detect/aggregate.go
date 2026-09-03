package detect

import (
	"sync"

	"github.com/aydocs/fang/pkg/models"
)

// Aggregator merges scored findings across modules onto single
// representatives per dedup key. Absorption is safe for concurrent use so
// callers may feed it from pool result loops as they aggregate.
type Aggregator struct {
	mu    sync.Mutex
	order []*models.Finding
	byKey map[string]*entry
}

type entry struct {
	finding     *models.Finding
	classes     map[string]bool
	corroborate bool // multi-class boost already applied
	result      Result
}

// Absorption reports what happened to one absorbed finding.
type Absorption struct {
	Finding *models.Finding // representative kept for this dedup key
	Key     string
	IsNew   bool // first sighting: caller should insert
	Changed bool // representative mutated by a merge: caller should update
}

func NewAggregator() *Aggregator {
	return &Aggregator{byKey: make(map[string]*entry)}
}

// Absorb scores f, then either registers it as the representative for its
// dedup key or merges it into the existing one. The representative carries
// max severity, max confidence and an Occurrences count; a second distinct
// payload class on the same key boosts confidence one tier. Calibration runs
// again after every merge so severity always reflects the combined signals.
func (a *Aggregator) Absorb(f *models.Finding, opts Options) Absorption {
	res := Score(f, opts)

	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.byKey[res.Key]; ok {
		return Absorption{Finding: e.finding, Key: res.Key, Changed: e.merge(f, res)}
	}
	f.Occurrences = 1
	e := &entry{finding: f, classes: map[string]bool{PayloadClass(f.Payload): true}, result: res}
	a.byKey[res.Key] = e
	a.order = append(a.order, f)
	return Absorption{Finding: f, Key: res.Key, IsNew: true}
}

// Findings returns the representatives in first-seen order.
func (a *Aggregator) Findings() []*models.Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*models.Finding, len(a.order))
	copy(out, a.order)
	return out
}

func (e *entry) merge(src *models.Finding, srcResult Result) bool {
	rep := e.finding
	rep.Occurrences++
	changed := false
	if src.Severity > rep.Severity {
		rep.Severity = src.Severity
		changed = true
	}
	if src.Confidence > rep.Confidence {
		rep.Confidence = src.Confidence
		changed = true
	}
	if srcResult.StrongSignals > e.result.StrongSignals {
		e.result.StrongSignals = srcResult.StrongSignals
		changed = true
	}
	if srcResult.Reflected && !e.result.Reflected {
		e.result.Reflected = true
		changed = true
	}
	class := PayloadClass(src.Payload)
	if !e.classes[class] {
		e.classes[class] = true
		if len(e.classes) >= 2 && !e.corroborate {
			e.corroborate = true
			e.result.Corroborated = true
			rep.Confidence = shift(rep.Confidence, 1)
			changed = true
		}
	}
	if changed {
		Calibrate(rep, e.result)
	}
	return changed
}

// Dedupe collapses an already-collected finding slice onto one representative
// per dedup key. It never issues requests (stability filter stays off).
func Dedupe(findings []*models.Finding) []*models.Finding {
	agg := NewAggregator()
	for _, f := range findings {
		if f != nil {
			agg.Absorb(f, Options{})
		}
	}
	return agg.Findings()
}
