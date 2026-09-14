// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package rules applies the Risk Navigator's prioritisation rules as the backlog
// repository publishes them in rules/prioritisation.yaml: which CVEs are in the
// backlog and which priority each one gets. The file is data, not a language: every
// "when" is one of a fixed set of conditions, and a condition the code does not
// know is an error at load time, never a silent skip. The outcome mirrors the
// generator's prioritisation_rules.py field for field.
package rules

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// The priority bands, as the file names them.
const (
	P0 = "P0 / Act"
	P1 = "P1 / Attend"
	P2 = "P2 / Investigate"
	P3 = "P3 / Track"
	P4 = "P4 / Exclude"
)

// The severity bands.
const (
	Critical = "Critical"
	High     = "High"
	Medium   = "Medium"
	Low      = "Low"
	Unscored = "Unscored"
)

// The member levels a Facts.MemberLevel can carry.
const (
	MemberNone      = "none"
	MemberWatch     = "watch"
	MemberElevated  = "elevated"
	MemberExploited = "exploited"
)

// The conditions the file may name, exactly as written there. Anything else fails to load.
const (
	whenBandCritical  = "band == critical"
	whenBandHigh      = "band == high"
	whenKEV           = "kev"
	whenWindowSignal  = "score >= 6.0 and score < 7.0 and any signal"
	whenP0            = "kev or (band == critical and (epss signal or member exploit evidence))"
	whenScoreHigh     = "score >= 7.0"
	whenWindow        = "score >= 6.0 and score < 7.0"
	whenOtherwise     = "otherwise"
	windowLow         = 6.0
	windowHighDefault = 7.0
)

// file is the YAML as written.
type file struct {
	Version string `yaml:"version"`
	Source  string `yaml:"source"`
	Bands   struct {
		Critical float64 `yaml:"critical"`
		High     float64 `yaml:"high"`
		Medium   float64 `yaml:"medium"`
	} `yaml:"bands"`
	Signals struct {
		EPSSPercentile         float64 `yaml:"epss_percentile"`
		KEV                    bool    `yaml:"kev"`
		MemberExploitEvidence  bool    `yaml:"member_exploit_evidence"`
		OnRuntimePathAndListed bool    `yaml:"on_runtime_path_and_listed"`
		FixedByUpgrade         bool    `yaml:"fixed_by_upgrade"`
	} `yaml:"signals"`
	Include []struct {
		Rule string `yaml:"rule"`
		When string `yaml:"when"`
	} `yaml:"include"`
	// Priority is a list of one entry maps: the priority name to its condition.
	Priority    []map[string]string `yaml:"priority"`
	CuratedList struct {
		Groups   []string `yaml:"groups"`
		Prefixes []string `yaml:"prefixes"`
	} `yaml:"curated_list"`
}

// Rules is the file, checked and ready to apply.
type Rules struct {
	Version  string
	Source   string
	Bands    Bands
	Signals  Signals
	Include  []Rule
	Priority []Rule
	Curated  Curated
}

// Bands are the score floors of Critical, High and Medium.
type Bands struct {
	Critical float64
	High     float64
	Medium   float64
}

// Signals says what counts as a signal in the 6.0 to 6.9 window.
type Signals struct {
	EPSSPercentile         float64
	KEV                    bool
	MemberExploitEvidence  bool
	OnRuntimePathAndListed bool
	FixedByUpgrade         bool
}

// Rule is one entry of include or priority: its name and its condition, as written.
type Rule struct {
	Name string
	When string
}

// Curated is the list of groups the backlog is scoped to.
type Curated struct {
	Groups   []string
	Prefixes []string
}

// Facts is everything the rules read about one CVE on one coordinate.
type Facts struct {
	// Score is the CVSS base score, nil when no source has one.
	Score *float64
	// CVSSSource names where the score came from (nvd, osv), recorded in Inputs.
	CVSSSource string
	KEV        bool
	// EPSSPercentile is FIRST's percentile, nil when FIRST has none.
	EPSSPercentile *float64
	// MemberLevel is none, watch, elevated or exploited.
	MemberLevel string
	// OnCuratedList says the coordinate's group is on the curated list.
	OnCuratedList bool
	// OnRuntimePath says the coordinate is on the line's runtime path.
	OnRuntimePath bool
	// FixedByUpgrade says the advisory source names a fixed version.
	FixedByUpgrade bool
}

// Outcome is what the rules say, the same fields prioritisation_rules.evaluate returns.
type Outcome struct {
	// Band is the severity band: Critical, High, Medium, Low, Unscored (severityBand).
	Band string
	// Applicable says the CVE is in the backlog (applicableToBacklog).
	Applicable bool
	// Rule is the include rule that fired, "none" when none did (backlogRule).
	Rule string
	// Priority is P0 to P4 (priority).
	Priority string
	// Inputs are the signals behind the priority (priorityInputs).
	Inputs []string
	// Signals are the rule 2d signals present, whatever the score (signals2d).
	Signals []string
}

// Load reads and checks the file.
func Load(path string) (*Rules, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the rules: %w", err)
	}
	return Parse(raw)
}

// Parse checks the YAML: every condition must be one the code knows.
func Parse(raw []byte) (*Rules, error) {
	// 1. the shape
	var f file
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing the rules: %w", err)
	}
	r := &Rules{
		Version: f.Version,
		Source:  f.Source,
		Bands:   Bands{Critical: f.Bands.Critical, High: f.Bands.High, Medium: f.Bands.Medium},
		Signals: Signals{
			EPSSPercentile:         f.Signals.EPSSPercentile,
			KEV:                    f.Signals.KEV,
			MemberExploitEvidence:  f.Signals.MemberExploitEvidence,
			OnRuntimePathAndListed: f.Signals.OnRuntimePathAndListed,
			FixedByUpgrade:         f.Signals.FixedByUpgrade,
		},
		Curated: Curated{Groups: f.CuratedList.Groups, Prefixes: f.CuratedList.Prefixes},
	}

	// 2. the include rules, every condition known
	known := map[string]bool{
		whenBandCritical: true,
		whenBandHigh:     true,
		whenKEV:          true,
		whenWindowSignal: true,
		whenP0:           true,
		whenScoreHigh:    true,
		whenWindow:       true,
		whenOtherwise:    true,
	}
	for _, in := range f.Include {
		when := strings.TrimSpace(in.When)
		if !known[when] {
			return nil, fmt.Errorf("include rule %q: unknown condition %q", in.Rule, in.When)
		}
		r.Include = append(r.Include, Rule{Name: in.Rule, When: when})
	}

	// 3. the priority rules, one name and one condition each
	for i, entry := range f.Priority {
		if len(entry) != 1 {
			return nil, fmt.Errorf("priority rule %d: one name and one condition expected, got %d", i, len(entry))
		}
		for name, when := range entry {
			when = strings.TrimSpace(when)
			if !known[when] {
				return nil, fmt.Errorf("priority rule %q: unknown condition %q", name, when)
			}
			r.Priority = append(r.Priority, Rule{Name: name, When: when})
		}
	}

	// 4. something to apply
	if len(r.Include) == 0 || len(r.Priority) == 0 {
		return nil, fmt.Errorf("the rules name no include or no priority rule")
	}
	if r.Bands.Critical == 0 || r.Bands.High == 0 {
		return nil, fmt.Errorf("the rules name no critical or high band")
	}
	return r, nil
}

// Band returns the severity band of a score.
func (r *Rules) Band(score *float64) string {
	if score == nil {
		return Unscored
	}
	if *score >= r.Bands.Critical {
		return Critical
	}
	if *score >= r.Bands.High {
		return High
	}
	if *score >= r.Bands.Medium {
		return Medium
	}
	return Low
}

// CuratedList says whether a Maven group is on the curated list, exactly or under a prefix.
func (r *Rules) CuratedList(group string) bool {
	for _, g := range r.Curated.Groups {
		if group == g {
			return true
		}
	}
	for _, p := range r.Curated.Prefixes {
		if group == p || strings.HasPrefix(group, p+".") {
			return true
		}
	}
	return false
}

// Evaluate applies the rules to one CVE. Same steps as prioritisation_rules.evaluate.
func (r *Rules) Evaluate(f Facts) Outcome {
	out := Outcome{Inputs: []string{}, Signals: []string{}}

	// 1. the band and the two signals that feed everything else
	out.Band = r.Band(f.Score)
	memberExploit := f.MemberLevel == MemberExploited
	epssSignal := f.EPSSPercentile != nil && *f.EPSSPercentile >= r.Signals.EPSSPercentile

	// 2. the rule 2d signals, evaluated for the 6.0 to 6.9 window
	if epssSignal {
		out.Signals = append(out.Signals, "epss")
	}
	if (f.KEV && r.Signals.KEV) || (memberExploit && r.Signals.MemberExploitEvidence) {
		if f.KEV && r.Signals.KEV {
			out.Signals = append(out.Signals, "kev")
		} else {
			out.Signals = append(out.Signals, "member")
		}
	}
	if r.Signals.OnRuntimePathAndListed && f.OnCuratedList && f.OnRuntimePath {
		out.Signals = append(out.Signals, "graph")
	}
	if r.Signals.FixedByUpgrade && f.FixedByUpgrade {
		out.Signals = append(out.Signals, "osv-fix")
	}
	if f.MemberLevel == MemberElevated && r.Signals.MemberExploitEvidence && !contains(out.Signals, "member") {
		out.Signals = append(out.Signals, "member")
	}
	inWindow := f.Score != nil && *f.Score >= windowLow && *f.Score < r.windowHigh()

	// 3. the include rules, in the file's order, the first that fires is recorded
	out.Rule = "none"
	for _, rule := range r.Include {
		if r.fires(rule.When, f, out.Band, inWindow, len(out.Signals) > 0, epssSignal, memberExploit) {
			out.Applicable = true
			out.Rule = rule.Name
			break
		}
	}

	// 4. the priority rules, in the file's order, the first that fires
	source := f.CVSSSource
	if source == "" {
		source = "osv"
	}
	for _, rule := range r.Priority {
		if !r.fires(rule.When, f, out.Band, inWindow, len(out.Signals) > 0, epssSignal, memberExploit) {
			continue
		}
		out.Priority = rule.Name
		switch rule.When {
		case whenP0:
			if f.KEV {
				out.Inputs = append(out.Inputs, "kev")
			}
			if out.Band == Critical {
				out.Inputs = append(out.Inputs, source)
				if epssSignal {
					out.Inputs = append(out.Inputs, "epss")
				}
				if memberExploit {
					out.Inputs = append(out.Inputs, "member")
				}
			}
		case whenScoreHigh:
			out.Inputs = append(out.Inputs, source)
		case whenWindowSignal:
			out.Inputs = append(out.Inputs, source)
			for _, s := range out.Signals {
				if !contains(out.Inputs, s) {
					out.Inputs = append(out.Inputs, s)
				}
			}
		case whenWindow:
			out.Inputs = append(out.Inputs, source)
		case whenOtherwise:
			if f.CVSSSource != "" {
				out.Inputs = append(out.Inputs, f.CVSSSource)
			}
		}
		break
	}
	return out
}

// fires says whether one condition holds for these facts.
func (r *Rules) fires(when string, f Facts, band string, inWindow, anySignal, epssSignal, memberExploit bool) bool {
	switch when {
	case whenBandCritical:
		return band == Critical
	case whenBandHigh:
		return band == High
	case whenKEV:
		return f.KEV
	case whenWindowSignal:
		return inWindow && anySignal
	case whenP0:
		return f.KEV || (band == Critical && (epssSignal || memberExploit))
	case whenScoreHigh:
		return f.Score != nil && *f.Score >= r.Bands.High
	case whenWindow:
		return inWindow
	case whenOtherwise:
		return true
	}
	return false
}

// windowHigh is the top of the signal window: the High floor, 7.0 as the rules stand.
func (r *Rules) windowHigh() float64 {
	if r.Bands.High > 0 {
		return r.Bands.High
	}
	return windowHighDefault
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
