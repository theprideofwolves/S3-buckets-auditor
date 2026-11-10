package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Nil means unobserved, never false. These are the same two API reads, with
// individual Public Access Block flags retained instead of discarded.
type BucketControls struct {
	PolicyPublic              *bool
	BlockConfigurationPresent *bool
	BlockPublicAcls           *bool
	IgnorePublicAcls          *bool
	BlockPublicPolicy         *bool
	RestrictPublicBuckets     *bool
}

type controlDefinition struct {
	ID, Name     string
	ConcernValue bool
}

var controlDefinitions = []controlDefinition{
	{"policy-public", "Bucket policy public status", true},
	{"block-complete", "Bucket Public Access Block complete", false},
	{"BlockPublicAcls", "BlockPublicAcls", false},
	{"IgnorePublicAcls", "IgnorePublicAcls", false},
	{"BlockPublicPolicy", "BlockPublicPolicy", false},
	{"RestrictPublicBuckets", "RestrictPublicBuckets", false},
}

func boolValue(v bool) *bool { return &v }

// Legacy summaries can prove all flags enabled, but cannot tell us which flag
// was disabled. Do not invent individual flag observations when upgrading.
func recordedControls(r BucketReport) BucketControls {
	if r.Controls != nil {
		return *r.Controls
	}
	var c BucketControls
	switch r.PolicyState {
	case "public according to policy status":
		c.PolicyPublic = boolValue(true)
	case "not public according to policy status", "no bucket policy":
		c.PolicyPublic = boolValue(false)
	}
	switch r.BlockState {
	case "configuration absent":
		c.BlockConfigurationPresent = boolValue(false)
	case "all four flags enabled":
		c.BlockConfigurationPresent = boolValue(true)
		c.BlockPublicAcls = boolValue(true)
		c.IgnorePublicAcls = boolValue(true)
		c.BlockPublicPolicy = boolValue(true)
		c.RestrictPublicBuckets = boolValue(true)
	case "one or more flags disabled":
		c.BlockConfigurationPresent = boolValue(true)
	}
	return c
}

func controlValues(r BucketReport) []*bool {
	c := recordedControls(r)
	flags := []*bool{c.BlockPublicAcls, c.IgnorePublicAcls, c.BlockPublicPolicy, c.RestrictPublicBuckets}
	var complete *bool
	if c.BlockConfigurationPresent != nil {
		if !*c.BlockConfigurationPresent {
			complete = boolValue(false)
		} else {
			allKnown, allEnabled := true, true
			for _, v := range flags {
				if v == nil {
					allKnown = false
				} else if !*v {
					allEnabled = false
				}
			}
			if !allEnabled {
				complete = boolValue(false)
			} else if allKnown {
				complete = boolValue(true)
			}
		}
	}
	if r.Controls == nil && r.BlockState == "one or more flags disabled" {
		complete = boolValue(false)
	}
	return append([]*bool{c.PolicyPublic, complete}, flags...)
}

func completeObservation(r BucketReport) bool {
	v := controlValues(r)
	if len(r.Errors) > 0 || v[0] == nil || v[1] == nil {
		return false
	}
	if r.Controls != nil && r.Controls.BlockConfigurationPresent != nil && *r.Controls.BlockConfigurationPresent {
		for _, flag := range v[2:] {
			if flag == nil {
				return false
			}
		}
	}
	return true
}

type ControlObservation struct {
	ScanID string
	At     time.Time
	State  string // concern, clear, unknown, not_assessed
	Value  *bool
	Note   string `json:",omitempty"`
}

type ConcernEpisode struct {
	FirstObserved ControlObservation
	LastObserved  ControlObservation
	VerifiedClear *ControlObservation
	AgeSeconds    int64 // first observation to selected scan or verified clear; not continuous exposure
}

type ControlEvidence struct {
	ID, Name     string
	Current      ControlObservation
	LastKnown    *ControlObservation
	ComparedWith *ControlObservation
	Change       string
	Episodes     []ConcernEpisode
	Timeline     []ControlObservation
}

type BucketEvidence struct {
	Name, Assessment string
	Assessed         bool
	OpenConcerns     int // the two aggregate checks only; flag detail is not double-counted
	Controls         []ControlEvidence
}

type EvidenceTicket struct{ Origin, Bucket, Key, State string }

type VerificationRecord struct {
	Version     int
	Scan        Scan
	Limitations []string
	Buckets     []BucketEvidence
	// Mappings have no historical revision log. Do not mislabel them as as-of-scan.
	CurrentTicketLinks []EvidenceTicket
}

func controlText(id string, v bool) string {
	if id == "policy-public" {
		if v {
			return "public"
		}
		return "not public"
	}
	if id == "block-complete" {
		if v {
			return "complete"
		}
		return "incomplete"
	}
	if v {
		return "enabled"
	}
	return "disabled"
}

func (c *ControlEvidence) observe(scan Scan, value *bool, assessed bool, legacy bool) {
	observation := ControlObservation{ScanID: scan.ID, At: scan.At, Value: value, State: "unknown"}
	c.ComparedWith = c.LastKnown
	c.Change = "Unknown; previous evidence retained"
	if !assessed {
		observation.State = "not_assessed"
		c.Change = "Not assessed; previous evidence retained"
	} else if value == nil && legacy {
		observation.Note = "Value unavailable in this legacy scan"
	}
	if value != nil {
		definition := controlDefinitionsByID(c.ID)
		observation.State = "clear"
		if *value == definition.ConcernValue {
			observation.State = "concern"
		}
		c.Change = "First successful observation"
		if c.LastKnown != nil {
			c.Change = "Unchanged since last successful observation"
			if *c.LastKnown.Value != *value {
				c.Change = controlText(c.ID, *c.LastKnown.Value) + " → " + controlText(c.ID, *value)
			}
		}
		active := len(c.Episodes) > 0 && c.Episodes[len(c.Episodes)-1].VerifiedClear == nil
		if observation.State == "concern" {
			if !active {
				c.Episodes = append(c.Episodes, ConcernEpisode{FirstObserved: observation, LastObserved: observation})
			} else {
				c.Episodes[len(c.Episodes)-1].LastObserved = observation
			}
		} else if active {
			copy := observation
			c.Episodes[len(c.Episodes)-1].VerifiedClear = &copy
		}
		copy := observation
		c.LastKnown = &copy
	}
	c.Current = observation
	c.Timeline = append(c.Timeline, observation)
}

func controlDefinitionsByID(id string) controlDefinition {
	for _, definition := range controlDefinitions {
		if definition.ID == id {
			return definition
		}
	}
	panic("unknown internal control ID")
}

func (c ControlEvidence) CurrentValue() string {
	if c.Current.Value == nil {
		return strings.ReplaceAll(c.Current.State, "_", " ")
	}
	return controlText(c.ID, *c.Current.Value)
}

func newBucketEvidence(name string) *BucketEvidence {
	b := &BucketEvidence{Name: name, Controls: make([]ControlEvidence, len(controlDefinitions))}
	for i, d := range controlDefinitions {
		b.Controls[i] = ControlEvidence{ID: d.ID, Name: d.Name, Episodes: []ConcernEpisode{}, Timeline: []ControlObservation{}}
	}
	return b
}

func openEpisode(c ControlEvidence) bool {
	return len(c.Episodes) > 0 && c.Episodes[len(c.Episodes)-1].VerifiedClear == nil
}

// Replay append order, not timestamp sorting. Stop at the selected scan and
// match BOTH account/region and synthetic/live status. Later evidence cannot
// rewrite an earlier export. The ledger is derived, not a second mutable store.
func verification(scans []Scan, selectedID string) (VerificationRecord, error) {
	selectedIndex := -1
	for i := range scans {
		if scans[i].ID == selectedID {
			selectedIndex = i
			break
		}
	}
	if selectedIndex < 0 {
		return VerificationRecord{}, errors.New("scan not found")
	}
	selected := scans[selectedIndex]
	record := VerificationRecord{Version: 1, Scan: selected, Buckets: []BucketEvidence{}, CurrentTicketLinks: []EvidenceTicket{}, Limitations: []string{
		"Bucket-policy public status and bucket-level Public Access Block only; not proof of effective anonymous access.",
		"Unknown and missing observations never clear a concern. Absence from discovery does not prove deletion.",
		"Replay uses saved append order up to the selected scan in the same scope and synthetic/live class.",
		"Times are scan observation timestamps, not the exact time a setting changed. Age is measured at the selected scan.",
		"CurrentTicketLinks are current local mappings, not historical Jira status. Local history is editable, not an authenticated audit ledger.",
	}}
	buckets := map[string]*BucketEvidence{}
	for _, scan := range scans[:selectedIndex+1] {
		if scan.Scope != selected.Scope || scan.Demo != selected.Demo {
			continue
		}
		reports := map[string]BucketReport{}
		for _, r := range scan.Reports {
			reports[r.Name] = r
			if buckets[r.Name] == nil {
				buckets[r.Name] = newBucketEvidence(r.Name)
			}
		}
		for name, b := range buckets {
			report, assessed := reports[name]
			hadConcern := openEpisode(b.Controls[0]) || openEpisode(b.Controls[1])
			values := controlValues(report)
			if !assessed {
				values = make([]*bool, len(controlDefinitions))
			}
			for i := range b.Controls {
				b.Controls[i].observe(scan, values[i], assessed, assessed && report.Controls == nil)
			}
			b.Assessed = assessed
			b.OpenConcerns = 0
			for _, c := range b.Controls[:2] {
				if openEpisode(c) {
					b.OpenConcerns++
				}
			}
			switch {
			case !assessed:
				b.Assessment = "Not assessed in this scan"
			case !completeObservation(report):
				b.Assessment = "Unknown — reassessment incomplete"
			case *values[0] || !*values[1]:
				b.Assessment = "New concern"
				if hadConcern {
					b.Assessment = "Persistent concern"
				}
			case hadConcern:
				b.Assessment = "Verified clear for checked controls"
			default:
				b.Assessment = "Checked controls enabled"
			}
		}
	}
	names := make([]string, 0, len(buckets))
	for name := range buckets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := buckets[name]
		for i := range b.Controls {
			for j := range b.Controls[i].Episodes {
				episode := &b.Controls[i].Episodes[j]
				end := selected.At
				if episode.VerifiedClear != nil {
					end = episode.VerifiedClear.At
				}
				episode.AgeSeconds = int64(end.Sub(episode.FirstObserved.At).Seconds())
				if episode.AgeSeconds < 0 {
					episode.AgeSeconds = 0
				}
			}
		}
		record.Buckets = append(record.Buckets, *b)
	}
	return record, nil
}

func (a *App) verificationRecord(id string) (VerificationRecord, error) {
	record, err := verification(a.state.Scans, id)
	if err != nil {
		return record, err
	}
	if !record.Scan.Demo {
		suffix := "|" + record.Scan.Scope + "|"
		for mapping, ticket := range a.state.Tickets {
			origin, rest, ok := strings.Cut(mapping, suffix)
			if !ok {
				continue
			}
			for _, bucket := range record.Buckets {
				if bucket.Name == rest {
					record.CurrentTicketLinks = append(record.CurrentTicketLinks, EvidenceTicket{Origin: origin, Bucket: rest, Key: ticket.Key, State: ticket.State})
				}
			}
		}
		sort.Slice(record.CurrentTicketLinks, func(i, j int) bool {
			a, b := record.CurrentTicketLinks[i], record.CurrentTicketLinks[j]
			if a.Origin == b.Origin {
				return a.Bucket < b.Bucket
			}
			return a.Origin < b.Origin
		})
	}
	return record, nil
}

func verificationSummary(record VerificationRecord, name string) string {
	for _, b := range record.Buckets {
		if b.Name == name {
			var text strings.Builder
			fmt.Fprintf(&text, "\nReassessment: %s; unresolved aggregate checks: %d\n", b.Assessment, b.OpenConcerns)
			for _, c := range b.Controls {
				fmt.Fprintf(&text, "%s: %s; %s\n", c.Name, c.Current.State, c.Change)
				gaps := 0
				for _, event := range c.Timeline {
					if event.State == "unknown" || event.State == "not_assessed" {
						gaps++
					}
				}
				fmt.Fprintf(&text, "  Unknown/missing observations in saved history: %d\n", gaps)
				if c.ComparedWith != nil {
					fmt.Fprintf(&text, "  Compared with scan %s at %s\n", c.ComparedWith.ScanID, c.ComparedWith.At.Format(time.RFC3339))
				}
				for _, episode := range c.Episodes {
					fmt.Fprintf(&text, "  Concern first observed %s (scan %s)", episode.FirstObserved.At.Format(time.RFC3339), episode.FirstObserved.ScanID)
					if episode.VerifiedClear != nil {
						fmt.Fprintf(&text, "; verified clear %s (scan %s)", episode.VerifiedClear.At.Format(time.RFC3339), episode.VerifiedClear.ScanID)
					} else {
						text.WriteString("; unresolved")
					}
					text.WriteByte('\n')
				}
			}
			return text.String()
		}
	}
	return ""
}
