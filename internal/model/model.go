package model

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

var SeverityRank = map[Severity]int{
	Critical: 0,
	High:     1,
	Medium:   2,
	Low:      3,
	Info:     4,
}

// Confidence separates structural findings we assert from heuristics we flag.
type Confidence string

const (
	Confirmed Confidence = "confirmed"
	Review    Confidence = "review"
)

type Finding struct {
	RuleID     string     `json:"rule_id"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	OWASP      string     `json:"owasp,omitempty"`
	File       string     `json:"file"`
	Line       int        `json:"line"`
	Excerpt    string     `json:"excerpt,omitempty"`
	Detail     string     `json:"detail"`
	Fix        string     `json:"fix"`
}

type Dependency struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Manifest  string `json:"manifest"`
}

type VulnDep struct {
	Dependency Dependency `json:"dependency"`
	Vulns      []DepVuln  `json:"vulns"`
	Severity   Severity   `json:"severity"`
}

type DepVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Summary  string   `json:"summary"`
	Severity Severity `json:"severity"`
	Fixed    string   `json:"fixed,omitempty"`
	URL      string   `json:"url,omitempty"`
}

type Result struct {
	Target       string      `json:"target"`
	Languages    []string    `json:"languages"`
	Frameworks   []string    `json:"frameworks"`
	FilesScanned int         `json:"files_scanned"`
	Findings     []Finding   `json:"findings"`
	VulnDeps     []VulnDep   `json:"vuln_deps"`
	Grade        string      `json:"grade"`
	Score        int         `json:"score"`
	Counts       CountsBySev `json:"counts"`
}

type CountsBySev struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func WorstSeverity(a, b Severity) Severity {
	if SeverityRank[a] <= SeverityRank[b] {
		return a
	}
	return b
}
