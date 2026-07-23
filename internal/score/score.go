package score

import "github.com/NotChaosuu/vibecheck/internal/model"

var confirmedWeight = map[model.Severity]int{
	model.Critical: 28,
	model.High:     13,
	model.Medium:   5,
	model.Low:      2,
	model.Info:     0,
}

var reviewWeight = map[model.Severity]int{
	model.Critical: 8,
	model.High:     5,
	model.Medium:   2,
	model.Low:      1,
	model.Info:     0,
}

// reviewOnlyFloor caps how far review findings alone can drag the score, so a
// project with nothing confirmed reads as "worth a look" (C at worst).
const reviewOnlyFloor = 22

func Compute(findings []model.Finding, vulnDeps []model.VulnDep) (int, string, model.CountsBySev) {
	counts := model.CountsBySev{}
	confirmedDed := 0
	reviewDed := 0
	hasConfirmedCritical := false
	hasConfirmedHigh := false

	for _, f := range findings {
		if f.Confidence == model.Confirmed {
			confirmedDed += confirmedWeight[f.Severity]
			if f.Severity == model.Critical {
				hasConfirmedCritical = true
			}
			if f.Severity == model.High {
				hasConfirmedHigh = true
			}
		} else {
			reviewDed += reviewWeight[f.Severity]
		}
		tally(&counts, f.Severity)
	}

	for _, vd := range vulnDeps {
		confirmedDed += confirmedWeight[vd.Severity]
		if vd.Severity == model.Critical {
			hasConfirmedCritical = true
		}
		if vd.Severity == model.High {
			hasConfirmedHigh = true
		}
		tally(&counts, vd.Severity)
	}

	if confirmedDed == 0 && reviewDed > reviewOnlyFloor {
		reviewDed = reviewOnlyFloor
	}

	score := 100 - confirmedDed - reviewDed
	if score < 0 {
		score = 0
	}

	grade := letter(score)
	if hasConfirmedCritical && grade < "D" {
		grade = "D"
	}
	if hasConfirmedHigh && grade < "B" {
		grade = "B"
	}
	return score, grade, counts
}

func letter(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 55:
		return "D"
	default:
		return "F"
	}
}

func tally(c *model.CountsBySev, s model.Severity) {
	switch s {
	case model.Critical:
		c.Critical++
	case model.High:
		c.High++
	case model.Medium:
		c.Medium++
	case model.Low:
		c.Low++
	case model.Info:
		c.Info++
	}
}
