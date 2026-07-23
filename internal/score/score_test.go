package score

import (
	"testing"

	"github.com/NotChaosuu/vibecheck/internal/model"
)

func f(sev model.Severity, conf model.Confidence) model.Finding {
	return model.Finding{Severity: sev, Confidence: conf}
}

func TestCleanScoreIsA(t *testing.T) {
	s, grade, _ := Compute(nil, nil)
	if s != 100 || grade != "A" {
		t.Errorf("clean scan should be 100/A, got %d/%s", s, grade)
	}
}

func TestConfirmedCriticalCapsGrade(t *testing.T) {
	// one confirmed critical: even if arithmetic left a high score, grade caps at D
	_, grade, _ := Compute([]model.Finding{f(model.Critical, model.Confirmed)}, nil)
	if grade > "D" || grade == "A" || grade == "B" || grade == "C" {
		t.Errorf("confirmed critical should cap grade at D, got %s", grade)
	}
}

func TestConfirmedWeighsMoreThanReview(t *testing.T) {
	confirmedScore, _, _ := Compute([]model.Finding{f(model.High, model.Confirmed)}, nil)
	reviewScore, _, _ := Compute([]model.Finding{f(model.High, model.Review)}, nil)
	if confirmedScore >= reviewScore {
		t.Errorf("a confirmed high (%d) should cost more than a review high (%d)", confirmedScore, reviewScore)
	}
}

func TestCountsIncludeVulnDeps(t *testing.T) {
	vds := []model.VulnDep{{Severity: model.High}, {Severity: model.Critical}}
	_, _, counts := Compute(nil, vds)
	if counts.High != 1 || counts.Critical != 1 {
		t.Errorf("vuln deps not counted: %+v", counts)
	}
}

func TestReviewOnlyNeverFails(t *testing.T) {
	// a wall of review findings and nothing confirmed: worth a look, not an F
	var many []model.Finding
	for i := 0; i < 15; i++ {
		many = append(many, f(model.High, model.Review))
	}
	s, grade, _ := Compute(many, nil)
	if grade == "F" || grade == "D" {
		t.Errorf("review-only findings should not sink the grade to %s (score %d)", grade, s)
	}
	if s < 70 {
		t.Errorf("review-only score should stay at C or better, got %d", s)
	}
}

func TestOneConfirmedCriticalStillTanks(t *testing.T) {
	// but a single real confirmed critical must still drop the grade hard,
	// even buried under review noise
	fs := []model.Finding{f(model.Critical, model.Confirmed)}
	for i := 0; i < 10; i++ {
		fs = append(fs, f(model.Low, model.Review))
	}
	_, grade, _ := Compute(fs, nil)
	if grade == "A" || grade == "B" || grade == "C" {
		t.Errorf("a confirmed critical must cap the grade at D or worse, got %s", grade)
	}
}

func TestScoreFloorsAtZero(t *testing.T) {
	var many []model.Finding
	for i := 0; i < 20; i++ {
		many = append(many, f(model.Critical, model.Confirmed))
	}
	s, grade, _ := Compute(many, nil)
	if s < 0 {
		t.Errorf("score should floor at 0, got %d", s)
	}
	if grade != "F" {
		t.Errorf("20 confirmed criticals should be F, got %s", grade)
	}
}
