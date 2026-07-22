package krynox

import (
	"encoding/json"
	"os"
	"testing"
)

func TestGoldenContractV1(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden-v1.json")
	if err != nil { t.Fatal(err) }
	var golden struct {
		Verify Result `json:"verify"`
		Classify Classification `json:"classify"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil { t.Fatal(err) }
	if !golden.Verify.Success || golden.Verify.Action != "signup" || golden.Verify.CData != "order-42" {
		t.Fatalf("verification contract mismatch: %+v", golden.Verify)
	}
	if golden.Classify.Classification != "NEUTRAL" || golden.Classify.Blocked {
		t.Fatalf("classification contract mismatch: %+v", golden.Classify)
	}
}
