package segment

import (
	"reflect"
	"strings"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// allModelTechniques is every technique constant the frozen model contract defines. The
// catalogue must cover exactly these.
var allModelTechniques = []string{
	model.TechDirect, model.TechSrcPort53, model.TechSrcPort88, model.TechSrcPort123,
	model.TechSrcPort20, model.TechSrcPort67, model.TechSrcPort500, model.TechICMP,
	model.TechIPv6, model.TechGatewayRoute, model.TechAltGateway, model.TechFragment,
	model.TechDot1QSubif, model.TechDTPTrunk, model.TechDoubleTag,
}

func TestTechniqueCatalogCoversTheModel(t *testing.T) {
	have := map[string]bool{}
	for _, info := range techniqueCatalog {
		if have[info.ID] {
			t.Errorf("technique %q listed twice", info.ID)
		}
		have[info.ID] = true
	}
	for _, id := range allModelTechniques {
		if !have[id] {
			t.Errorf("model.Tech* constant %q is missing from the catalogue", id)
		}
		delete(have, id)
	}
	for id := range have {
		t.Errorf("catalogue advertises %q, which is not a model.Tech* constant", id)
	}
}

func TestTechniqueInfoIsUsable(t *testing.T) {
	tester := New(nil, nil, nil)
	for _, info := range tester.Techniques() {
		if info.Title == "" {
			t.Errorf("%s: empty title", info.ID)
		}
		if len(info.Description) < 40 {
			t.Errorf("%s: description is too short to help the operator: %q", info.ID, info.Description)
		}
		if !strings.HasSuffix(strings.TrimSpace(info.Description), ".") {
			t.Errorf("%s: description should be a sentence: %q", info.ID, info.Description)
		}
	}
}

func TestTechniquesIsACopy(t *testing.T) {
	tester := New(nil, nil, nil)
	got := tester.Techniques()
	got[0].Title = "mutated"
	if tester.Techniques()[0].Title == "mutated" {
		t.Fatal("Techniques() exposes the package-level catalogue to mutation")
	}
}

func TestL2ActiveAndOneWayFlags(t *testing.T) {
	wantL2 := map[string]bool{
		model.TechDot1QSubif: true,
		model.TechDTPTrunk:   true,
		model.TechDoubleTag:  true,
	}
	for _, info := range techniqueCatalog {
		if info.L2Active != wantL2[info.ID] {
			t.Errorf("%s: L2Active = %v, want %v", info.ID, info.L2Active, wantL2[info.ID])
		}
		if isL2Active(info.ID) != info.L2Active {
			t.Errorf("%s: isL2Active disagrees with the catalogue", info.ID)
		}
		wantOneWay := info.ID == model.TechDoubleTag
		if info.OneWay != wantOneWay {
			t.Errorf("%s: OneWay = %v, want %v", info.ID, info.OneWay, wantOneWay)
		}
		if isOneWay(info.ID) != info.OneWay {
			t.Errorf("%s: isOneWay disagrees with the catalogue", info.ID)
		}
		if info.L2Active && !needsExclusiveAccess(info.ID) {
			t.Errorf("%s: an L2-active technique must run exclusively", info.ID)
		}
	}
}

func TestDefaultTechniques(t *testing.T) {
	want := []string{
		model.TechDirect, model.TechICMP, model.TechSrcPort53,
		model.TechSrcPort123, model.TechIPv6, model.TechGatewayRoute,
	}
	got := DefaultTechniques()
	if len(got) != len(want) {
		t.Fatalf("defaults = %v, want %v", got, want)
	}
	for _, id := range want {
		if !containsString(got, id) {
			t.Errorf("%s should be enabled by default", id)
		}
	}
	for _, id := range got {
		if isL2Active(id) {
			t.Errorf("%s is L2-active and must never be a default", id)
		}
	}
}

func TestSelectTechniquesEmptyMeansDefaults(t *testing.T) {
	got, dropped := selectTechniques(nil, false)
	if !reflect.DeepEqual(got, DefaultTechniques()) {
		t.Errorf("selected = %v, want the default set %v", got, DefaultTechniques())
	}
	if len(dropped) != 0 {
		t.Errorf("dropped = %v", dropped)
	}
}

func TestSelectTechniquesDropsL2WithoutPermission(t *testing.T) {
	req := []string{model.TechDirect, model.TechDot1QSubif, model.TechDoubleTag}

	got, dropped := selectTechniques(req, false)
	if !reflect.DeepEqual(got, []string{model.TechDirect}) {
		t.Errorf("selected = %v, want only direct", got)
	}
	if len(dropped) != 2 {
		t.Errorf("dropped = %v, want both L2 techniques", dropped)
	}

	got, dropped = selectTechniques(req, true)
	if len(got) != 3 {
		t.Errorf("selected = %v, want all three with AllowL2Active", got)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped = %v", dropped)
	}
}

func TestSelectTechniquesDropsUnknownAndDuplicates(t *testing.T) {
	got, dropped := selectTechniques([]string{"direct", "direct", "teleport", "icmp"}, false)
	if !reflect.DeepEqual(got, []string{model.TechDirect, model.TechICMP}) {
		t.Errorf("selected = %v", got)
	}
	if !reflect.DeepEqual(dropped, []string{"teleport"}) {
		t.Errorf("dropped = %v, want [teleport]", dropped)
	}
}

func TestSelectTechniquesKeepsCatalogOrder(t *testing.T) {
	got, _ := selectTechniques([]string{model.TechIPv6, model.TechDirect, model.TechICMP}, false)
	want := []string{model.TechDirect, model.TechICMP, model.TechIPv6}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("selected = %v, want catalogue order %v", got, want)
	}
}

func TestSrcPortTechniqueMapping(t *testing.T) {
	want := map[string]uint16{
		model.TechSrcPort53: 53, model.TechSrcPort88: 88, model.TechSrcPort123: 123,
		model.TechSrcPort20: 20, model.TechSrcPort67: 67, model.TechSrcPort500: 500,
	}
	if !reflect.DeepEqual(srcPortTechniques, want) {
		t.Errorf("srcPortTechniques = %v", srcPortTechniques)
	}
	for id := range srcPortTechniques {
		if _, ok := techniqueByID[id]; !ok {
			t.Errorf("%s has a source port but is not in the catalogue", id)
		}
	}
}

func TestSortedVLANs(t *testing.T) {
	got := sortedVLANs([]int{300, 0, 10, 4095, 10, -1, 42})
	want := []int{10, 42, 300}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sortedVLANs = %v, want %v (sorted, de-duplicated, 0/4095 rejected)", got, want)
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
