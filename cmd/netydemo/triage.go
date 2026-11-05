package main

import (
	"context"
	"math/rand"

	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

// A mission that has been worked on for three days has been triaged. A demo where every
// row still reads "to do" shows the inventory and none of the pass over it, which is half
// of what the tool is for.
//
// What is seeded here is the shape of a real pass rather than a random sprinkle: the
// noisy ports of the office workstations are cleared in bulk, the servers are where the
// attention went, one machine is out of scope because it belongs to the client's own IT,
// and a couple of findings turned out to be wrong rather than merely uninteresting.

func seedTriage(ctx context.Context, st *store.Store, missionID int64, userID int64, rng *rand.Rand) error {
	services, err := st.ListServices(ctx, store.ServiceFilter{MissionID: missionID})
	if err != nil {
		return err
	}
	findings, err := st.ListFindings(ctx, store.FindingFilter{MissionID: missionID})
	if err != nil {
		return err
	}
	hosts, err := st.ListHosts(ctx, missionID, 0)
	if err != nil {
		return err
	}

	set := func(status model.TriageStatus, note string) (*model.TriageStatus, *string) {
		s := status
		if note == "" {
			return &s, nil
		}
		n := note
		return &s, &n
	}

	// The workstation ports nobody is going to test one by one.
	noise := map[int]bool{135: true, 137: true, 139: true, 5040: true}
	for _, sv := range services {
		switch {
		case noise[int(sv.Port)]:
			s, n := set(model.TriageDone, "")
			if _, err := st.SetServiceTriage(ctx, sv.ID, s, n, userID); err != nil {
				return err
			}
		case sv.Port == 445 && rng.Intn(3) == 0:
			s, n := set(model.TriageFlagged, "SMB signing off, relay path to the file server.")
			if _, err := st.SetServiceTriage(ctx, sv.ID, s, n, userID); err != nil {
				return err
			}
		case sv.Port == 6379 || sv.Port == 9200:
			s, n := set(model.TriageFlagged, "No authentication at all. In the report.")
			if _, err := st.SetServiceTriage(ctx, sv.ID, s, n, userID); err != nil {
				return err
			}
		case sv.Port == 22 && rng.Intn(2) == 0:
			s, n := set(model.TriageDone, "Key auth only, modern algorithms. Nothing to say.")
			if _, err := st.SetServiceTriage(ctx, sv.ID, s, n, userID); err != nil {
				return err
			}
		case sv.Port == 443 && rng.Intn(4) == 0:
			s, n := set(model.TriageInProgress, "Checking whether the console is reachable from the office VLAN.")
			if _, err := st.SetServiceTriage(ctx, sv.ID, s, n, userID); err != nil {
				return err
			}
		}
	}

	// One machine is the client's own: out of scope, and everything attached to it goes
	// out of the way with it.
	for _, h := range hosts {
		if h.Hostname == "PC-DIR-01" {
			s, n := set(model.TriageSkipped, "The IT manager's own laptop. Agreed out of scope at the kick-off.")
			if _, err := st.SetHostTriage(ctx, h.ID, s, n, userID); err != nil {
				return err
			}
		}
	}

	// The findings pass. Self-signed certificates on an internal estate are the textbook
	// thing an operator waves away; the two false positives are a different judgement and
	// are recorded as one.
	for i, f := range findings {
		switch {
		case f.CheckID == "tls-cert-self-signed":
			s, n := set(model.TriageSkipped, "Internal CA, known and accepted by the client. Not worth the time.")
			if _, err := st.SetFindingTriage(ctx, f.ID, s, n, userID); err != nil {
				return err
			}
		case f.CheckID == "ssh-password-auth":
			s, n := set(model.TriageFalsePositive, "Password auth is refused by the PAM stack; the banner advertises it, the server does not accept it.")
			if _, err := st.SetFindingTriage(ctx, f.ID, s, n, userID); err != nil {
				return err
			}
		case f.Severity == model.SevCritical || f.Severity == model.SevHigh:
			s, n := set(model.TriageFlagged, "Reproduced by hand, screenshot taken.")
			if _, err := st.SetFindingTriage(ctx, f.ID, s, n, userID); err != nil {
				return err
			}
		case i%3 == 0:
			s, n := set(model.TriageDone, "")
			if _, err := st.SetFindingTriage(ctx, f.ID, s, n, userID); err != nil {
				return err
			}
		}
	}
	return nil
}
