package manifest

// View is the JSON shape of a policy, shared by `audit --json`, the activity
// log and the dashboard. Network is the enum name, paths stay symbolic
// (${CWD}, ~), and Summary is the one-line Effective.Summary() form.
//
// For a grant or an effective policy (Effective.View) Write, Deny and Env are
// never nil; Read is nil when reads are unrestricted beyond the deny list. For
// a request as written (Manifest.View) every field the manifest omitted is
// nil, so a consumer can tell "asked for nothing" from "asked for an empty
// list".
type View struct {
	Network      string   `json:"network"` // none | localhost | all
	Write        []string `json:"write"`
	Read         []string `json:"read,omitempty"` // nil = everything except deny
	Deny         []string `json:"deny"`
	DenyPatterns []string `json:"denyPatterns,omitempty"`
	ExecAny      bool     `json:"execAny"`
	Exec         []string `json:"exec,omitempty"`
	Env          []string `json:"env"`
	AutoAllow    bool     `json:"autoAllow"`
	Summary      string   `json:"summary"` // Effective.Summary() format
}

// View renders a resolved policy. Slices are copied; nil Write, Deny and Env
// become empty lists so the JSON always carries arrays for them.
func (e Effective) View() View {
	return View{
		Network:      e.Network.String(),
		Write:        nonNil(cloneStrings(e.Write)),
		Read:         cloneStrings(e.Read),
		Deny:         nonNil(cloneStrings(e.Deny)),
		DenyPatterns: cloneStrings(e.DenyPatterns),
		ExecAny:      e.ExecAny,
		Exec:         cloneStrings(e.Exec),
		Env:          nonNil(cloneStrings(e.Env)),
		AutoAllow:    e.AutoAllow,
		Summary:      e.Summary(),
	}
}

// View renders the request exactly as written: fields the manifest omitted
// are nil, Deny is the manifest's own deny list (patterns included, not
// split), AutoAllow is false because a request cannot ask for approval, and
// Summary uses the Effective.Summary() format over the request's own fields.
func (m Manifest) View() View {
	req := Effective{
		Network: m.Network,
		Write:   m.Filesystem.Write,
		Env:     m.Env,
		ExecAny: m.ExecAny,
		Exec:    m.Exec,
	}
	return View{
		Network:   m.Network.String(),
		Write:     cloneStrings(m.Filesystem.Write),
		Read:      cloneStrings(m.Filesystem.Read),
		Deny:      cloneStrings(m.Filesystem.Deny),
		ExecAny:   m.ExecAny,
		Exec:      cloneStrings(m.Exec),
		Env:       cloneStrings(m.Env),
		AutoAllow: false,
		Summary:   req.Summary(),
	}
}

// nonNil turns a nil slice into an empty one.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
