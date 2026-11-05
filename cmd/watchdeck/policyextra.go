package main

import (
	"os"
	"path/filepath"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/index"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
)

// policyFiles are the user overrides.yaml and the project .watchdeck.yaml
// of the current directory's git root ("" outside a repository), and that
// root ("" too).
func policyFiles(hp paths.Paths) (user, project, root string) {
	cwd, _ := os.Getwd()
	return policyFilesAt(hp, cwd)
}

// policyFilesAt is policyFiles for a working directory other than this
// one (rules explain --cwd), as the hook finds them for a session there.
func policyFilesAt(hp paths.Paths, cwd string) (user, project, root string) {
	if root = index.ProjectRoot(cwd, hp.Home); root != "" {
		project = filepath.Join(root, manifest.ProjectOverridesFile)
	}
	return hp.OverridesFile(), project, root
}

// policyExtra is the set of extra hook registrations the policy needs (M6.3)
// for a settings file at user scope, or at project scope when projectTarget
// is set: the policy files of policyFiles, and the pack rules whose native
// twins are installed for that target (coveredTwins, read once here).
// `enforce install`, `setup` and `doctor` use it.
func policyExtra(projectTarget bool) settings.Extra {
	hp, _, err := hostPaths()
	if err != nil {
		return settings.Extra{}
	}
	user, project, root := policyFiles(hp)
	return settings.NeededExtra(user, project, coveredTwins(hp, nativeRoot(projectTarget, root)))
}

// nativeRoot is the project root whose settings count toward coveredTwins:
// none for a user-scope install, whose hooks serve every project, so native
// rules that live in one project's files do not drop a file-tools hook for
// the rest; the git root (else the current directory, as --project resolves
// it) for a project-scope install.
func nativeRoot(projectTarget bool, root string) string {
	if !projectTarget {
		return ""
	}
	if root == "" {
		root, _ = os.Getwd()
	}
	return root
}

// nativeState reads, read-only, the Claude Code settings Claude Code reads
// for root (managed and user always; project and local when root is set):
// the pack rules whose recommended native twins are all there
// (rulebook.CoveredTwins), and whether every recommended rule is. Settings
// that exist but cannot be read cover nothing, so every hook stays.
func nativeState(hp paths.Paths, root string) (covered []string, all bool) {
	eff, err := claudesettings.Read(claudesettings.Locate(hp, root), nil)
	if err != nil {
		return nil, false
	}
	return rulebook.CoveredTwins(eff), len(rulebook.RecommendedMissing(eff)) == 0
}

// coveredTwins is nativeState's covered list.
func coveredTwins(hp paths.Paths, root string) []string {
	covered, _ := nativeState(hp, root)
	return covered
}
