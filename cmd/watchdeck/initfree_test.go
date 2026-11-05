package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The hook is this binary, so every package init runs on every Bash call
// Claude Code makes (CONTRIBUTING "Packages linked into the hook must be
// init-free", DESIGN §7). Two tests guard that for every package of this
// module that cmd/watchdeck links, found with `go list -deps`, so a new
// package is covered without editing a list:
//
//   - TestLinkedPackagesHaveNoInitWork runs the built binary under
//     GODEBUG=inittrace=1 and fails if any package of this module reports
//     init work. This is the ground truth: it sees what the compiler could
//     not lay out statically, whatever the source looks like.
//   - TestLinkedPackagesAreInitFreeInSource is the locator. It parses every
//     non-test, non-generated .go file of those packages, for every GOOS
//     (build tags are ignored, so linux-only files are checked on a Mac),
//     and names the file:line of a func init, or of a package-level var
//     whose initialiser calls a function or builds a map. Map literals are
//     found by their type: a map type written out, a named type of the same
//     package whose underlying type is a map, and elided inner literals
//     (`[]map[string]bool{{...}}`, struct fields of map type). Allowed calls:
//     errors.New with a string literal (inittrace on darwin arm64, go1.27.2,
//     2026-10-13, shows it is laid out statically) and type conversions
//     (`[]byte("x")`, `T(1)` for a same-package or builtin T, and the
//     qualified types in convertibleQualified).
//
//     The source check is syntactic, not go/types. Known gaps: a map type
//     named in another package (`url.Values{}`, `http.Header{}`), a type
//     alias of one, and a conversion to a qualified type not in the list
//     (reported as a call, a false positive). The inittrace test still
//     catches the gaps on each OS it runs on (darwin locally, ubuntu in CI).
//
// Use lazyre.Regexp for a package-level regexp, a sync.Once for other
// tables, and a switch instead of a lookup map.

const modulePath = "github.com/Panda-Taps-LLC/watchdeck"

type listedPackage struct {
	ImportPath string
	Dir        string
	Standard   bool
	Module     *struct{ Path string }
}

// linkedModulePackages returns the packages of this module that the
// watchdeck command links, from `go list -deps -json`.
func linkedModulePackages(t *testing.T) []listedPackage {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not on PATH")
	}
	cmd := exec.Command(goBin, "list", "-deps", "-json", ".")
	cmd.Dir = pkgDir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []listedPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("go list output: %v", err)
		}
		if !p.Standard && p.Module != nil && p.Module.Path == modulePath {
			pkgs = append(pkgs, p)
		}
	}
	if len(pkgs) < 10 {
		t.Fatalf("go list found %d packages of %s; expected the whole tree", len(pkgs), modulePath)
	}
	return pkgs
}

func TestLinkedPackagesAreInitFreeInSource(t *testing.T) {
	for _, p := range linkedModulePackages(t) {
		paths, err := filepath.Glob(filepath.Join(p.Dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		var files []*ast.File
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			if !ast.IsGenerated(f) {
				files = append(files, f)
			}
		}
		c := &initChecker{errorf: t.Errorf, fset: fset, pkg: p.ImportPath, types: packageTypes(files)}
		for _, f := range files {
			c.file(f)
		}
	}
}

// packageTypes maps each type name declared in files to its type expression.
func packageTypes(files []*ast.File) map[string]ast.Expr {
	types := map[string]ast.Expr{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, s := range gd.Specs {
				ts := s.(*ast.TypeSpec)
				types[ts.Name.Name] = ts.Type
			}
		}
	}
	return types
}

// initChecker reports init work in the package-level declarations of one
// package; types holds that package's named types.
type initChecker struct {
	errorf func(format string, args ...any)
	fset   *token.FileSet
	pkg    string
	types  map[string]ast.Expr
}

func (c *initChecker) report(n ast.Node, what string) {
	pos := c.fset.Position(n.Pos())
	c.errorf("%s/%s:%d: %s", c.pkg, filepath.Base(pos.Filename), pos.Line, what)
}

func (c *initChecker) file(f *ast.File) {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "init" {
			c.report(fd, "declares func init")
		}
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, s := range gd.Specs {
			for _, v := range s.(*ast.ValueSpec).Values {
				c.expr(v, nil)
			}
		}
	}
}

// underlying follows same-package type names and parentheses to the type
// expression they stand for; anything else is returned as is.
func (c *initChecker) underlying(e ast.Expr) ast.Expr {
	for i := 0; i < 16 && e != nil; i++ {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr: // a generic instantiation
			e = x.X
		case *ast.Ident:
			d, ok := c.types[x.Name]
			if !ok {
				return e
			}
			e = d
		default:
			return e
		}
	}
	return e
}

// expr checks an initialiser; implied is the type an elided composite
// literal at e would have, or nil.
func (c *initChecker) expr(e ast.Expr, implied ast.Expr) {
	switch x := e.(type) {
	case *ast.CompositeLit:
		c.lit(x, implied)
		return
	case *ast.UnaryExpr:
		if cl, ok := x.X.(*ast.CompositeLit); ok && x.Op == token.AND {
			var elem ast.Expr
			if star, ok := c.underlying(implied).(*ast.StarExpr); ok {
				elem = star.X
			}
			c.lit(cl, elem)
			return
		}
	}
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false // a function value; its body runs later
		case *ast.CompositeLit:
			c.lit(x, nil)
			return false
		case *ast.CallExpr:
			if staticErrorsNew(x) {
				return false
			}
			if c.isType(x.Fun) {
				return true // a conversion; its operand is still checked
			}
			c.report(x, "package-level var calls a function")
		}
		return true
	})
}

// lit checks a composite literal and, through the literal's type, every
// elided literal inside it.
func (c *initChecker) lit(cl *ast.CompositeLit, implied ast.Expr) {
	typ := cl.Type
	if typ == nil {
		typ = implied
	}
	var key, elem ast.Expr
	var fields []ast.Expr // struct field types in order
	named := map[string]ast.Expr{}
	under := c.underlying(typ)
	if star, ok := under.(*ast.StarExpr); ok && cl.Type == nil {
		under = c.underlying(star.X) // an elided &T{...} in a []*T
	}
	switch u := under.(type) {
	case *ast.MapType:
		c.report(cl, "package-level map literal")
		key, elem = u.Key, u.Value
	case *ast.ArrayType:
		elem = u.Elt
	case *ast.StructType:
		for _, f := range u.Fields.List {
			n := len(f.Names)
			if n == 0 {
				n = 1 // embedded field
			}
			for i := 0; i < n; i++ {
				fields = append(fields, f.Type)
			}
			for _, name := range f.Names {
				named[name.Name] = f.Type
			}
		}
	}
	for i, el := range cl.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if id, isIdent := kv.Key.(*ast.Ident); isIdent && len(named) > 0 {
				c.expr(kv.Value, named[id.Name])
				continue
			}
			c.expr(kv.Key, key)
			c.expr(kv.Value, elem)
			continue
		}
		if fields != nil {
			var ft ast.Expr
			if i < len(fields) {
				ft = fields[i]
			}
			c.expr(el, ft)
			continue
		}
		c.expr(el, elem)
	}
}

// builtinTypes are the predeclared types a conversion may name.
var builtinTypes = []string{
	"bool", "byte", "rune", "string", "error", "any",
	"int", "int8", "int16", "int32", "int64",
	"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
	"float32", "float64", "complex64", "complex128",
}

// convertibleQualified are types of other packages that a package-level
// conversion may name. Without go/types a qualified call cannot be told
// from a conversion, so this list is explicit.
var convertibleQualified = []string{"time.Duration", "fs.FileMode", "os.FileMode"}

// isType reports whether e, the callee of a call, names a type, which makes
// the call a conversion.
func (c *initChecker) isType(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return c.isType(x.X)
	case *ast.ArrayType, *ast.StarExpr, *ast.FuncType, *ast.ChanType, *ast.InterfaceType, *ast.MapType:
		return true
	case *ast.Ident:
		if _, ok := c.types[x.Name]; ok {
			return true
		}
		return slices.Contains(builtinTypes, x.Name)
	case *ast.SelectorExpr:
		if pkg, ok := x.X.(*ast.Ident); ok {
			return slices.Contains(convertibleQualified, pkg.Name+"."+x.Sel.Name)
		}
	}
	return false
}

// staticErrorsNew reports errors.New("literal"), which needs no init code.
func staticErrorsNew(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "New" || len(c.Args) != 1 {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "errors" {
		return false
	}
	lit, ok := c.Args[0].(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// TestInitCheckerCases runs the source check on snippets, so its rules are
// pinned without a real offender in the tree.
func TestInitCheckerCases(t *testing.T) {
	cases := []struct {
		name string
		src  string
		bad  int // number of reports
	}{
		{"map literal", `var m = map[string]bool{"a": true}`, 1},
		{"named map type", `type set map[string]bool; var m = set{"a": true}`, 1},
		{"named chain", `type set map[string]bool; type set2 set; var m = set2{}`, 1},
		{"elided in slice", `var m = []map[string]bool{{"a": true}, {}}`, 2},
		{"elided named in slice", `type set map[string]bool; var m = []set{{"a": true}}`, 1},
		{"struct field by name", `type s struct{ x int; m map[string]bool }; var v = s{m: map[string]bool{}}`, 1},
		{"struct field elided via pointer slice", `type s struct{ m map[string]int }; var v = []*s{{m: map[string]int{}}}`, 1},
		{"address of struct", `type s struct{ m map[string]int }; var v = &s{m: map[string]int{}}`, 1},
		{"struct field named map type", `type set map[string]bool; type s struct{ m set }; var v = []s{{m: set{}}}`, 1},
		{"positional struct", `type set map[string]bool; type s struct{ n int; m set }; var v = []s{{1, {}}}`, 1},
		{"map in struct in array", `type s struct{ m map[string]int }; var v = [2]s{{m: map[string]int{}}}`, 1},
		{"call", `var r = regexp.MustCompile("a")`, 1},
		{"call in slice", `var r = []int{f()}`, 1},
		{"errors.New", `var e = errors.New("x")`, 0},
		{"byte conversion", `var b = []byte("x")`, 0},
		{"builtin conversion", `var n = int64(5)`, 0},
		{"same-package conversion", `type kind int; var k = kind(3)`, 0},
		{"qualified conversion", `var d = time.Duration(5)`, 0},
		{"conversion of a call", `var b = []byte(f())`, 1},
		{"func literal body", `var f = func() map[string]bool { return map[string]bool{} }`, 0},
		{"slice of strings", `var s = []string{"a"}`, 0},
		{"lazyre", `var r = lazyre.Regexp{Expr: "a"}`, 0},
		{"init func", `func init() {}`, 1},
		{"method named init", `type x int; func (x) init() {}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", "package x\n"+strings.ReplaceAll(tc.src, "; ", "\n"), parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			c := &initChecker{errorf: func(string, ...any) { n++ }, fset: fset, pkg: "x", types: packageTypes([]*ast.File{f})}
			c.file(f)
			if n != tc.bad {
				t.Errorf("%d reports, want %d", n, tc.bad)
			}
		})
	}
}

func TestLinkedPackagesHaveNoInitWork(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := testBinary(t)
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "hook")
	cmd.Dir = tmp
	cmd.Stdin = strings.NewReader("")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(tmp, "config"),
		"XDG_CACHE_HOME=" + filepath.Join(tmp, "cache"),
		"XDG_STATE_HOME=" + filepath.Join(tmp, "state"),
		"WATCHDECK_ACTIVITY=" + filepath.Join(tmp, "state", "activity.jsonl"),
		"GODEBUG=inittrace=1",
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run() // the exit code of an empty hook call is not the point

	sc := bufio.NewScanner(&stderr)
	inits := 0
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "init ") {
			continue
		}
		inits++
		if fields := strings.Fields(line); len(fields) > 1 && strings.HasPrefix(fields[1], modulePath) {
			t.Errorf("package has init work on every hook call: %s", line)
		}
	}
	if inits == 0 {
		t.Fatalf("no inittrace lines; GODEBUG=inittrace=1 had no effect?\n%s", stderr.String())
	}
}
