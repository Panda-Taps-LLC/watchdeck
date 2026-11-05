package scan

import (
	"regexp"
	"sync"
)

// rule is one regex mapped to a category. name is stable and appears in
// Hit.Pattern; keep names unique across all tables.
type rule struct {
	cat  Category
	name string
	re   *regexp.Regexp
	not  *regexp.Regexp // optional: a line matching this is not a hit (cheap negative lookahead)
	lits [][]byte       // pre-filter: a matching line must contain one of these (nil = no filter)
}

func mk(cat Category, name, expr string) rule {
	return rule{cat: cat, name: name, re: regexp.MustCompile(expr), lits: requiredLiterals(expr)}
}

func mkx(cat Category, name, expr, exclude string) rule {
	return rule{cat: cat, name: name, re: regexp.MustCompile(expr), not: regexp.MustCompile(exclude), lits: requiredLiterals(expr)}
}

// match reports whether line triggers the rule.
func (r rule) match(line []byte) bool {
	return r.re.Match(line) && (r.not == nil || !r.not.Match(line))
}

// cmdPos anchors a shell word at command position: start of line, after a
// pipe / `;` / `&` / `(` / `$(`, or after a control keyword, optionally
// negated with `!`.
const cmdPos = `(?:^|[|;&(]|\$\(|\b(?:if|then|else|elif|do|while|until|time|nohup)\s)\s*(?:!\s*)?`

// sudoOpt allows an optional sudo prefix (with flags) before a command word.
const sudoOpt = `(?:sudo\s+(?:-\S+\s+)*)?`

// jsNetMods are JS/TS modules whose import implies network access.
const jsNetMods = `(?:node:)?(?:axios|node-fetch|undici|https?|net|ws|dgram|tls|http2|got|superagent|socket\.io(?:-client)?)`

// jsExecMods are JS/TS modules that spawn processes.
const jsExecMods = `(?:node:)?(?:child_process|execa|shelljs|zx|cross-spawn)`

// secretSuffix matches environment variable names that hold secrets.
const secretSuffix = `(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)`

// buildCommonRules: rules that apply to every script language (py, js, sh).
func buildCommonRules() []rule {
	return []rule{
		mk(Credential, "cred-home-path", `(?:~|\$\{?HOME\}?|%USERPROFILE%)/\.(?:ssh|aws|gnupg|netrc|config/gcloud|docker/config\.json|kube/config|azure)\b`),
		mk(Credential, "cred-dotdir-literal", `['"]\.(?:ssh|aws|gnupg)['"]`),
		mk(Credential, "cred-ssh-key-file", `\bid_(?:rsa|ed25519|ecdsa|dsa)\b`),
		mk(Credential, "cred-claude-credentials", `\.credentials\.json\b`),
		mk(Credential, "cred-macos-keychain", `\bsecurity\s+find-(?:generic|internet)-password\b`),
	}
}

// buildPyRules: rules that apply to Python.
func buildPyRules() []rule {
	return []rule{
		mk(Network, "py-net-import", `^\s*(?:import|from)\s+(?:requests\b|urllib3\b|urllib\.request\b|urllib\.error\b|urllib\s|urllib$|http\.client\b|httpx\b|aiohttp\b|websockets?\b|boto3\b|botocore\b|google\.(?:auth|oauth2|cloud|api_core)\b|googleapiclient\b|paramiko\b|smtplib\b|ftplib\b|pycurl\b|openai\b|anthropic\b)`),
		mkx(Network, "py-net-call", `\b(?:requests\.(?:get|post|put|delete|patch|head|request|Session)|urlopen|socket\.(?:socket|create_connection|create_server)|httpx\.(?:get|post|Client|AsyncClient)|http\.client\.HTTPS?Connection)\(`, `\bAF_UNIX\b`),
		mk(Credential, "py-dotenv", `\b(?:load_dotenv|dotenv_values|find_dotenv)\(`),
		mk(Credential, "py-open-dotenv", `\bopen\(\s*[^)]*\.env['"]`),
		mk(Credential, "py-keyring", `\bkeyring\.`),
		mk(Credential, "py-secret-env", `\bos\.(?:environ(?:\.get)?\s*[\[(]|getenv\()\s*['"]\w*`+secretSuffix+`['"]`),
		mk(Exec, "py-subprocess", `\bsubprocess\.`),
		mk(Exec, "py-os-exec", `\bos\.(?:system|popen|exec\w*|spawn\w*)\(`),
		mk(Exec, "py-async-subprocess", `\b(?:asyncio\.create_subprocess_\w+|pty\.spawn)\(`),
		mk(Environment, "py-environ", `\bos\.(?:environ\b|getenv\(|putenv\()`),
		mk(Encoding, "py-base64-decode", `\bbase64\.(?:b64decode|standard_b64decode|urlsafe_b64decode|b32decode|b16decode|decodebytes)\(`),
		mk(Encoding, "py-codecs-decode", `\bcodecs\.decode\(`),
		mk(Encoding, "py-exec-call", `(?:^|[^\w.])exec\(`),
		mk(Encoding, "py-eval-call", `(?:^|[^\w.])eval\(`),
		mk(Encoding, "py-compile-call", `(?:^|[^\w.])compile\(`),
		mk(Encoding, "py-marshal-pickle", `\b(?:marshal|pickle)\.loads\(`),
		mk(Encoding, "py-zlib-decompress", `\bzlib\.decompress\(`),
		mk(Filesystem, "py-shutil-destructive", `\bshutil\.(?:rmtree|move)\(`),
		mk(Filesystem, "py-os-remove", `\bos\.(?:remove|unlink|rmdir|removedirs)\(`),
		mk(Filesystem, "py-open-write-abs", `\bopen\(\s*['"](?:/|~)[^'"]*['"]\s*,\s*['"][wax]`),
		mk(Filesystem, "py-path-write-abs", `\bPath\(\s*['"](?:/|~)[^'"]*['"]\s*\)\.(?:write_text|write_bytes|mkdir|touch|unlink|rmdir)\(`),
		mk(Filesystem, "py-home-path", `\b(?:Path\.home\(\)|expanduser\(\s*['"]~)`),
	}
}

// buildJsRules: rules that apply to JavaScript and TypeScript.
func buildJsRules() []rule {
	return []rule{
		mk(Network, "js-fetch", `\bfetch\(`),
		mk(Network, "js-net-require", `\brequire\(\s*['"]`+jsNetMods+`['"]\s*\)`),
		mk(Network, "js-net-import", `\b(?:from|import)\s+['"]`+jsNetMods+`['"]`),
		mk(Network, "js-net-api", `\b(?:new\s+WebSocket\(|XMLHttpRequest\b|https?\.(?:get|request)\()`),
		mk(Credential, "js-secret-env", `\bprocess\.env(?:\.|\[\s*['"])\w*`+secretSuffix+`\b`),
		mk(Credential, "js-dotenv", `(?:\brequire\(\s*['"]dotenv(?:/config)?['"]|\b(?:from|import)\s+['"]dotenv(?:/config)?['"]|\bdotenv\.config\()`),
		mk(Exec, "js-child-process", `\b(?:require\(\s*['"]`+jsExecMods+`['"]|(?:from|import)\s+['"]`+jsExecMods+`['"]|child_process\b)`),
		mk(Exec, "js-exec-call", `\b(?:exec(?:File)?Sync|execFile|spawn(?:Sync)?|Deno\.run|Deno\.Command|Bun\.spawn)\(`),
		mk(Environment, "js-process-env", `\b(?:process|Deno|Bun)\.env\b`),
		mk(Encoding, "js-atob", `\batob\(`),
		mk(Encoding, "js-buffer-base64", `\bBuffer\.from\(\s*[^)]*,\s*['"]base64['"]`),
		mk(Encoding, "js-new-function", `\bnew\s+Function\(`),
		mk(Encoding, "js-eval", `(?:^|[^\w.])eval\(`),
		mk(Encoding, "js-vm-run", `\bvm\.(?:runIn\w+|Script)\(`),
		mk(Filesystem, "js-fs-write-abs", `\bfs\.(?:promises\.)?(?:write|rm|unlink|rmdir|append|mkdir|rename|chmod|chown|cp|copy)\w*\(\s*['"\x60](?:/|~)`),
		mk(Filesystem, "js-fs-rm-recursive", `\b(?:fs\.(?:promises\.)?rm(?:dir)?(?:Sync)?\([^)]*\brecursive\s*:\s*true|require\(\s*['"]rimraf['"])`),
		mk(Filesystem, "js-homedir", `\bos\.homedir\(`),
	}
}

// buildShRules: rules that apply to sh, bash and zsh.
func buildShRules() []rule {
	return []rule{
		mk(Network, "sh-net-cmd", cmdPos+sudoOpt+`(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|telnet|ftp)\b`),
		mk(Network, "sh-openssl-client", `\bopenssl\s+s_client\b`),
		mk(Network, "sh-dev-tcp", `/dev/(?:tcp|udp)/`),
		mk(Network, "sh-net-pkg", cmdPos+sudoOpt+`(?:pip3?|pipx|uv|npm|npx|pnpm|yarn|brew|apt(?:-get)?|gem|cargo|go)\s+(?:install|add|get|sync|download|fetch|update|upgrade)\b`),
		mk(Network, "sh-net-git", cmdPos+`git\s+(?:clone|pull|fetch|push|ls-remote|submodule\s+update)\b`),
		mk(Credential, "sh-dotenv", `(?:\b(?:source|cat|grep|sed|awk)\s+[^|;&#]*\.env|(?:^|[;&|(]|&&|\|\|)\s*\.\s+[^|;&#]*\.env|>>?\s*[^|;&#\s]*\.env)(?:[\s'"\x60)]|$)`),
		mk(Credential, "sh-secret-var", `\$\{?[A-Z0-9_]*`+secretSuffix+`\b`),
		mk(Credential, "sh-cred-cli", cmdPos+`(?:gh\s+auth\s+token|op\s+(?:read|item\s+get)|aws\s+configure\s+(?:get|export-credentials)|gcloud\s+auth\s+print-access-token)\b`),
		mk(Exec, "sh-exec-cmd", cmdPos+`(?:eval|exec|xargs|sudo|doas|osascript)\b`),
		mk(Exec, "sh-inline-interp", cmdPos+`(?:(?:ba|z|da)?sh|python3?|node|perl|ruby)\s+(?:-\w+\s+)*-[ce]\b`),
		mk(Environment, "sh-printenv", `\bprintenv\b`),
		mk(Environment, "sh-env-dump", cmdPos+`(?:env|export\s+-p|declare\s+-x)\s*(?:$|\||>)`),
		mk(Encoding, "sh-base64-decode", `\bbase64\s+(?:-d|--decode|-D)\b`),
		mk(Encoding, "sh-pipe-to-shell", `\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh|python3?|node|perl|ruby)\b`),
		mk(Encoding, "sh-openssl-decrypt", `\bopenssl\s+enc\b[^|;&]*\s-d\b`),
		mk(Encoding, "sh-hex-escapes", `(?:\\x[0-9a-fA-F]{2}){6,}`),
		mk(Encoding, "sh-xxd-reverse", `\bxxd\s+-r\b`),
		mk(Filesystem, "sh-rm-rf", `\brm\s+(?:-\S+\s+)*-\S*(?:[rR]\S*f|f\S*[rR])|\brm\s+(?:-\S+\s+)*-[rR]\S*\s+(?:-\S+\s+)*-f|\brm\s+(?:-\S+\s+)*-f\S*\s+(?:-\S+\s+)*-[rR]|\brm\s+(?:-\S+\s+)*--recursive\b`),
		mk(Filesystem, "sh-system-cmd", cmdPos+sudoOpt+`(?:chmod|chown|crontab|launchctl|systemctl|diskutil)\b`),
		mk(Filesystem, "sh-defaults-write", `\bdefaults\s+write\b`),
		mk(Filesystem, "sh-redirect-abs", `>>?\s*['"]?(?:~/|\$\{?HOME\}?/|/(?:etc|usr|Users|home|Library|var|opt|private|tmp)\b)`),
		mk(Filesystem, "sh-write-home", cmdPos+`(?:cp|mv|tee|install|mkdir|touch|ln)\s+(?:-\S+\s+)*[^|;&>#]*\s['"]?(?:~|\$\{?HOME\}?)/[^\s'"]*['"]?\s*(?:$|[|;&#])`),
	}
}

// buildInstrRules: rules that apply to SKILL.md prose only; all case-insensitive.
func buildInstrRules() []rule {
	return []rule{
		mk(Instruction, "instr-relocate-script", `(?i)\b(?:copy|move|cp|mv)\b.{0,40}\b(?:script|file|binary|hook)s?\b.{0,40}(?:/tmp\b|\belsewhere\b|\banother\s+(?:dir|directory|folder|location)\b|\bhidden\b)`),
		mk(Instruction, "instr-hide-from-user", `(?i)\b(?:do\s+not|don'?t|never)\s+(?:tell|mention|show|inform|reveal|disclose|alert|notify|warn)\s+(?:the\s+)?user\s+(?:about|that|of|what|when|if|this|these|anything)\b|\b(?:do\s+not|don'?t|never)\s+(?:tell|mention|show|reveal|disclose|report)\s+(?:this|that|it|these|them|anything|the\s+\w+(?:\s+\w+)?)\s+to\s+the\s+user\b|\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?user\b|\b(?:hide|conceal)\s+(?:this|it|that|these|the\s+\w+)\s+from\s+the\s+user\b`),
		mk(Instruction, "instr-ignore-previous", `(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules|guidance)\b`),
		mk(Instruction, "instr-pipe-to-interp", `(?i)\b(?:cat|curl|wget)\b.{0,80}\|\s*(?:sudo\s+)?(?:python3?|sh|bash|zsh|node)\b`),
		mk(Instruction, "instr-decode-and-run", `(?i)\bbase64\s+(?:-d|--decode|-D)\b.{0,40}\|\s*(?:sh|bash|zsh|python3?|node)\b`),
	}
}

// ruleTables holds the compiled tables. They are built on first use, not at
// package init: this package is linked into the hook binary, and compiling
// ~80 regexps at init cost about 1 ms on every hook call (DESIGN §7).
type ruleTables struct{ common, py, js, sh, instr []rule }

var (
	rulesOnce  sync.Once
	rulesTab   ruleTables
	rulesBuilt bool // set only after every table compiled
)

// tables returns the compiled tables, building them on the first call. If
// that build panicked (a bad expression) and the panic was recovered, the
// Once is spent but the tables are not built; every later call panics too,
// rather than scanning with empty tables and finding nothing.
func tables() *ruleTables {
	rulesOnce.Do(func() {
		t := ruleTables{
			common: buildCommonRules(),
			py:     buildPyRules(),
			js:     buildJsRules(),
			sh:     buildShRules(),
			instr:  buildInstrRules(),
		}
		rulesTab = t
		rulesBuilt = true
	})
	if !rulesBuilt {
		panic("scan: rule tables failed to build")
	}
	return &rulesTab
}

// rulesFor returns the rule set for an inventory language key.
func rulesFor(lang string) []rule {
	switch lang {
	case "py":
		return append(append([]rule{}, tables().py...), tables().common...)
	case "js", "ts":
		return append(append([]rule{}, tables().js...), tables().common...)
	case "sh":
		return append(append([]rule{}, tables().sh...), tables().common...)
	case "skillmd":
		return tables().instr
	}
	return nil
}

// allRules lists every table, for the coverage and pre-filter tests.
func allRules() []rule {
	t := tables()
	var all []rule
	all = append(all, t.py...)
	all = append(all, t.js...)
	all = append(all, t.sh...)
	all = append(all, t.common...)
	all = append(all, t.instr...)
	return all
}
