// ============================================================
//
//	OTOTP — TOTP / HOTP 2FA Code Generator & Validator
//	Author  : khaled.s.haddad
//	Website : owlsec.org
//	Language: Go (stdlib only, CGO disabled, static build) — OWL suite
//
//	TOTP (RFC 6238) and HOTP (RFC 4226) implemented from scratch on
//	crypto/hmac and the SHA-1/SHA-256/SHA-512 families. Generate live
//	codes, validate with a drift window, mint new secrets with an
//	otpauth:// provisioning URI, and inspect existing otpauth URIs.
//
// ============================================================
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func header(title string) {
	fmt.Println()
	rule()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const BANNER = `
 ██████╗ ████████╗ ██████╗ ████████╗██████╗
██╔═══██╗╚══██╔══╝██╔═══██╗╚══██╔══╝██╔══██╗
██║   ██║   ██║   ██║   ██║   ██║   ██████╔╝
██║   ██║   ██║   ██║   ██║   ██║   ██╔═══╝
╚██████╔╝   ██║   ╚██████╔╝   ██║   ██║
 ╚═════╝    ╚═╝    ╚═════╝    ╚═╝   ╚═╝
`

const (
	APPNAME = "OTOTP"
	SUITE   = "Owl 2FA Suite"
	SUBLINE = "TOTP · HOTP · Validate · Secret + otpauth URI · Inspect"
	VERSION = "1.0"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Core: RFC 4226 (HOTP) / RFC 6238 (TOTP) — stdlib only
// ---------------------------------------------------------------------------

func hashFor(algo string) func() hash.Hash {
	switch strings.ToUpper(strings.TrimSpace(algo)) {
	case "SHA256", "SHA-256":
		return sha256.New
	case "SHA512", "SHA-512":
		return sha512.New
	default:
		return sha1.New
	}
}

func normAlgo(algo string) string {
	switch strings.ToUpper(strings.TrimSpace(algo)) {
	case "SHA256", "SHA-256":
		return "SHA256"
	case "SHA512", "SHA-512":
		return "SHA512"
	default:
		return "SHA1"
	}
}

// decodeSecret accepts a base32 secret (spaces/lowercase/padding tolerated).
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, fmt.Errorf("empty secret")
	}
	if m := len(s) % 8; m != 0 {
		s += strings.Repeat("=", 8-m)
	}
	return base32.StdEncoding.DecodeString(s)
}

// hotp implements RFC 4226 dynamic truncation.
func hotp(key []byte, counter uint64, digits int, algo string) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(hashFor(algo), key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code = code % mod
	return fmt.Sprintf("%0*d", digits, code)
}

func totpAt(key []byte, t time.Time, period, digits int, algo string) string {
	counter := uint64(t.Unix()) / uint64(period)
	return hotp(key, counter, digits, algo)
}

// ---------------------------------------------------------------------------
// Interactive handlers
// ---------------------------------------------------------------------------

func askInt(label string, def int) int {
	v := prompt(label + " [" + strconv.Itoa(def) + "]")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func askStr(label, def string) string {
	v := prompt(label + " [" + def + "]")
	if v == "" {
		return def
	}
	return v
}

func doTOTPNow() {
	sec := prompt("base32 secret")
	key, err := decodeSecret(sec)
	if err != nil {
		errMsg("bad base32 secret: " + err.Error())
		pause()
		return
	}
	digits := askInt("digits", 6)
	period := askInt("period seconds", 30)
	algo := normAlgo(askStr("algorithm (SHA1/SHA256/SHA512)", "SHA1"))
	clear()
	banner()
	header("TOTP — current code")
	now := time.Now()
	code := totpAt(key, now, period, digits, algo)
	rem := period - int(now.Unix()%int64(period))
	info(fmt.Sprintf("Key bytes : %d", len(key)))
	info(fmt.Sprintf("Algorithm : %s   Digits: %d   Period: %ds", algo, digits, period))
	fmt.Println()
	fmt.Println("   " + col("▸ CODE  ", CY) + col(code, GRN+B))
	fmt.Println()
	if rem <= 5 {
		warnMsg(fmt.Sprintf("Valid for %d more second(s) — expiring soon", rem))
	} else {
		info(fmt.Sprintf("Valid for %d more second(s)", rem))
	}
	prev := totpAt(key, now.Add(-time.Duration(period)*time.Second), period, digits, algo)
	next := totpAt(key, now.Add(time.Duration(period)*time.Second), period, digits, algo)
	fmt.Println()
	table([]string{"Window", "Code"}, [][]string{
		{"-1 (prev)", prev},
		{" 0 (now) ", col(code, GRN+B)},
		{"+1 (next)", next},
	})
	pause()
}

func doHOTP() {
	sec := prompt("base32 secret")
	key, err := decodeSecret(sec)
	if err != nil {
		errMsg("bad base32 secret: " + err.Error())
		pause()
		return
	}
	counter := askInt("counter value", 0)
	digits := askInt("digits", 6)
	algo := normAlgo(askStr("algorithm (SHA1/SHA256/SHA512)", "SHA1"))
	clear()
	banner()
	header(fmt.Sprintf("HOTP — counters %d..%d", counter, counter+4))
	rows := [][]string{}
	for i := 0; i < 5; i++ {
		c := uint64(counter + i)
		rows = append(rows, []string{strconv.FormatUint(c, 10), hotp(key, c, digits, algo)})
	}
	table([]string{"Counter", "Code"}, rows)
	pause()
}

func doValidate() {
	sec := prompt("base32 secret")
	key, err := decodeSecret(sec)
	if err != nil {
		errMsg("bad base32 secret: " + err.Error())
		pause()
		return
	}
	code := strings.TrimSpace(prompt("code to validate"))
	digits := len(code)
	if digits < 6 || digits > 8 {
		digits = askInt("digits", 6)
	}
	period := askInt("period seconds", 30)
	algo := normAlgo(askStr("algorithm (SHA1/SHA256/SHA512)", "SHA1"))
	window := askInt("allowed +/- steps", 1)
	clear()
	banner()
	header("TOTP — validation")
	ok, step := validateTOTP(key, code, time.Now(), period, digits, algo, window)
	if ok {
		okMsg(fmt.Sprintf("VALID — matched at step offset %+d (%+d sec drift)", step, step*period))
	} else {
		errMsg("INVALID — no match within ±" + strconv.Itoa(window) + " step(s)")
	}
	pause()
}

// validateTOTP returns whether code matches within +/- window steps, and the matching step.
func validateTOTP(key []byte, code string, now time.Time, period, digits int, algo string, window int) (bool, int) {
	for s := -window; s <= window; s++ {
		cand := totpAt(key, now.Add(time.Duration(s*period)*time.Second), period, digits, algo)
		if hmac.Equal([]byte(cand), []byte(code)) {
			return true, s
		}
	}
	return false, 0
}

func doGenSecret() {
	n := askInt("secret length in bytes (10=80bit,20=160bit)", 20)
	if n < 10 {
		n = 10
	}
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	b32 := strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "=")
	issuer := askStr("issuer label", "OWL")
	account := askStr("account name", "user@owlsec.org")
	clear()
	banner()
	header("New shared secret")
	info(fmt.Sprintf("Generated %d random bytes (%d-bit)", n, n*8))
	fmt.Println()
	fmt.Println("   " + col("secret : ", CY) + col(b32, GRN+B))
	uri := provisioningURI(issuer, account, b32, "SHA1", 6, 30)
	fmt.Println()
	info("Provisioning URI (paste into your authenticator):")
	fmt.Println("   " + col(uri, W))
	key, _ := decodeSecret(b32)
	fmt.Println()
	info("Current TOTP for this secret: " + col(totpAt(key, time.Now(), 30, 6, "SHA1"), GRN+B))
	pause()
}

func provisioningURI(issuer, account, b32, algo string, digits, period int) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", b32)
	q.Set("issuer", issuer)
	q.Set("algorithm", normAlgo(algo))
	q.Set("digits", strconv.Itoa(digits))
	q.Set("period", strconv.Itoa(period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func doParseURI() {
	raw := prompt("otpauth:// URI")
	fields, live, err := parseOtpauth(raw)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	clear()
	banner()
	header("otpauth:// inspector")
	rows := [][]string{}
	for _, f := range fields {
		rows = append(rows, []string{f[0], f[1]})
	}
	table([]string{"Field", "Value"}, rows)
	if live != "" {
		fmt.Println()
		okMsg("Live code (now): " + col(live, GRN+B))
	}
	pause()
}

// parseOtpauth returns ordered fields, a live code (if a totp secret decodes), or error.
func parseOtpauth(raw string) ([][2]string, string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "otpauth" {
		return nil, "", fmt.Errorf("not a valid otpauth:// URI")
	}
	q := u.Query()
	label := strings.TrimPrefix(u.Path, "/")
	algo := firstNonEmpty(q.Get("algorithm"), "SHA1")
	digS := firstNonEmpty(q.Get("digits"), "6")
	perS := firstNonEmpty(q.Get("period"), "30")
	fields := [][2]string{
		{"type", u.Host},
		{"label", label},
		{"secret", q.Get("secret")},
		{"issuer", q.Get("issuer")},
		{"algorithm", algo},
		{"digits", digS},
		{"period", perS},
	}
	if u.Host == "hotp" {
		fields = append(fields, [2]string{"counter", firstNonEmpty(q.Get("counter"), "0")})
	}
	live := ""
	if u.Host == "totp" && q.Get("secret") != "" {
		if key, err := decodeSecret(q.Get("secret")); err == nil {
			d, _ := strconv.Atoi(digS)
			p, _ := strconv.Atoi(perS)
			if d == 0 {
				d = 6
			}
			if p == 0 {
				p = 30
			}
			live = totpAt(key, time.Now(), p, d, algo)
		}
	}
	return fields, live, nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Interactive menu
// ---------------------------------------------------------------------------

func menu(title string, items [][2]string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
			col(pad(it[0], 30), W) + col("─ "+it[1], DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 30), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 30), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	rule()
	return prompt("Select option")
}

func interactive() {
	for {
		c := menu("Main Menu", [][2]string{
			{"Generate TOTP code (now)", "RFC 6238 time-based, live code"},
			{"Generate HOTP codes", "RFC 4226 counter-based table"},
			{"Validate a TOTP code", "with a ± drift window"},
			{"New secret + otpauth URI", "random base32 + QR-ready URI"},
			{"Inspect otpauth:// URI", "decode fields + live code"},
		})
		switch strings.ToLower(c) {
		case "1":
			doTOTPNow()
		case "2":
			doHOTP()
		case "3":
			doValidate()
		case "4":
			doGenSecret()
		case "5":
			doParseURI()
		case "h", "help", "?":
			tuiHelp()
		case "0", "00", "q", "exit", "":
			clear()
			okMsg("Goodbye — owlsec.org")
			return
		default:
			warnMsg("unknown selection")
			pause()
		}
	}
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    " + APPNAME + " [flags]            (no flags → interactive TUI)")
	fmt.Println()
	sec("MODES")
	fmt.Println("    --totp             print the current TOTP code (needs --secret)")
	fmt.Println("    --hotp             print a HOTP code (needs --secret, --counter)")
	fmt.Println("    --validate CODE    check CODE against --secret within --window steps")
	fmt.Println("    --gen              mint a random secret + otpauth URI")
	fmt.Println("    --parse URI        decode an otpauth:// URI (and print a live code)")
	fmt.Println()
	sec("PARAMETERS")
	fmt.Println("    --secret STR       base32 shared secret")
	fmt.Println("    --algo NAME        SHA1 (default) | SHA256 | SHA512")
	fmt.Println("    --digits N         code length (default 6)")
	fmt.Println("    --period N         TOTP step seconds (default 30)")
	fmt.Println("    --counter N        HOTP counter (default 0)")
	fmt.Println("    --window N         validation drift, ± steps (default 1)")
	fmt.Println("    --issuer STR       issuer label for --gen (default OWL)")
	fmt.Println("    --account STR      account name for --gen")
	fmt.Println("    --bytes N          secret size for --gen (default 20)")
	fmt.Println()
	sec("OUTPUT")
	fmt.Println("    --quiet            print only the code / result — scriptable")
	fmt.Println("    --no-color         disable ANSI colour")
	fmt.Println()
	sec("GENERAL")
	fmt.Println("    --demo  --selftest  --version  -h/--help")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    " + APPNAME + " --totp --secret JBSWY3DPEHPK3PXP")
	fmt.Println("    " + APPNAME + " --totp --secret JBSWY3DPEHPK3PXP --quiet")
	fmt.Println("    " + APPNAME + " --hotp --secret JBSWY3DPEHPK3PXP --counter 5")
	fmt.Println("    " + APPNAME + " --validate 123456 --secret JBSWY3DPEHPK3PXP --window 2")
	fmt.Println("    " + APPNAME + " --gen --issuer ACME --account alice@acme.io")
	fmt.Println("    " + APPNAME + " --parse 'otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME'")
	fmt.Println()
	rule()
}

func cliTOTP(secret, algo string, digits, period int, quiet bool) int {
	key, err := decodeSecret(secret)
	if err != nil {
		errMsg("bad base32 secret: " + err.Error())
		return 2
	}
	code := totpAt(key, time.Now(), period, digits, normAlgo(algo))
	if quiet {
		fmt.Println(code)
		return 0
	}
	banner()
	header("TOTP — current code")
	now := time.Now()
	rem := period - int(now.Unix()%int64(period))
	info(fmt.Sprintf("Algorithm : %s   Digits: %d   Period: %ds", normAlgo(algo), digits, period))
	fmt.Println()
	fmt.Println("   " + col("▸ CODE  ", CY) + col(code, GRN+B) + col(fmt.Sprintf("   (valid %ds)", rem), DIM))
	return 0
}

func cliHOTP(secret, algo string, digits int, counter uint64, quiet bool) int {
	key, err := decodeSecret(secret)
	if err != nil {
		errMsg("bad base32 secret: " + err.Error())
		return 2
	}
	code := hotp(key, counter, digits, normAlgo(algo))
	if quiet {
		fmt.Println(code)
		return 0
	}
	banner()
	header("HOTP code")
	info(fmt.Sprintf("Algorithm : %s   Digits: %d   Counter: %d", normAlgo(algo), digits, counter))
	fmt.Println()
	fmt.Println("   " + col("▸ CODE  ", CY) + col(code, GRN+B))
	return 0
}

func cliValidate(code, secret, algo string, digits, period, window int, quiet bool) int {
	key, err := decodeSecret(secret)
	if err != nil {
		errMsg("bad base32 secret: " + err.Error())
		return 2
	}
	if digits == 0 {
		digits = len(code)
	}
	ok, step := validateTOTP(key, code, time.Now(), period, digits, normAlgo(algo), window)
	if ok {
		if !quiet {
			okMsg(fmt.Sprintf("VALID — step offset %+d", step))
		} else {
			fmt.Println("VALID")
		}
		return 0
	}
	if !quiet {
		errMsg("INVALID — no match within ±" + strconv.Itoa(window) + " step(s)")
	} else {
		fmt.Println("INVALID")
	}
	return 1
}

func cliGen(issuer, account string, nbytes int, quiet bool) int {
	if nbytes < 10 {
		nbytes = 10
	}
	raw := make([]byte, nbytes)
	if _, err := rand.Read(raw); err != nil {
		errMsg(err.Error())
		return 2
	}
	b32 := strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "=")
	uri := provisioningURI(issuer, account, b32, "SHA1", 6, 30)
	if quiet {
		fmt.Println(b32)
		return 0
	}
	banner()
	header("New shared secret")
	fmt.Println("   " + col("secret : ", CY) + col(b32, GRN+B))
	fmt.Println("   " + col("uri    : ", CY) + col(uri, W))
	return 0
}

func cliParse(raw string, quiet bool) int {
	fields, live, err := parseOtpauth(raw)
	if err != nil {
		errMsg(err.Error())
		return 2
	}
	if quiet {
		if live != "" {
			fmt.Println(live)
		}
		return 0
	}
	banner()
	header("otpauth:// inspector")
	rows := [][]string{}
	for _, f := range fields {
		rows = append(rows, []string{f[0], f[1]})
	}
	table([]string{"Field", "Value"}, rows)
	if live != "" {
		fmt.Println()
		okMsg("Live code (now): " + col(live, GRN+B))
	}
	return 0
}

// ---------------------------------------------------------------------------
// Help (TUI) — shares the house help layout
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	out := []string{}
	cur := ""
	for _, w := range words {
		if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
			out = append(out, cur)
			cur = w
		} else if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	out = append(out, cur)
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}
func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}
func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func tuiHelp() {
	clear()
	banner()
	rule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	rule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	rule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	usage()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OTOTP generates and checks the one-time codes used for two-factor authentication. It implements TOTP (RFC 6238, time-based) and HOTP (RFC 4226, counter-based) from scratch on the Go standard library (crypto/hmac + SHA-1/256/512).",
	"Use it to generate a live 2FA code from a shared secret, validate a code with a drift window, mint a brand-new secret with an otpauth:// provisioning URI for an authenticator app, or decode and inspect an existing otpauth URI.",
}
var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Each option asks for its inputs; press Enter to accept the default shown in brackets. [H] opens this help, [0] or q quits.",
	"Secrets are entered in base32 (spaces, lowercase and padding are tolerated). Everything also works from the command line (see page 2) for scripting.",
}
var owlHelpMenu = []owlHelpItem{
	{"1", "Generate TOTP code: enter a base32 secret, digits, period and algorithm; prints the current code, seconds remaining, and the previous/next window codes."},
	{"2", "Generate HOTP codes: enter a secret and a starting counter; prints a table of five consecutive counter-based codes."},
	{"3", "Validate a TOTP code: paste a secret and a code; OTOTP checks it against the current, previous and next windows (± your chosen step count) and reports the drift."},
	{"4", "New secret + otpauth URI: generates a random base32 secret and a ready-to-scan otpauth:// URI, and proves it by printing the current code."},
	{"5", "Inspect otpauth:// URI: decodes the type, label, secret, issuer, algorithm, digits and period, and prints a live code when it is a totp URI."},
}
var owlHelpTips = []owlHelpItem{
	{"*", "Most services use the defaults: SHA1, 6 digits, 30-second period. Change them only if the provider says so."},
	{"*", "When validating, a window of 1 tolerates one 30-second step of clock drift each way. Keep it small (1–2) to limit the attack surface."},
	{"*", "--quiet prints only the code, handy in scripts: CODE=$(OTOTP --totp --secret \"$S\" --quiet)."},
	{"*", "Run --selftest to check OTOTP against the published RFC 4226 and RFC 6238 test vectors."},
}

// ---------------------------------------------------------------------------
// Demo + self-test
// ---------------------------------------------------------------------------

func runDemo() {
	banner()
	header("Demo — RFC test-vector secret")
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32 of "12345678901234567890"
	key, _ := decodeSecret(secret)
	info("base32 secret : " + secret)
	info("decoded (ASCII): 12345678901234567890")
	fmt.Println()
	rows := [][]string{}
	for _, c := range []uint64{0, 1, 2, 3, 4} {
		rows = append(rows, []string{strconv.FormatUint(c, 10), hotp(key, c, 6, "SHA1")})
	}
	fmt.Println("  " + col("HOTP (SHA1, 6 digits):", B+CY))
	table([]string{"Counter", "Code"}, rows)
	fmt.Println()
	t := time.Unix(59, 0)
	fmt.Println("  " + col("TOTP at Unix t=59 (RFC 6238):", B+CY))
	table([]string{"Algorithm", "8-digit code"}, [][]string{
		{"SHA1", totpAt(key, t, 30, 8, "SHA1")},
	})
}

func runSelfTest() int {
	banner()
	header("Self-Test — RFC 4226 / RFC 6238 known-answer vectors")
	pass, fail := 0, 0
	check := func(name, got, want string) {
		if got == want {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W))
			fmt.Println("        got  " + col(got, GY))
			fmt.Println("        want " + col(want, GY))
		}
	}

	// RFC 4226 Appendix D — HOTP, secret ASCII "12345678901234567890", SHA1, 6 digits.
	hkey := []byte("12345678901234567890")
	hotpWant := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}
	for i, w := range hotpWant {
		check(fmt.Sprintf("HOTP RFC4226 count=%d", i), hotp(hkey, uint64(i), 6, "SHA1"), w)
	}

	// RFC 6238 Appendix B — TOTP, 8 digits, period 30, three seed lengths.
	sha1Key := []byte("12345678901234567890")
	sha256Key := []byte("12345678901234567890123456789012")
	sha512Key := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	type tv struct {
		t                    int64
		sha1, sha256, sha512 string
	}
	vectors := []tv{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}
	for _, v := range vectors {
		tm := time.Unix(v.t, 0)
		check(fmt.Sprintf("TOTP RFC6238 SHA1   t=%d", v.t), totpAt(sha1Key, tm, 30, 8, "SHA1"), v.sha1)
		check(fmt.Sprintf("TOTP RFC6238 SHA256 t=%d", v.t), totpAt(sha256Key, tm, 30, 8, "SHA256"), v.sha256)
		check(fmt.Sprintf("TOTP RFC6238 SHA512 t=%d", v.t), totpAt(sha512Key, tm, 30, 8, "SHA512"), v.sha512)
	}

	// base32 decode tolerance (spaces / lowercase / missing padding).
	if k, err := decodeSecret("jbsw y3dp ehpk 3pxp"); err == nil && len(k) == 10 {
		pass++
		fmt.Println("  " + col("[✔] ", GRN) + col("base32 decode tolerates spaces/lowercase/padding", W))
	} else {
		fail++
		fmt.Println("  " + col("[✘] ", R) + col("base32 decode tolerance", W))
	}

	// validateTOTP accepts the correct current code and rejects a wrong one.
	nowCode := totpAt(sha1Key, time.Now(), 30, 6, "SHA1")
	if ok, _ := validateTOTP(sha1Key, nowCode, time.Now(), 30, 6, "SHA1", 1); ok {
		pass++
		fmt.Println("  " + col("[✔] ", GRN) + col("validateTOTP accepts the current code", W))
	} else {
		fail++
		fmt.Println("  " + col("[✘] ", R) + col("validateTOTP accepts the current code", W))
	}
	if ok, _ := validateTOTP(sha1Key, "000000", time.Now(), 30, 6, "SHA1", 1); !ok {
		pass++
		fmt.Println("  " + col("[✔] ", GRN) + col("validateTOTP rejects a wrong code", W))
	} else {
		fail++
		fmt.Println("  " + col("[✘] ", R) + col("validateTOTP rejects a wrong code", W))
	}

	// otpauth round-trip: build a URI, parse it back, confirm the secret survives.
	uri := provisioningURI("ACME", "alice@acme.io", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30)
	if fields, _, err := parseOtpauth(uri); err == nil {
		got := ""
		for _, f := range fields {
			if f[0] == "secret" {
				got = f[1]
			}
		}
		if got == "JBSWY3DPEHPK3PXP" {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col("otpauth URI build→parse round-trip", W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col("otpauth URI round-trip (secret mismatch)", W))
		}
	} else {
		fail++
		fmt.Println("  " + col("[✘] ", R) + col("otpauth URI round-trip (parse failed)", W))
	}

	fmt.Println()
	rule()
	if fail == 0 {
		okMsg(fmt.Sprintf("ALL %d CHECKS PASSED", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}

// ---------------------------------------------------------------------------

func main() {
	var (
		fTOTP  = flag.Bool("totp", false, "")
		fHOTP  = flag.Bool("hotp", false, "")
		fVal   = flag.String("validate", "", "")
		fGen   = flag.Bool("gen", false, "")
		fParse = flag.String("parse", "", "")

		fSecret = flag.String("secret", "", "")
		fAlgo   = flag.String("algo", "SHA1", "")
		fDigits = flag.Int("digits", 6, "")
		fPeriod = flag.Int("period", 30, "")
		fCount  = flag.Int("counter", 0, "")
		fWindow = flag.Int("window", 1, "")
		fIssuer = flag.String("issuer", "OWL", "")
		fAcct   = flag.String("account", "user@owlsec.org", "")
		fBytes  = flag.Int("bytes", 20, "")

		fQuiet = flag.Bool("quiet", false, "")
		fNoCol = flag.Bool("no-color", false, "")
		fDemo  = flag.Bool("demo", false, "")
		fSelf  = flag.Bool("selftest", false, "")
		fVerN  = flag.Bool("version", false, "")
	)
	flag.Usage = usage
	flag.Parse()
	if *fNoCol {
		noColor = true
	}
	switch {
	case *fVerN:
		fmt.Printf("%s %s  (OWL suite — %s / %s)\n", APPNAME, VERSION, AUTHOR, WEBSITE)
		return
	case *fSelf:
		os.Exit(runSelfTest())
	case *fDemo:
		runDemo()
		return
	case *fTOTP:
		os.Exit(cliTOTP(*fSecret, *fAlgo, *fDigits, *fPeriod, *fQuiet))
	case *fHOTP:
		os.Exit(cliHOTP(*fSecret, *fAlgo, *fDigits, uint64(*fCount), *fQuiet))
	case *fVal != "":
		os.Exit(cliValidate(*fVal, *fSecret, *fAlgo, *fDigits, *fPeriod, *fWindow, *fQuiet))
	case *fGen:
		os.Exit(cliGen(*fIssuer, *fAcct, *fBytes, *fQuiet))
	case *fParse != "":
		os.Exit(cliParse(*fParse, *fQuiet))
	default:
		interactive()
	}
}
