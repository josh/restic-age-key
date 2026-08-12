package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"restic-age-key": main,

		"print-file": printFileMain,
		"hang":       hangMain,

		"fake-age":         fakeAgeMain,
		"silent-age":       silentAgeMain,
		"broken-age":       brokenAgeMain,
		"flaky-age":        flakyAgeMain,
		"blocking-age":     blockingAgeMain,
		"slow-rclone":      slowRcloneMain,
		"age-plugin-crash": agePluginCrashMain,
		"age-plugin-hang":  agePluginHangMain,
	})
}

func TestScript(t *testing.T) {
	updateScripts, _ := strconv.ParseBool(os.Getenv("UPDATE_SCRIPTS"))

	testscript.Run(t, testscript.Params{
		Dir:                 "testdata",
		ContinueOnError:     true,
		UpdateScripts:       updateScripts,
		RequireExplicitExec: true,
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"touch":          scriptTouch,
			"wait4file":      scriptWait4file,
			"hardlink":       scriptHardlink,
			"capture-output": scriptCaptureOutput,
			"exit-status":    scriptExitStatus,
			"mode":           scriptMode,
			"sha256":         scriptSha256,
			"cut-chars":      scriptCutChars,
			"sort-lines":     scriptSortLines,
			"json-len":       scriptJSONLen,
			"json-get":       scriptJSONGet,
			"json-filter":    scriptJSONFilter,
			"json-find":      scriptJSONFind,
			"json-set":       scriptJSONSet,
			"json-del":       scriptJSONDel,
		},
		Setup: func(env *testscript.Env) error {
			env.Setenv("RESTIC_CACHE_DIR", filepath.Join(env.WorkDir, ".restic-cache"))
			return nil
		},
	})
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func runReal(name string, args []string) {
	path, err := exec.LookPath(name)
	if err != nil {
		fatalf("%v", err)
	}
	cmd := exec.Command(path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fatalf("%v", err)
	}
	os.Exit(0)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func printFileMain() {
	if len(os.Args) < 2 {
		fatalf("usage: print-file file...")
	}
	for _, name := range os.Args[1:] {
		file, err := os.Open(name)
		if err != nil {
			fatalf("print-file: %v", err)
		}
		_, err = io.Copy(os.Stdout, file)
		_ = file.Close()
		if err != nil {
			fatalf("print-file: %v", err)
		}
	}
}

func hangMain() {
	if len(os.Args) != 2 {
		fatalf("usage: hang seconds")
	}
	seconds, err := strconv.ParseFloat(os.Args[1], 64)
	if err != nil {
		fatalf("hang: %v", err)
	}
	time.Sleep(time.Duration(seconds * float64(time.Second)))
}

func fakeAgeMain() {
	os.Exit(1)
}

func silentAgeMain() {
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func brokenAgeMain() {
	fmt.Fprintln(os.Stderr, "age: error: plugin unavailable")
	os.Exit(1)
}

func flakyAgeMain() {
	work := os.Getenv("WORK")
	marker := filepath.Join(work, "failed-after-init")
	if fileExists(filepath.Join(work, "repo", "config")) && !fileExists(marker) {
		if err := os.WriteFile(marker, nil, 0o666); err != nil {
			fatalf("%v", err)
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(1)
	}
	runReal("age", os.Args[1:])
}

func blockingAgeMain() {
	work := os.Getenv("WORK")
	if err := os.WriteFile(filepath.Join(work, "age-started"), nil, 0o666); err != nil {
		fatalf("%v", err)
	}
	release := filepath.Join(work, "release-age")
	for attempt := 0; !fileExists(release); attempt++ {
		if attempt >= 200 {
			fatalf("timed out waiting for release-age")
		}
		time.Sleep(50 * time.Millisecond)
	}
	runReal("age", os.Args[1:])
}

func slowRcloneMain() {
	time.Sleep(30 * time.Second)
}

func agePluginCrashMain() {
	fmt.Println("CRASH")
	time.Sleep(1 * time.Second)
	_ = os.Stdout.Close()
	os.Exit(1)
}

func agePluginHangMain() {
	time.Sleep(10 * time.Second)
	os.Exit(1)
}

func requireArgs(ts *testscript.TestScript, neg bool, args []string, usage string, minArgs, maxArgs int) {
	if neg || len(args) < minArgs || len(args) > maxArgs {
		ts.Fatalf("usage: %s", usage)
	}
}

func scriptTouch(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "touch file", 1, 1)
	path := ts.MkAbs(args[0])
	if fileExists(path) {
		now := time.Now()
		ts.Check(os.Chtimes(path, now, now))
		return
	}
	ts.Check(os.WriteFile(path, nil, 0o666))
}

func scriptWait4file(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "wait4file file", 1, 1)
	path := ts.MkAbs(args[0])
	for attempt := 0; !fileExists(path); attempt++ {
		if attempt >= 200 {
			ts.Fatalf("timed out waiting for %s", args[0])
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func scriptHardlink(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "hardlink oldfile newfile", 2, 2)
	ts.Check(os.Link(ts.MkAbs(args[0]), ts.MkAbs(args[1])))
}

func scriptCaptureOutput(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "capture-output env-var", 1, 1)
	value := strings.TrimSuffix(ts.ReadFile("stdout"), "\n")
	if value == "" {
		ts.Fatalf("capture-output: stdout is empty")
	}
	if strings.Contains(value, "\n") {
		ts.Fatalf("capture-output: stdout has multiple lines")
	}
	ts.Setenv(args[0], value)
}

func scriptExitStatus(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "exit-status file program [args...]", 2, 64)
	err := ts.Exec(args[1], args[2:]...)
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		ts.Fatalf("exit-status: %v", err)
	}
	ts.Check(os.WriteFile(ts.MkAbs(args[0]), []byte(strconv.Itoa(code)+"\n"), 0o600))
}

func scriptMode(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "mode file", 1, 1)
	info, err := os.Stat(ts.MkAbs(args[0]))
	ts.Check(err)
	_, err = fmt.Fprintf(ts.Stdout(), "%03o\n", info.Mode().Perm())
	ts.Check(err)
}

func scriptSha256(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "sha256 path [env-var]", 1, 2)
	data, err := os.ReadFile(ts.MkAbs(args[0]))
	ts.Check(err)
	digest := sha256.Sum256(data)
	sum := hex.EncodeToString(digest[:])
	_, err = fmt.Fprintln(ts.Stdout(), sum)
	ts.Check(err)
	if len(args) == 2 {
		ts.Setenv(args[1], sum)
	}
}

func scriptCutChars(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "cut-chars file n", 2, 2)
	n, err := strconv.Atoi(args[1])
	if err != nil || n < 1 {
		ts.Fatalf("cut-chars: invalid length %q", args[1])
	}
	lines := readLines(ts, args[0])
	for i, line := range lines {
		if len(line) > n {
			lines[i] = line[:n]
		}
	}
	writeLines(ts, lines)
}

func scriptSortLines(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "sort-lines file", 1, 1)
	lines := readLines(ts, args[0])
	sort.Strings(lines)
	writeLines(ts, lines)
}

func readLines(ts *testscript.TestScript, file string) []string {
	text := strings.TrimSuffix(ts.ReadFile(file), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func writeLines(ts *testscript.TestScript, lines []string) {
	out := ts.Stdout()
	for _, line := range lines {
		_, err := fmt.Fprintln(out, line)
		ts.Check(err)
	}
}

func readJSON(ts *testscript.TestScript, file string) any {
	var value any
	ts.Check(json.Unmarshal([]byte(ts.ReadFile(file)), &value))
	return value
}

func jsonString(ts *testscript.TestScript, value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	data, err := json.Marshal(value)
	ts.Check(err)
	return string(data)
}

func jsonMatches(ts *testscript.TestScript, value any, matcher string) bool {
	name, want, ok := strings.Cut(matcher, "=")
	if !ok {
		ts.Fatalf("%q is not field=value", matcher)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	field, ok := object[name]
	if !ok {
		return false
	}
	return jsonString(ts, field) == want
}

func scriptJSONLen(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "json-len file", 1, 1)
	array, ok := readJSON(ts, args[0]).([]any)
	if !ok {
		ts.Fatalf("json-len: %s is not a JSON array", args[0])
	}
	_, err := fmt.Fprintln(ts.Stdout(), len(array))
	ts.Check(err)
}

func scriptJSONGet(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "json-get file field", 2, 2)
	value := readJSON(ts, args[0])
	elements, ok := value.([]any)
	if !ok {
		elements = []any{value}
	}
	out := ts.Stdout()
	for _, element := range elements {
		object, ok := element.(map[string]any)
		if !ok {
			ts.Fatalf("json-get: element is not a JSON object")
		}
		field, ok := object[args[1]]
		if !ok {
			ts.Fatalf("json-get: no field %q", args[1])
		}
		_, err := fmt.Fprintln(out, jsonString(ts, field))
		ts.Check(err)
	}
}

func scriptJSONFilter(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "json-filter file field=value", 2, 2)
	array, ok := readJSON(ts, args[0]).([]any)
	if !ok {
		ts.Fatalf("json-filter: %s is not a JSON array", args[0])
	}
	matches := make([]any, 0)
	for _, element := range array {
		if jsonMatches(ts, element, args[1]) {
			matches = append(matches, element)
		}
	}
	data, err := json.Marshal(matches)
	ts.Check(err)
	_, err = fmt.Fprintln(ts.Stdout(), string(data))
	ts.Check(err)
}

func scriptJSONFind(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "json-find dir field=value", 2, 2)
	dir := ts.MkAbs(args[0])
	entries, err := os.ReadDir(dir)
	ts.Check(err)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		ts.Check(err)
		var value any
		if json.Unmarshal(data, &value) != nil {
			continue
		}
		if jsonMatches(ts, value, args[1]) {
			_, err = fmt.Fprintln(ts.Stdout(), entry.Name())
			ts.Check(err)
			return
		}
	}
	ts.Fatalf("json-find: no file in %s matches %s", args[0], args[1])
}

func editJSONFile(ts *testscript.TestScript, inFile, outFile string, edit func(map[string]json.RawMessage)) {
	data, err := os.ReadFile(ts.MkAbs(inFile))
	ts.Check(err)
	var fields map[string]json.RawMessage
	ts.Check(json.Unmarshal(data, &fields))
	edit(fields)
	out, err := json.Marshal(fields)
	ts.Check(err)
	ts.Check(os.WriteFile(ts.MkAbs(outFile), out, 0o666))
}

func scriptJSONSet(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "json-set in-file out-file field=value...", 3, 16)
	editJSONFile(ts, args[0], args[1], func(fields map[string]json.RawMessage) {
		for _, pair := range args[2:] {
			name, value, ok := strings.Cut(pair, "=")
			if !ok {
				ts.Fatalf("json-set: %q is not field=value", pair)
			}
			data, err := json.Marshal(value)
			ts.Check(err)
			fields[name] = data
		}
	})
}

func scriptJSONDel(ts *testscript.TestScript, neg bool, args []string) {
	requireArgs(ts, neg, args, "json-del in-file out-file field...", 3, 16)
	editJSONFile(ts, args[0], args[1], func(fields map[string]json.RawMessage) {
		for _, name := range args[2:] {
			delete(fields, name)
		}
	})
}
