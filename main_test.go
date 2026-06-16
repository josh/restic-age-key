package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"restic-age-key": main,
	})
}

func TestScript(t *testing.T) {
	updateScripts, _ := strconv.ParseBool(os.Getenv("UPDATE_SCRIPTS"))

	testscript.Run(t, testscript.Params{
		Dir:             "testdata",
		ContinueOnError: true,
		UpdateScripts:   updateScripts,
		Setup: func(env *testscript.Env) error {
			env.Setenv("RESTIC_CACHE_DIR", filepath.Join(env.WorkDir, ".restic-cache"))
			return nil
		},
	})
}
