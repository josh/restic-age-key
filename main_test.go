package main

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"restic-age-key": main,
	})
}

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir:             "testdata",
		ContinueOnError: true,
		// UpdateScripts:   os.Getenv("CI") != "1",
	})
}
