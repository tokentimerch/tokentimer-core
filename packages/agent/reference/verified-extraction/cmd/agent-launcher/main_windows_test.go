//go:build windows

package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestTrustPolicyIsReleaseBoundAndFailsClosed(t *testing.T) {
	p := trustPolicy{publisher: strings.Repeat("a", 64), runtimePublisher: strings.Repeat("b", 64), installer: strings.Repeat("c", 64), commit: strings.Repeat("d", 40), version: "0.18.2", architecture: runtime.GOARCH}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*trustPolicy){
		"publisher":         func(p *trustPolicy) { p.publisher = "" },
		"runtime publisher": func(p *trustPolicy) { p.runtimePublisher = strings.Repeat("A", 64) },
		"installer":         func(p *trustPolicy) { p.installer = "" },
		"commit":            func(p *trustPolicy) { p.commit = "" },
		"version":           func(p *trustPolicy) { p.version = "latest" },
		"architecture":      func(p *trustPolicy) { p.architecture = "x86" },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			change(&q)
			if q.validate() == nil {
				t.Fatal("incomplete policy accepted")
			}
		})
	}
	if (trustPolicy{}).validate() == nil {
		t.Fatal("empty build policy accepted")
	}
}
