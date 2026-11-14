package sh

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Run ejecuta un comando (stdout+stderr combinados) con timeout.
func Run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// RunStdout ejecuta un comando devolviendo solo stdout (para parsear JSON).
func RunStdout(timeout time.Duration, dir, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var so bytes.Buffer
	cmd.Stdout = &so
	err := cmd.Run()
	return so.String(), err
}

func Have(name string) bool { _, err := exec.LookPath(name); return err == nil }

func ReadFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func Exists(p string) bool { _, err := os.Stat(p); return err == nil }

func Trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
