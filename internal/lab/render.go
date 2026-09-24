package lab

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

// Renderer turns deploy/lab.yaml into the configuration each container mounts.
//
// The configs under configs/ are the authoritative source: they are copied and
// then rewritten with the lab addresses, rather than re-authored here. That
// keeps the shipped configurations and the containerised ones in step, and it
// means a change to configs/ shows up in the stack.
type Renderer struct {
	RepoRoot   string
	DeployDir  string
	RuntimeDir string
	Lab        *Lab
}

// NewRenderer builds a renderer for a lab definition.
func NewRenderer(repoRoot, deployDir string, lab *Lab) *Renderer {
	return &Renderer{
		RepoRoot:   repoRoot,
		DeployDir:  deployDir,
		RuntimeDir: filepath.Join(deployDir, "runtime"),
		Lab:        lab,
	}
}

// Result reports what a render produced.
type Result struct {
	EnvFile string
	Files   []string
}

// Render writes deploy/.env and the whole deploy/runtime tree.
func (r *Renderer) Render() (*Result, error) {
	if err := os.MkdirAll(r.RuntimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("render: cannot create %s: %w", r.RuntimeDir, err)
	}
	// Start from a clean tree so a removed component does not leave stale config
	// behind for the next container to mount.
	for _, dir := range []string{"pyhss", "mariadb", "kamailio", "open5gs", "epdg", "enb", "strongswan", "freediameter"} {
		if err := os.RemoveAll(filepath.Join(r.RuntimeDir, dir)); err != nil {
			return nil, fmt.Errorf("render: cannot clear %s: %w", dir, err)
		}
	}

	res := &Result{}
	steps := []func() error{
		r.renderEnv,
		r.renderEPDG,
		r.renderENB,
		r.renderMariaDB,
		r.renderPyHSS,
		r.renderKamailio,
		r.renderOpen5GS,
		r.renderStrongSwan,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}

	res.EnvFile = filepath.Join(r.DeployDir, ".env")
	if err := filepath.Walk(r.RuntimeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, _ := filepath.Rel(r.DeployDir, path)
			res.Files = append(res.Files, rel)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("render: cannot list %s: %w", r.RuntimeDir, err)
	}
	sort.Strings(res.Files)
	return res, nil
}

// write renders a Go template to runtime/<name>.
func (r *Renderer) write(name, body string, data any) error {
	path := filepath.Join(r.RuntimeDir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmpl, err := template.New(filepath.Base(name)).Funcs(templateFuncs).Parse(body)
	if err != nil {
		return fmt.Errorf("render: template %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("render: template %s: %w", name, err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("render: cannot write %s: %w", path, err)
	}
	return nil
}

var templateFuncs = template.FuncMap{
	"join": func(sep string, items []string) string { return strings.Join(items, sep) },
}

// copyAndSubstitute copies a file from configs/ into the runtime tree and
// applies literal replacements. Every replacement is explicit so it is easy to
// see exactly what the lab changes about the shipped configuration.
func (r *Renderer) copyAndSubstitute(srcRel, dstRel string, subs [][2]string) error {
	src := filepath.Join(r.RepoRoot, srcRel)
	body, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("render: cannot read %s: %w", src, err)
	}
	text := string(body)
	for _, sub := range subs {
		if !strings.Contains(text, sub[0]) {
			// A missing pattern means configs/ changed under us; fail loudly
			// rather than silently producing a config with the wrong address.
			return fmt.Errorf("render: %s does not contain %q, the shipped config changed", srcRel, sub[0])
		}
		text = strings.ReplaceAll(text, sub[0], sub[1])
	}
	dst := filepath.Join(r.RuntimeDir, dstRel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, []byte(text), 0o644); err != nil {
		return fmt.Errorf("render: cannot write %s: %w", dst, err)
	}
	return nil
}

// copyTree copies a directory from configs/ into the runtime tree, applying the
// same substitutions to every file. Substitutions that do not match any file are
// ignored, which lets one list cover a whole directory.
func (r *Renderer) copyTree(srcRel, dstRel string, subs [][2]string) error {
	src := filepath.Join(r.RepoRoot, srcRel)
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(r.RuntimeDir, dstRel, rel), 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("render: cannot read %s: %w", path, err)
		}
		text := string(body)
		for _, sub := range subs {
			text = strings.ReplaceAll(text, sub[0], sub[1])
		}
		dst := filepath.Join(r.RuntimeDir, dstRel, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, []byte(text), 0o644)
	})
}
