// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)

// Resolver runs the resolve: the repositories to read POMs from, how many
// Maven probes at once, and the Maven binary.
type Resolver struct {
	HTTP *http.Client
	// RepositoryURLs are the repositories Maven and the POM reader use, Central when empty.
	RepositoryURLs []string
	// Servers are the credentials for the repositories that need them, matched by URL prefix.
	Servers []Server
	// Workers is how many probes run at once, four when zero.
	Workers int
	// BatchSize is how many components one Maven run resolves, forty when zero.
	BatchSize int
	// Progress, when set, is told after every batch: probes done, nodes known, the depth.
	Progress func(done, nodes, depth int)
	// Logf, when set, is told the detail: every Maven run with its duration, every fallback.
	Logf func(format string, a ...any)
	// Maven is the binary, mvn on PATH when empty.
	Maven string
	// ProbeTimeout bounds one Maven run, ten minutes when zero.
	ProbeTimeout time.Duration
}

// NewResolver returns a resolver on Central with four workers.
func NewResolver() *Resolver {
	return &Resolver{HTTP: &http.Client{Timeout: 60 * time.Second}, Workers: 4, Maven: "mvn", ProbeTimeout: 10 * time.Minute}
}

// Server is one repository's credentials: the line manager's own Nexus account for the
// release repository, which refuses anonymous reads. Central needs none.
type Server struct {
	URL      string
	User     string
	Password string
}

// server returns the credentials for a repository URL, if any.
func (r *Resolver) server(base string) (Server, bool) {
	for _, srv := range r.Servers {
		if strings.HasPrefix(base, strings.TrimSuffix(srv.URL, "/")) {
			return srv, true
		}
	}
	return Server{}, false
}

// settingsXML is the Maven settings file for a probe: one server per repository that
// has credentials, the ids matching the ones the throwaway POM declares, and the
// default http blocker of Maven 3.8 and later overridden, so an in cluster repository
// on plain http (the Nexus service address) is allowed. The override is the one Maven
// documents: a mirror with the blocker's id pointed at nothing.
func (r *Resolver) settingsXML() string {
	var b strings.Builder
	b.WriteString(`<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">` + "\n")
	b.WriteString("<mirrors>\n<mirror><id>maven-default-http-blocker</id><mirrorOf>osera-unblock-http</mirrorOf><name>http repositories allowed for the in cluster Nexus</name><url>http://0.0.0.0/</url><blocked>false</blocked></mirror>\n</mirrors>\n")
	b.WriteString("<servers>\n")
	for i, u := range r.repositories() {
		srv, found := r.server(u)
		if !found {
			continue
		}
		fmt.Fprintf(&b, "<server><id>osera-%d</id><username>%s</username><password>%s</password></server>\n", i, xmlEscape(srv.User), xmlEscape(srv.Password))
	}
	b.WriteString("</servers>\n</settings>\n")
	return b.String()
}

// needsSettings says whether a settings file must accompany the probe: any repository
// other than Central, since it may be plain http or need credentials.
func (r *Resolver) needsSettings() bool {
	repos := r.repositories()
	if len(repos) == 1 && repos[0] == Central {
		return false
	}
	return true
}

func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return ""
	}
	return b.String()
}

func (r *Resolver) repositories() []string {
	if len(r.RepositoryURLs) == 0 {
		return []string{Central}
	}
	return r.RepositoryURLs
}

func (r *Resolver) batchSize() int {
	if r.BatchSize <= 0 {
		return 40
	}
	return r.BatchSize
}

// say logs the detail when a logger was given.
func (r *Resolver) say(format string, a ...any) {
	if r.Logf != nil {
		r.Logf(format, a...)
	}
}

func (r *Resolver) workers() int {
	if r.Workers <= 0 {
		return 4
	}
	return r.Workers
}

// Resolve builds the graph of a line from its anchor. workDir holds the throwaway
// project of the build, and one fresh directory per probe when the fallback runs.
func (r *Resolver) Resolve(ctx context.Context, lineID string, anchor book.Anchor, rule Rule, workDir string) (*Graph, error) {
	// 1. the anchor's model: a BOM manages the roots, the rule picks them, a jar is the single root
	m, err := r.readModel(ctx, anchor.Group, anchor.Artifact, anchor.Version)
	if err != nil {
		return nil, errorf("anchor %s: %w", anchor, err)
	}
	g := &Graph{LineID: lineID, Anchor: anchor, RootsRule: rule.String(), Declared: componentsString(rule), Dependencies: map[string][]string{}, Unresolved: map[string]string{}}
	importBOM := m.Packaging == "pom"
	var roots []Component
	var managed []Component
	if importBOM {
		g.Pins = pinsFor(m.Managed, rule)
		managed = applyPins(m.Managed, g.Pins)
		for _, group := range unmanagedGroups(m.Managed, rule) {
			r.say("%s: the anchor %s manages nothing in the declared group %s, it gives no roots", lineID, anchor, group)
		}
		roots, err = r.roots(ctx, selectRoots(managed, rule))
		if err != nil {
			return nil, err
		}
	} else {
		roots = []Component{{Group: anchor.Group, Artifact: anchor.Artifact, Version: anchor.Version, Type: m.Packaging}}
	}
	if len(roots) == 0 {
		return nil, errorf("anchor %s manages nothing that is not a pom", anchor)
	}
	err = os.MkdirAll(workDir, 0o755)
	if err != nil {
		return nil, errorf("work directory: %w", err)
	}

	// 2. one build for the whole line, the way a bank builds it: Maven mediates, one version each
	r.say("%s: one Maven build of the line, %d roots as its dependencies", lineID, len(roots))
	started := time.Now()
	tree, why := r.buildLine(ctx, workDir, anchor, importBOM, managed, g.Pins, roots)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if why == "" {
		g.Method = "one build"
		graphFromTree(g, tree)
		g.sortAll()
		r.say("%s: Maven resolved %d libraries in %s", lineID, len(g.Components), time.Since(started).Round(time.Second))
		return g, nil
	}

	// 3. the fallback: every root probed alone, breadth first
	r.say("%s: the single build failed after %s (%s), every root probed alone in batches", lineID, time.Since(started).Round(time.Second), why)
	g.Method = "batched probes, the single build failed: " + why
	err = r.resolveByProbes(ctx, g, workDir, anchor, importBOM, roots)
	if err != nil {
		return nil, err
	}
	g.sortAll()
	return g, nil
}

// buildLine writes the line's project and runs dependency:tree on it once. The
// tree is returned on success; otherwise the reason it failed.
func (r *Resolver) buildLine(ctx context.Context, workDir string, anchor book.Anchor, importBOM bool, managed []Component, pins []Pin, roots []Component) (treeNode, string) {
	// 1. a fresh directory with the project
	dir, err := os.MkdirTemp(workDir, "line-")
	if err != nil {
		return treeNode{}, err.Error()
	}
	defer os.RemoveAll(dir)
	err = os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(r.linePOM(anchor, importBOM, managed, pins, roots)), 0o644)
	if err != nil {
		return treeNode{}, err.Error()
	}

	// 2. Maven, twice at most
	out := filepath.Join(dir, "tree.json")
	var mvnErr string
	for attempt := 0; attempt < 2; attempt++ {
		mvnErr = r.runMaven(ctx, dir, out, false)
		if mvnErr == "" {
			break
		}
		if ctx.Err() != nil {
			return treeNode{}, ctx.Err().Error()
		}
	}
	if mvnErr != "" {
		return treeNode{}, mvnErr
	}

	// 3. the tree
	raw, err := os.ReadFile(out)
	if err != nil {
		return treeNode{}, err.Error()
	}
	var root treeNode
	err = json.Unmarshal(raw, &root)
	if err != nil {
		return treeNode{}, "tree: " + err.Error()
	}
	if len(root.Children) == 0 {
		return treeNode{}, "tree: the build resolved nothing"
	}
	return root, ""
}

// linePOM is the line's throwaway project: the pinned artifacts managed first, so an
// explicit entry wins over the imported anchor, then the anchor imported when it is a
// BOM, and every root as a dependency.
func (r *Resolver) linePOM(anchor book.Anchor, importBOM bool, managed []Component, pins []Pin, roots []Component) string {
	var b strings.Builder
	b.WriteString(`<project xmlns="http://maven.apache.org/POM/4.0.0">` + "\n")
	b.WriteString("<modelVersion>4.0.0</modelVersion>\n")
	b.WriteString("<groupId>osera.line</groupId><artifactId>line</artifactId><version>1</version>\n")
	repos := r.repositories()
	if len(repos) > 1 || repos[0] != Central {
		b.WriteString("<repositories>\n")
		for i, u := range repos {
			fmt.Fprintf(&b, "<repository><id>osera-%d</id><url>%s</url></repository>\n", i, u)
		}
		b.WriteString("</repositories>\n")
	}
	if importBOM {
		b.WriteString("<dependencyManagement><dependencies>\n")
		for _, c := range pinnedArtifacts(managed, pins) {
			fmt.Fprintf(&b, "<dependency><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version>", c.Group, c.Artifact, c.Version)
			if c.Classifier != "" {
				fmt.Fprintf(&b, "<classifier>%s</classifier>", c.Classifier)
			}
			if c.Type != "" && c.Type != "jar" {
				fmt.Fprintf(&b, "<type>%s</type>", c.Type)
			}
			b.WriteString("</dependency>\n")
		}
		b.WriteString("<dependency>")
		fmt.Fprintf(&b, "<groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version><type>pom</type><scope>import</scope>", anchor.Group, anchor.Artifact, anchor.Version)
		b.WriteString("</dependency>\n</dependencies></dependencyManagement>\n")
	}
	b.WriteString("<dependencies>\n")
	for _, c := range roots {
		fmt.Fprintf(&b, "<dependency><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version>", c.Group, c.Artifact, c.Version)
		if c.Classifier != "" {
			fmt.Fprintf(&b, "<classifier>%s</classifier>", c.Classifier)
		}
		if c.Type != "" && c.Type != "jar" {
			fmt.Fprintf(&b, "<type>%s</type>", c.Type)
		}
		b.WriteString("</dependency>\n")
	}
	b.WriteString("</dependencies>\n</project>\n")
	return b.String()
}

// pinnedArtifacts is every managed artifact of a pinned group, at the pinned version.
func pinnedArtifacts(managed []Component, pins []Pin) []Component {
	var out []Component
	for _, c := range managed {
		for _, pin := range pins {
			if c.Group == pin.Group && c.Version == pin.To {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// graphFromTree fills the graph from the build's tree: every node a component,
// once per group, artifact and classifier (Maven has mediated, one version each),
// the edges the tree's parent to child links in compile and runtime scope, not
// optional, and the roots the project's direct dependencies.
func graphFromTree(g *Graph, root treeNode) {
	// 1. the roots
	nodes := map[string]Component{}
	byGA := map[string]string{}
	var walk func(parent treeNode)
	for _, ch := range childrenOf(root) {
		key := placeNode(ch, nodes, byGA)
		g.Roots = append(g.Roots, key)
	}

	// 2. every node's children, depth first, an edge per child
	walk = func(parent treeNode) {
		parentKey := byGA[gaKey(Component{Group: parent.GroupID, Artifact: parent.ArtifactID, Classifier: parent.Classifier, Type: firstOf(parent.Type, "jar")})]
		var edges []string
		for _, ch := range parent.Children {
			scope := firstOf(ch.Scope, "compile")
			if scope != "compile" && scope != "runtime" {
				continue
			}
			if bool(ch.Optional) {
				continue
			}
			c := Component{Group: ch.GroupID, Artifact: ch.ArtifactID, Version: ch.Version, Classifier: ch.Classifier, Type: firstOf(ch.Type, "jar")}
			key := placeNode(c, nodes, byGA)
			edges = append(edges, key)
			walk(ch)
		}
		if parentKey != "" {
			g.Dependencies[parentKey] = mergeEdges(g.Dependencies[parentKey], edges)
		}
	}
	for _, ch := range root.Children {
		walk(ch)
	}

	// 3. the components
	for _, c := range nodes {
		g.Components = append(g.Components, c)
	}
}

// placeNode records a component once per group, artifact and classifier and returns its key;
// a second version of the same library, which a mediated tree should never carry, is
// folded onto the first one seen.
func placeNode(c Component, nodes map[string]Component, byGA map[string]string) string {
	ga := gaKey(c)
	if key, seen := byGA[ga]; seen {
		return key
	}
	nodes[c.Key()] = c
	byGA[ga] = c.Key()
	return c.Key()
}

// gaKey is group:artifact with the classifier and a non jar type, without the version.
func gaKey(c Component) string {
	k := c.Group + ":" + c.Artifact
	if c.Classifier != "" {
		k += ":" + c.Classifier
	}
	if c.Type != "" && c.Type != "jar" {
		k += ":" + c.Type
	}
	return k
}

// mergeEdges adds the new edges to the known ones, each once.
func mergeEdges(known, more []string) []string {
	seen := map[string]bool{}
	for _, k := range known {
		seen[k] = true
	}
	for _, k := range more {
		if !seen[k] {
			seen[k] = true
			known = append(known, k)
		}
	}
	return known
}

// resolveByProbes is the fallback: every root probed alone, its children queued,
// breadth first until nothing new appears, batches of roots per Maven run.
func (r *Resolver) resolveByProbes(ctx context.Context, g *Graph, workDir string, anchor book.Anchor, importBOM bool, roots []Component) error {
	// 1. the queue
	nodes := map[string]Component{}
	var queue []Component
	for _, c := range roots {
		if _, seen := nodes[c.Key()]; seen {
			continue
		}
		nodes[c.Key()] = c
		g.Roots = append(g.Roots, c.Key())
		queue = append(queue, c)
	}
	done := 0
	if r.Progress != nil {
		r.Progress(0, len(nodes), 0)
	}

	// 2. breadth first
	for depth := 0; len(queue) > 0; depth++ {
		batch := queue
		queue = nil
		results, err := r.probeAll(ctx, workDir, anchor, importBOM, batch)
		if err != nil {
			return err
		}
		done += len(batch)
		if r.Progress != nil {
			r.Progress(done, len(nodes), depth)
		}
		for _, res := range results {
			if res.err != "" {
				g.Unresolved[res.parent.Key()] = res.err
			}
			var edges []string
			for _, child := range res.children {
				edges = append(edges, child.Key())
				if _, seen := nodes[child.Key()]; seen {
					continue
				}
				nodes[child.Key()] = child
				queue = append(queue, child)
			}
			g.Dependencies[res.parent.Key()] = edges
		}
	}

	// 3. the components
	for _, c := range nodes {
		g.Components = append(g.Components, c)
	}
	return nil
}

// roots keeps the managed artifacts whose packaging is not pom, read with the worker pool.
func (r *Resolver) roots(ctx context.Context, managed []Component) ([]Component, error) {
	type answer struct {
		index int
		keep  bool
		err   error
	}
	answers := make([]answer, len(managed))
	var wg sync.WaitGroup
	sem := make(chan struct{}, r.workers())
	for i, c := range managed {
		wg.Add(1)
		go func(i int, c Component) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if c.Type == "pom" {
				answers[i] = answer{index: i}
				return
			}
			raw, err := r.fetchPOM(ctx, c.Group, c.Artifact, c.Version)
			if err != nil {
				// a managed artifact with no POM in the repositories: not on the line
				answers[i] = answer{index: i}
				return
			}
			var p pom
			err = xmlUnmarshal(raw, &p)
			if err != nil {
				answers[i] = answer{index: i, err: err}
				return
			}
			answers[i] = answer{index: i, keep: firstOf(p.Packaging, "jar") != "pom"}
		}(i, c)
	}
	wg.Wait()
	var out []Component
	for _, a := range answers {
		if a.err != nil {
			return nil, errorf("reading the managed POMs: %w", a.err)
		}
		if a.keep {
			out = append(out, managed[a.index])
		}
	}
	return out, nil
}

// probeResult is what one probe found: the direct children, or why it could not run.
type probeResult struct {
	parent   Component
	children []Component
	err      string
}

// probeAll resolves the batch: BatchSize components per Maven run, Workers runs at a time.
func (r *Resolver) probeAll(ctx context.Context, workDir string, anchor book.Anchor, importBOM bool, batch []Component) ([]probeResult, error) {
	results := make([]probeResult, len(batch))
	var wg sync.WaitGroup
	sem := make(chan struct{}, r.workers())
	size := r.batchSize()
	for start := 0; start < len(batch); start += size {
		end := start + size
		if end > len(batch) {
			end = len(batch)
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			started := time.Now()
			chunk := r.probeBatch(ctx, workDir, anchor, importBOM, batch[start:end])
			copy(results[start:end], chunk)
			failed := 0
			for _, res := range chunk {
				if res.err != "" {
					failed++
				}
			}
			r.say("Maven run: %d libraries resolved in %s, %d could not be", end-start, time.Since(started).Round(time.Second), failed)
		}(start, end)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return results, nil
}

// probeBatch resolves several components in one Maven run: a throwaway multi module
// project, one module per component, the reactor run once with --fail-at-end so a
// module that fails does not stop the others. A module whose tree is missing falls
// back to the single probe, so nothing is lost when one component breaks the batch.
func (r *Resolver) probeBatch(ctx context.Context, workDir string, anchor book.Anchor, importBOM bool, chunk []Component) []probeResult {
	results := make([]probeResult, len(chunk))

	// 1. the project: the parent and one module per component
	dir, err := os.MkdirTemp(workDir, "batch-")
	if err != nil {
		for i, c := range chunk {
			results[i] = probeResult{parent: c, err: err.Error()}
		}
		return results
	}
	defer os.RemoveAll(dir)
	err = r.writeBatch(dir, anchor, importBOM, chunk)
	if err != nil {
		for i, c := range chunk {
			results[i] = probeResult{parent: c, err: err.Error()}
		}
		return results
	}

	// 2. one Maven run for the whole reactor, the tree of every module written next to its POM
	_ = r.runMaven(ctx, dir, "tree.json", true)
	if ctx.Err() != nil {
		for i, c := range chunk {
			results[i] = probeResult{parent: c, err: ctx.Err().Error()}
		}
		return results
	}

	// 3. every module's tree; a module without one is probed alone
	for i, c := range chunk {
		children, err := readTree(filepath.Join(dir, moduleName(i), "tree.json"))
		if err == nil {
			results[i] = probeResult{parent: c, children: children}
			continue
		}
		r.say("%s failed in the batch, resolved alone", c.Key())
		results[i] = r.probe(ctx, workDir, anchor, importBOM, c)
	}
	return results
}

// moduleName is the directory of the i-th component of a batch.
func moduleName(i int) string {
	return fmt.Sprintf("m%d", i)
}

// writeBatch lays the throwaway multi module project out: the parent POM with
// packaging pom listing the modules, and one module POM per component.
func (r *Resolver) writeBatch(dir string, anchor book.Anchor, importBOM bool, chunk []Component) error {
	// 1. the modules
	for i, c := range chunk {
		module := filepath.Join(dir, moduleName(i))
		err := os.MkdirAll(module, 0o755)
		if err != nil {
			return err
		}
		err = os.WriteFile(filepath.Join(module, "pom.xml"), []byte(r.probePOMNamed(anchor, importBOM, c, "probe-"+moduleName(i))), 0o644)
		if err != nil {
			return err
		}
	}

	// 2. the parent
	var b strings.Builder
	b.WriteString(`<project xmlns="http://maven.apache.org/POM/4.0.0">` + "\n")
	b.WriteString("<modelVersion>4.0.0</modelVersion>\n")
	b.WriteString("<groupId>osera.probe</groupId><artifactId>batch</artifactId><version>1</version><packaging>pom</packaging>\n")
	b.WriteString("<modules>\n")
	for i := range chunk {
		fmt.Fprintf(&b, "<module>%s</module>\n", moduleName(i))
	}
	b.WriteString("</modules>\n</project>\n")
	return os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(b.String()), 0o644)
}

// probe resolves one component as the single dependency of a throwaway POM and
// records its direct compile and runtime children. When Maven cannot build the
// model, the children are read from the component's own POM and the node is
// marked unresolved.
func (r *Resolver) probe(ctx context.Context, workDir string, anchor book.Anchor, importBOM bool, c Component) probeResult {
	res := probeResult{parent: c}

	// 1. a fresh directory with the throwaway POM
	dir, err := os.MkdirTemp(workDir, "probe-")
	if err != nil {
		res.err = err.Error()
		return res
	}
	defer os.RemoveAll(dir)
	err = os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(r.probePOM(anchor, importBOM, c)), 0o644)
	if err != nil {
		res.err = err.Error()
		return res
	}

	// 2. Maven, twice at most
	out := filepath.Join(dir, "tree.json")
	var mvnErr string
	for attempt := 0; attempt < 2; attempt++ {
		mvnErr = r.runMaven(ctx, dir, out, false)
		if mvnErr == "" {
			break
		}
		if ctx.Err() != nil {
			res.err = ctx.Err().Error()
			return res
		}
	}
	if mvnErr == "" {
		children, err := readTree(out)
		if err == nil {
			res.children = children
			return res
		}
		mvnErr = err.Error()
	}

	// 3. the fallback: the POM on the repository, marked
	m, err := r.readModel(ctx, c.Group, c.Artifact, c.Version)
	if err != nil {
		res.err = "unresolved: " + mvnErr + "; pom fallback failed: " + err.Error()
		return res
	}
	res.children = m.Declared
	res.err = "read from the POM, Maven failed: " + mvnErr
	return res
}

// probePOM is the throwaway consumer: the anchor imported when it is a BOM, the component as its only dependency.
func (r *Resolver) probePOM(anchor book.Anchor, importBOM bool, c Component) string {
	return r.probePOMNamed(anchor, importBOM, c, "probe")
}

// probePOMNamed is probePOM with the artifact id chosen, so the modules of a batch are distinct in the reactor.
func (r *Resolver) probePOMNamed(anchor book.Anchor, importBOM bool, c Component, artifactID string) string {
	var b strings.Builder
	b.WriteString(`<project xmlns="http://maven.apache.org/POM/4.0.0">` + "\n")
	b.WriteString("<modelVersion>4.0.0</modelVersion>\n")
	fmt.Fprintf(&b, "<groupId>osera.probe</groupId><artifactId>%s</artifactId><version>1</version>\n", artifactID)
	repos := r.repositories()
	if len(repos) > 1 || repos[0] != Central {
		b.WriteString("<repositories>\n")
		for i, u := range repos {
			fmt.Fprintf(&b, "<repository><id>osera-%d</id><url>%s</url></repository>\n", i, u)
		}
		b.WriteString("</repositories>\n")
	}
	if importBOM {
		b.WriteString("<dependencyManagement><dependencies><dependency>\n")
		fmt.Fprintf(&b, "<groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version><type>pom</type><scope>import</scope>\n", anchor.Group, anchor.Artifact, anchor.Version)
		b.WriteString("</dependency></dependencies></dependencyManagement>\n")
	}
	b.WriteString("<dependencies><dependency>\n")
	fmt.Fprintf(&b, "<groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version>\n", c.Group, c.Artifact, c.Version)
	if c.Classifier != "" {
		fmt.Fprintf(&b, "<classifier>%s</classifier>\n", c.Classifier)
	}
	if c.Type != "" && c.Type != "jar" {
		fmt.Fprintf(&b, "<type>%s</type>\n", c.Type)
	}
	b.WriteString("</dependency></dependencies>\n</project>\n")
	return b.String()
}

// runMaven runs dependency:tree once; the error text is what Maven said, empty on success.
func (r *Resolver) runMaven(ctx context.Context, dir, out string, failAtEnd bool) string {
	timeout := r.ProbeTimeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	mvn := r.Maven
	if mvn == "" {
		mvn = "mvn"
	}
	args := []string{"-B", "-q"}
	if failAtEnd {
		args = append(args, "--fail-at-end")
	}
	args = append(args, "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree", "-DoutputType=json", "-DoutputFile="+out)
	// the credentials for a repository that needs them, in a settings file next to the probe
	if r.needsSettings() {
		settings := filepath.Join(dir, "settings.xml")
		if err := os.WriteFile(settings, []byte(r.settingsXML()), 0o600); err != nil {
			return "settings: " + err.Error()
		}
		args = append(args, "-s", settings)
	}
	cmd := exec.CommandContext(ctx, mvn, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err == nil {
		if failAtEnd {
			return ""
		}
		if _, statErr := os.Stat(out); statErr == nil {
			return ""
		}
		return "no tree written"
	}
	var lines []string
	for _, l := range strings.Split(string(output), "\n") {
		if strings.Contains(l, "ERROR") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	msg := strings.Join(lines, " | ")
	if msg == "" {
		msg = "mvn failed: " + err.Error()
	}
	if len(msg) > 600 {
		msg = msg[:600]
	}
	return msg
}

// treeNode is one node of dependency:tree's JSON output.
type treeNode struct {
	GroupID    string     `json:"groupId"`
	ArtifactID string     `json:"artifactId"`
	Version    string     `json:"version"`
	Type       string     `json:"type"`
	Scope      string     `json:"scope"`
	Classifier string     `json:"classifier"`
	Optional   flexBool   `json:"optional"`
	Children   []treeNode `json:"children"`
}

// flexBool reads "true", true, "false" and false alike.
type flexBool bool

func (f *flexBool) UnmarshalJSON(raw []byte) error {
	s := strings.Trim(string(raw), `"`)
	*f = flexBool(s == "true")
	return nil
}

// readTree reads the probe's tree: the probe node, its one dependency, and that
// dependency's direct children in compile and runtime scope, not optional.
func readTree(path string) ([]Component, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root treeNode
	err = json.Unmarshal(raw, &root)
	if err != nil {
		return nil, errorf("tree: %w", err)
	}
	if len(root.Children) == 0 {
		return nil, errorf("tree: the probe resolved nothing")
	}
	return childrenOf(root.Children[0]), nil
}

// childrenOf keeps the direct compile and runtime, non optional children of a node.
func childrenOf(n treeNode) []Component {
	var out []Component
	for _, ch := range n.Children {
		scope := firstOf(ch.Scope, "compile")
		if scope != "compile" && scope != "runtime" {
			continue
		}
		if bool(ch.Optional) {
			continue
		}
		out = append(out, Component{Group: ch.GroupID, Artifact: ch.ArtifactID, Version: ch.Version, Classifier: ch.Classifier, Type: firstOf(ch.Type, "jar")})
	}
	return out
}
