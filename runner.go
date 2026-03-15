package runner

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xxeshot/xxeshot/internal/cli"
	"github.com/xxeshot/xxeshot/internal/detector"
	httpclient "github.com/xxeshot/xxeshot/internal/http"
	"github.com/xxeshot/xxeshot/internal/output"
	"github.com/xxeshot/xxeshot/internal/payloads"
)

// Runner orchestrates the full XXE scan
type Runner struct {
	opts    *cli.Options
	client  *httpclient.Client
	writer  *output.Writer
	builder *payloads.Builder
	targets []string
}

func New(opts *cli.Options) (*Runner, error) {
	// Build HTTP client
	client, err := httpclient.NewClient(httpclient.Config{
		Proxy:          opts.Proxy,
		Timeout:        opts.Timeout,
		SkipVerify:     opts.SkipVerify,
		FollowRedirect: opts.FollowRedirect,
		Headers:        opts.Headers,
		Cookies:        opts.Cookies,
		Method:         opts.Method,
		Verbose:        opts.Verbose,
	})
	if err != nil {
		return nil, fmt.Errorf("http client: %w", err)
	}

	// Build output writer
	writer, err := output.New(opts.OutputFormat, opts.Output, opts.NoColor, opts.Silent, opts.Verbose)
	if err != nil {
		return nil, fmt.Errorf("output writer: %w", err)
	}

	// Parse files to read
	var files []string
	for _, f := range strings.Split(opts.FilesToRead, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			files = append(files, f)
		}
	}

	// Build payload generator
	builder := payloads.NewBuilder(opts.OOBServer, opts.DTDServer, opts.Collaborator, files)

	// Collect targets
	targets, err := collectTargets(opts)
	if err != nil {
		return nil, err
	}

	return &Runner{
		opts:    opts,
		client:  client,
		writer:  writer,
		builder: builder,
		targets: targets,
	}, nil
}

func (r *Runner) Run() {
	defer r.writer.Close()

	// Parse techniques and frameworks
	techniques := splitTrim(r.opts.Techniques)
	frameworks := splitTrim(r.opts.Frameworks)

	// Build payloads
	pls := r.builder.Build(techniques, frameworks)

	// Print evil.dtd content if OOB is configured
	if r.opts.DTDServer != "" || r.opts.OOBServer != "" || r.opts.Collaborator != "" {
		r.writer.Info("Evil DTD to host at " + r.builder.DTDServerURL() + ":")
		r.writer.Info("\n" + r.builder.EvilDTD("/etc/passwd"))
		r.writer.Info("")
	}

	total := len(r.targets) * len(pls)
	r.writer.Info(fmt.Sprintf("Targets: %d | Payloads: %d | Total requests: %d",
		len(r.targets), len(pls), total))
	r.writer.Info(fmt.Sprintf("Techniques: %s | Threads: %d",
		strings.Join(techniques, ","), r.opts.Threads))
	r.writer.Info("Starting scan...")

	// Semaphore for concurrency
	sem := make(chan struct{}, r.opts.Threads)
	rateLimiter := time.NewTicker(time.Second / time.Duration(r.opts.RateLimit))
	defer rateLimiter.Stop()

	var wg sync.WaitGroup
	counter := 0
	var counterMu sync.Mutex

	for _, target := range r.targets {
		for _, pl := range pls {
			wg.Add(1)
			sem <- struct{}{}
			<-rateLimiter.C

			go func(tgt string, p payloads.Payload) {
				defer wg.Done()
				defer func() { <-sem }()

				counterMu.Lock()
				counter++
				curr := counter
				counterMu.Unlock()

				r.writer.Progress(curr, total, tgt, p.Name)
				r.writer.Verbose(fmt.Sprintf("Testing [%s] %s → %s", p.Technique, tgt, p.Name))

				ct := p.ContentType
				if r.opts.ContentType != "" {
					ct = r.opts.ContentType
				}

				body := p.Body
				if r.opts.Data != "" {
					body = strings.ReplaceAll(r.opts.Data, "{XXE_PAYLOAD}", p.Body)
				}

				resp, err := r.client.Send(tgt, body, ct)
				r.writer.IncrTested()

				if err != nil {
					r.writer.Verbose(fmt.Sprintf("Error [%s]: %v", tgt, err))
					return
				}

				// Analyze response
				finding := detector.Analyze(tgt, p.ID, p.Name, p.Technique, p.Framework, resp.Body)
				if finding != nil {
					r.writer.Finding(finding)
				}
			}(target, pl)
		}
	}

	wg.Wait()
	r.writer.Summary()
}

func collectTargets(opts *cli.Options) ([]string, error) {
	var targets []string
	seen := make(map[string]bool)

	add := func(u string) {
		u = strings.TrimSpace(u)
		if u != "" && !seen[u] {
			seen[u] = true
			targets = append(targets, u)
		}
	}

	if opts.URL != "" {
		add(opts.URL)
	}

	if opts.URLList != "" {
		f, err := os.Open(opts.URLList)
		if err != nil {
			return nil, fmt.Errorf("cannot open list file: %w", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			add(scanner.Text())
		}
	}

	// stdin pipe
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			add(scanner.Text())
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets found")
	}

	return targets, nil
}

func splitTrim(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(strings.ToLower(v))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
