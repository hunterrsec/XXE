package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xxeshot/xxeshot/internal/detector"
)

// Colors
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	BgRed  = "\033[41m"
)

// Writer handles all output
type Writer struct {
	format  string
	outFile *os.File
	noColor bool
	silent  bool
	verbose bool
	mu      sync.Mutex
	stats   Stats
}

type Stats struct {
	Tested   int
	Found    int
	Skipped  int
	StartTime time.Time
}

func New(format, outPath string, noColor, silent, verbose bool) (*Writer, error) {
	w := &Writer{
		format:  format,
		noColor: noColor,
		silent:  silent,
		verbose: verbose,
		stats:   Stats{StartTime: time.Now()},
	}
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return nil, fmt.Errorf("cannot create output file: %w", err)
		}
		w.outFile = f
	}
	return w, nil
}

func (w *Writer) Close() {
	if w.outFile != nil {
		w.outFile.Close()
	}
}

func (w *Writer) Info(msg string) {
	if w.silent {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Printf("%s[INF]%s %s\n", w.c(Cyan), w.c(Reset), msg)
}

func (w *Writer) Verbose(msg string) {
	if !w.verbose || w.silent {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Printf("%s[VRB]%s %s%s%s\n", w.c(Dim), w.c(Reset), w.c(Dim), msg, w.c(Reset))
}

func (w *Writer) Progress(current, total int, url, payloadName string) {
	if w.silent {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	pct := float64(current) / float64(total) * 100
	bar := progressBar(int(pct), 20)
	fmt.Printf("\r%s[%d/%d]%s %s %.0f%% %s%-40s%s",
		w.c(Dim), current, total, w.c(Reset),
		bar, pct,
		w.c(Dim), truncate(payloadName, 40), w.c(Reset))
}

func (w *Writer) Finding(f *detector.Finding) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stats.Found++

	// Clear progress line
	fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")

	switch w.format {
	case "json", "jsonl":
		data, _ := json.Marshal(map[string]interface{}{
			"type":        "finding",
			"payload_id":  f.PayloadID,
			"name":        f.PayloadName,
			"technique":   f.Technique,
			"framework":   f.Framework,
			"url":         f.URL,
			"evidence":    f.Evidence,
			"evidence_type": f.EvidenceType,
			"severity":    f.Severity,
			"confidence":  f.Confidence,
			"timestamp":   time.Now().Format(time.RFC3339),
		})
		out := string(data)
		if w.outFile != nil {
			fmt.Fprintln(w.outFile, out)
		}
		fmt.Println(out)

	default:
		sev := w.severityLabel(f.Severity)
		conf := w.confidenceLabel(f.Confidence)

		fmt.Printf("\n%s%s[FOUND]%s%s %s %s\n",
			w.c(Bold), w.c(BgRed), w.c(Reset), w.c(Reset),
			sev, conf)
		fmt.Printf("  %sURL:%s         %s\n", w.c(Bold), w.c(Reset), f.URL)
		fmt.Printf("  %sTechnique:%s   %s%s%s\n", w.c(Bold), w.c(Reset), w.c(Yellow), f.Technique, w.c(Reset))
		fmt.Printf("  %sFramework:%s   %s\n", w.c(Bold), w.c(Reset), f.Framework)
		fmt.Printf("  %sPayload:%s     %s\n", w.c(Bold), w.c(Reset), f.PayloadName)
		fmt.Printf("  %sEvidence:%s    %s%s%s\n", w.c(Bold), w.c(Reset), w.c(Green), f.Evidence, w.c(Reset))
		fmt.Printf("  %sType:%s        %s\n\n", w.c(Bold), w.c(Reset), f.EvidenceType)

		if w.outFile != nil {
			fmt.Fprintf(w.outFile, "[FOUND] %s | %s | %s | %s | %s\n",
				f.Severity, f.URL, f.Technique, f.PayloadName, f.Evidence)
		}
	}
}

func (w *Writer) Summary() {
	if w.silent {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	elapsed := time.Since(w.stats.StartTime).Round(time.Millisecond)
	fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
	fmt.Println()
	fmt.Printf("%s╔═══════════════ XXESHOT SCAN SUMMARY ═══════════════╗%s\n", w.c(Cyan), w.c(Reset))
	fmt.Printf("%s║%s  Payloads Tested:  %-33d%s║%s\n", w.c(Cyan), w.c(Reset), w.stats.Tested, w.c(Cyan), w.c(Reset))
	fmt.Printf("%s║%s  Findings:         %-33s%s║%s\n", w.c(Cyan), w.c(Reset),
		fmt.Sprintf("%s%d%s", w.c(Red+Bold), w.stats.Found, w.c(Reset)),
		w.c(Cyan), w.c(Reset))
	fmt.Printf("%s║%s  Elapsed:          %-33s%s║%s\n", w.c(Cyan), w.c(Reset), elapsed, w.c(Cyan), w.c(Reset))
	fmt.Printf("%s╚════════════════════════════════════════════════════╝%s\n\n", w.c(Cyan), w.c(Reset))
}

func (w *Writer) IncrTested() {
	w.mu.Lock()
	w.stats.Tested++
	w.mu.Unlock()
}

func (w *Writer) c(color string) string {
	if w.noColor {
		return ""
	}
	return color
}

func (w *Writer) severityLabel(s string) string {
	switch s {
	case "CRITICAL":
		return w.c(Red+Bold) + "[CRITICAL]" + w.c(Reset)
	case "HIGH":
		return w.c(Red) + "[HIGH]" + w.c(Reset)
	case "MEDIUM":
		return w.c(Yellow) + "[MEDIUM]" + w.c(Reset)
	case "INFO":
		return w.c(Cyan) + "[INFO]" + w.c(Reset)
	default:
		return "[" + s + "]"
	}
}

func (w *Writer) confidenceLabel(c string) string {
	switch c {
	case "confirmed":
		return w.c(Green) + "(confirmed)" + w.c(Reset)
	case "likely":
		return w.c(Yellow) + "(likely)" + w.c(Reset)
	case "potential":
		return w.c(Dim) + "(potential)" + w.c(Reset)
	default:
		return ""
	}
}

func progressBar(pct, width int) string {
	filled := pct * width / 100
	bar := "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
	return bar
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s + strings.Repeat(" ", n-len(s))
	}
	return s[:n-3] + "..."
}
