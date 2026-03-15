package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Options holds all CLI flags
type Options struct {
	// Targeting
	URL         string
	URLList     string
	Target      string

	// Techniques
	Techniques  string // comma-separated: classic,blind,oob,xinclude,xslt,ssrf,oob-dns
	AllTech     bool

	// Framework-specific
	Frameworks  string // java,php,python,dotnet,nodejs,ruby,go,scala,soap,saml,svg,office
	AllFrameworks bool

	// OOB/Collaborator
	Collaborator string
	OOBServer    string
	DTDServer    string

	// Payloads
	CustomPayload string
	PayloadFile   string
	FilesToRead   string

	// HTTP Options
	Headers     string
	Method      string
	Data        string
	ContentType string
	Proxy       string
	Timeout     int
	Retries     int
	RateLimit   int
	Threads     int

	// Output
	Output      string
	OutputFormat string // text, json, jsonl
	Verbose     bool
	Silent      bool
	NoColor     bool

	// Misc
	Version     bool
	SkipVerify  bool
	FollowRedirect bool
	Cookies     string
}

func ParseFlags() (*Options, error) {
	opts := &Options{}

	// Targeting
	flag.StringVar(&opts.URL, "u", "", "Target URL")
	flag.StringVar(&opts.URL, "url", "", "Target URL")
	flag.StringVar(&opts.URLList, "l", "", "File containing list of target URLs")
	flag.StringVar(&opts.URLList, "list", "", "File containing list of target URLs")

	// Techniques
	flag.StringVar(&opts.Techniques, "t", "classic,oob,xinclude", "Techniques: classic,blind,oob,xinclude,xslt,ssrf,error,cdata")
	flag.StringVar(&opts.Techniques, "techniques", "classic,oob,xinclude", "Techniques to use")
	flag.BoolVar(&opts.AllTech, "at", false, "Use ALL techniques")
	flag.BoolVar(&opts.AllTech, "all-techniques", false, "Use ALL techniques")

	// Frameworks
	flag.StringVar(&opts.Frameworks, "fw", "all", "Frameworks: java,php,python,dotnet,nodejs,ruby,go,scala,soap,saml,svg,office")
	flag.StringVar(&opts.Frameworks, "frameworks", "all", "Target frameworks")
	flag.BoolVar(&opts.AllFrameworks, "af", false, "Test all frameworks")

	// OOB
	flag.StringVar(&opts.Collaborator, "cb", "", "Burp Collaborator domain for OOB detection")
	flag.StringVar(&opts.Collaborator, "collaborator", "", "Burp Collaborator domain")
	flag.StringVar(&opts.OOBServer, "oob", "", "OOB server (interact.sh, canarytokens, etc.)")
	flag.StringVar(&opts.DTDServer, "dtd", "", "Your server to host evil.dtd for blind OOB exfil")

	// Payloads
	flag.StringVar(&opts.CustomPayload, "p", "", "Custom XXE payload (use {ENTITY} placeholder)")
	flag.StringVar(&opts.PayloadFile, "pf", "", "File with custom XXE payloads (one per line)")
	flag.StringVar(&opts.FilesToRead, "fr", "/etc/passwd,/etc/hostname,/proc/version", "Files to read (comma-separated)")

	// HTTP
	flag.StringVar(&opts.Headers, "H", "", "Custom headers (comma-separated, e.g. 'Authorization: Bearer xxx')")
	flag.StringVar(&opts.Method, "X", "POST", "HTTP method (POST, PUT, PATCH)")
	flag.StringVar(&opts.Data, "d", "", "POST data (use {XXE_PAYLOAD} placeholder)")
	flag.StringVar(&opts.ContentType, "ct", "", "Content-Type override (default: application/xml)")
	flag.StringVar(&opts.Proxy, "proxy", "", "HTTP proxy (e.g. http://127.0.0.1:8080)")
	flag.IntVar(&opts.Timeout, "timeout", 10, "HTTP timeout in seconds")
	flag.IntVar(&opts.Retries, "retries", 2, "Number of retries")
	flag.IntVar(&opts.RateLimit, "rl", 150, "Rate limit (requests per second)")
	flag.IntVar(&opts.Threads, "c", 25, "Concurrent threads")
	flag.StringVar(&opts.Cookies, "cookies", "", "Cookies (name=value; name2=value2)")

	// Output
	flag.StringVar(&opts.Output, "o", "", "Output file")
	flag.StringVar(&opts.OutputFormat, "of", "text", "Output format: text,json,jsonl")
	flag.BoolVar(&opts.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&opts.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&opts.Silent, "silent", false, "Silent mode (only print findings)")
	flag.BoolVar(&opts.NoColor, "nc", false, "No color output")

	// Misc
	flag.BoolVar(&opts.Version, "version", false, "Show version")
	flag.BoolVar(&opts.SkipVerify, "k", false, "Skip TLS verification")
	flag.BoolVar(&opts.FollowRedirect, "fr2", false, "Follow redirects")

	flag.Usage = usage
	flag.Parse()

	return opts, validate(opts)
}

func validate(opts *Options) error {
	if opts.Version {
		return nil
	}
	if opts.URL == "" && opts.URLList == "" && !hasStdin() {
		return fmt.Errorf("provide a target: -u <url> or -l <file> or pipe URLs via stdin")
	}
	if opts.AllTech {
		opts.Techniques = "classic,blind,oob,xinclude,xslt,ssrf,error,cdata"
	}
	return nil
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func usage() {
	fmt.Fprintf(os.Stderr, `
USAGE:
  xxeshot [OPTIONS]

TARGETING:
  -u, -url        string   Target URL
  -l, -list       string   File with target URLs (one per line)
                           (stdin pipe also supported)

TECHNIQUES:
  -t, -techniques string   Techniques: classic,blind,oob,xinclude,xslt,ssrf,error,cdata
                           Default: classic,oob,xinclude
  -at, -all-techniques     Use ALL available techniques

FRAMEWORKS:
  -fw, -frameworks string  Frameworks: java,php,python,dotnet,nodejs,ruby,go,scala,
                           soap,saml,svg,office  (default: all)

OUT-OF-BAND (OOB):
  -cb, -collaborator string  Burp Collaborator domain for OOB detection
  -oob           string      OOB interaction server (interact.sh domain, etc.)
  -dtd           string      Your server hosting evil.dtd for blind data exfil

PAYLOADS:
  -p             string   Custom XXE payload template
  -pf            string   Custom payload file (one per line)
  -fr            string   Files to read (comma-separated)
                          Default: /etc/passwd,/etc/hostname,/proc/version

HTTP OPTIONS:
  -H             string   Custom headers ('Key: Value, Key2: Value2')
  -X             string   HTTP method (default: POST)
  -d             string   Request body with {XXE_PAYLOAD} placeholder
  -ct            string   Content-Type override
  -proxy         string   HTTP proxy URL
  -timeout       int      Timeout in seconds (default: 10)
  -c             int      Concurrent threads (default: 25)
  -rl            int      Requests per second rate limit (default: 150)
  -cookies       string   Cookies to include

OUTPUT:
  -o             string   Output file path
  -of            string   Output format: text, json, jsonl (default: text)
  -v, -verbose           Verbose output
  -silent                Print only findings
  -nc                    No color output

EXAMPLES:
  xxeshot -u https://target.com/api/upload -at -cb your.burpcollaborator.net
  xxeshot -l urls.txt -t classic,xinclude -o results.json -of json
  xxeshot -u https://target.com/parse -t oob -oob xxeshot.interact.sh -v
  xxeshot -u https://target.com/api -fw soap,saml -t classic,blind
  cat urls.txt | xxeshot -t all -silent | tee findings.txt
  xxeshot -u https://target.com -proxy http://127.0.0.1:8080 -k -v

INSTALL:
  go install -v github.com/xxeshot/xxeshot/cmd/xxeshot@latest

`)
	fmt.Println("  Techniques: " + strings.Join([]string{
		"classic  → file read, SSRF via reflected output",
		"blind    → parameter entity with OOB server",
		"oob      → Burp Collaborator / interact.sh detection",
		"xinclude → DOCTYPE-less XInclude injection",
		"xslt     → XSLT stylesheet document() injection",
		"ssrf     → cloud metadata / internal network",
		"error    → error-based blind extraction",
		"cdata    → CDATA wrapped exfiltration bypass",
	}, "\n             "))
}
