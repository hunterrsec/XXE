package detector

import (
	"regexp"
	"strings"
)

// Finding represents a confirmed XXE finding
type Finding struct {
	PayloadID    string
	PayloadName  string
	Technique    string
	Framework    string
	URL          string
	Evidence     string
	EvidenceType string // "file-content", "ssrf-response", "error-leak", "oob-interaction"
	Severity     string
	Confidence   string // "confirmed", "likely", "potential"
	RawResponse  string
}

var (
	// Indicators of successful file read
	fileReadPatterns = []*regexp.Regexp{
		regexp.MustCompile(`root:x:0:0`),                                          // /etc/passwd
		regexp.MustCompile(`daemon:[x*]:1:1`),                                     // /etc/passwd
		regexp.MustCompile(`\[boot loader\]`),                                     // win.ini
		regexp.MustCompile(`\[extensions\]`),                                      // win.ini
		regexp.MustCompile(`\[fonts\]`),                                           // win.ini
		regexp.MustCompile(`Linux version \d+\.\d+`),                              // /proc/version
		regexp.MustCompile(`for x86_64`),                                          // /proc/version
		regexp.MustCompile(`\[configuration\]`),                                   // web.config
		regexp.MustCompile(`<connectionStrings`),                                  // web.config
		regexp.MustCompile(`<appSettings`),                                        // web.config
		regexp.MustCompile(`hostname=`),                                           // /etc/hostname
		regexp.MustCompile(`(?i)uid=\d+\([a-z]+\) gid=\d+`),                     // id command output
		regexp.MustCompile(`(?i)(AWS_SECRET|ACCESS_KEY|aws_access_key_id)`),       // AWS creds
		regexp.MustCompile(`(?i)"AccessKeyId"\s*:\s*"`),                           // AWS IMDS
		regexp.MustCompile(`(?i)"Token"\s*:\s*"[A-Za-z0-9/+]{100,}"`),            // AWS IMDS token
		regexp.MustCompile(`(?i)eyJ[A-Za-z0-9-_=]{20,}\.[A-Za-z0-9-_=]{20,}`),   // JWT token
		regexp.MustCompile(`(?i)iam/security-credentials/`),                       // AWS IAM
		regexp.MustCompile(`(?i)"computeMetadata"`),                               // GCP metadata
	}

	// SSRF indicators
	ssrfPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)"ami-id"`),                                        // AWS IMDS
		regexp.MustCompile(`(?i)"instance-id"\s*:`),                               // AWS IMDS
		regexp.MustCompile(`(?i)"local-ipv4"\s*:`),                                // AWS IMDS
		regexp.MustCompile(`(?i)compute\.googleapis\.com`),                        // GCP
		regexp.MustCompile(`(?i)metadata\.google\.internal`),                      // GCP
		regexp.MustCompile(`(?i)microsoft azure`),                                 // Azure
		regexp.MustCompile(`(?i)"subscriptionId"`),                                // Azure
		regexp.MustCompile(`(?i)redis_version`),                                   // Redis
		regexp.MustCompile(`(?i)\+PONG`),                                          // Redis
		regexp.MustCompile(`(?i)"cluster_name"`),                                  // Elasticsearch
		regexp.MustCompile(`(?i)"number_of_nodes"`),                               // Elasticsearch
		regexp.MustCompile(`(?i)kubernetes`),                                      // K8s
		regexp.MustCompile(`(?i)"apiVersion"\s*:\s*"v1"`),                        // K8s API
	}

	// Error-based leak indicators
	errorLeakPatterns = []*regexp.Regexp{
		regexp.MustCompile(`root:x:0:0:.+FileNotFoundException`),
		regexp.MustCompile(`FileNotFoundException.*XXESHOT_INVALID`),
		regexp.MustCompile(`(?i)xml.*parse.*error.*root:x`),
		regexp.MustCompile(`(?i)entity.*value.*root:x:0`),
		regexp.MustCompile(`(?i)SAXParseException.*root:x`),
		regexp.MustCompile(`(?i)XMLParseError.*passwd`),
	}

	// PHP filter base64 (confirms XXE even if content is encoded)
	base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`)

	// Error messages that suggest parser is processing entities (potential)
	potentialPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(EntityResolutionException|ExternalEntityException)`),
		regexp.MustCompile(`(?i)(DOCTYPE|ENTITY|DTD).*(not|disallow|prohibit|block)`),
		regexp.MustCompile(`(?i)external entity`),
		regexp.MustCompile(`(?i)dtd.*(not allowed|forbidden|blocked)`),
	}
)

// Analyze checks a response body for XXE indicators
func Analyze(url, payloadID, payloadName, technique, framework, body string) *Finding {
	// Check for direct file read
	for _, p := range fileReadPatterns {
		if m := p.FindString(body); m != "" {
			return &Finding{
				PayloadID:    payloadID,
				PayloadName:  payloadName,
				Technique:    technique,
				Framework:    framework,
				URL:          url,
				Evidence:     truncate(m, 200),
				EvidenceType: "file-content",
				Severity:     "HIGH",
				Confidence:   "confirmed",
				RawResponse:  truncate(body, 500),
			}
		}
	}

	// Check for SSRF response
	for _, p := range ssrfPatterns {
		if m := p.FindString(body); m != "" {
			return &Finding{
				PayloadID:    payloadID,
				PayloadName:  payloadName,
				Technique:    technique,
				Framework:    framework,
				URL:          url,
				Evidence:     truncate(m, 200),
				EvidenceType: "ssrf-response",
				Severity:     "HIGH",
				Confidence:   "confirmed",
				RawResponse:  truncate(body, 500),
			}
		}
	}

	// Check for error-based leak
	for _, p := range errorLeakPatterns {
		if m := p.FindString(body); m != "" {
			return &Finding{
				PayloadID:    payloadID,
				PayloadName:  payloadName,
				Technique:    technique,
				Framework:    framework,
				URL:          url,
				Evidence:     truncate(m, 200),
				EvidenceType: "error-leak",
				Severity:     "HIGH",
				Confidence:   "confirmed",
				RawResponse:  truncate(body, 500),
			}
		}
	}

	// Check for PHP base64 filter output
	if technique == "classic" && framework == "php" {
		lines := strings.Split(strings.TrimSpace(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) > 40 && base64Pattern.MatchString(line) {
				return &Finding{
					PayloadID:    payloadID,
					PayloadName:  payloadName,
					Technique:    technique,
					Framework:    framework,
					URL:          url,
					Evidence:     "Base64 encoded content detected: " + truncate(line, 60) + "...",
					EvidenceType: "file-content-b64",
					Severity:     "HIGH",
					Confidence:   "likely",
					RawResponse:  truncate(body, 500),
				}
			}
		}
	}

	// Potential — parser mentions entities but blocks them
	for _, p := range potentialPatterns {
		if m := p.FindString(body); m != "" {
			return &Finding{
				PayloadID:    payloadID,
				PayloadName:  payloadName,
				Technique:    technique,
				Framework:    framework,
				URL:          url,
				Evidence:     truncate(m, 200),
				EvidenceType: "entity-error",
				Severity:     "INFO",
				Confidence:   "potential",
				RawResponse:  truncate(body, 500),
			}
		}
	}

	return nil
}

// CheckOOBInteraction checks if an OOB domain received a hit
// This is a placeholder - in real deployment, integrate with Collaborator API or interact.sh
func CheckOOBInteraction(domain string) bool {
	// In a full implementation, this would poll the OOB server API
	// Burp Collaborator polling API or interact.sh API
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
