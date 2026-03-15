package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client wraps http.Client with XXE-testing helpers
type Client struct {
	inner   *http.Client
	headers map[string]string
	cookies string
	method  string
	verbose bool
}

// Response holds a parsed HTTP response
type Response struct {
	StatusCode int
	Body       string
	Headers    http.Header
	Duration   time.Duration
}

// Config for the HTTP client
type Config struct {
	Proxy          string
	Timeout        int
	SkipVerify     bool
	FollowRedirect bool
	Headers        string
	Cookies        string
	Method         string
	Verbose        bool
}

func NewClient(cfg Config) (*Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.SkipVerify},
		MaxIdleConns:    100,
		IdleConnTimeout: 30 * time.Second,
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		if !cfg.FollowRedirect {
			return http.ErrUseLastResponse
		}
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	inner := &http.Client{
		Transport:     transport,
		Timeout:       time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: redirectPolicy,
	}

	headers := parseHeaders(cfg.Headers)

	return &Client{
		inner:   inner,
		headers: headers,
		cookies: cfg.Cookies,
		method:  cfg.Method,
		verbose: cfg.Verbose,
	}, nil
}

func (c *Client) Send(targetURL, body, contentType string) (*Response, error) {
	method := c.method
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequest(method, targetURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request build error: %w", err)
	}

	// Set Content-Type
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; xxeshot/1.0)")
	req.Header.Set("Accept", "application/xml, text/xml, */*")

	// Custom headers
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	// Cookies
	if c.cookies != "" {
		req.Header.Set("Cookie", c.cookies)
	}

	start := time.Now()
	resp, err := c.inner.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("body read error: %w", err)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       string(bodyBytes),
		Headers:    resp.Header,
		Duration:   duration,
	}, nil
}

func parseHeaders(raw string) map[string]string {
	headers := make(map[string]string)
	if raw == "" {
		return headers
	}
	for _, h := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}
