package engine

import (
	"time"

	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type Config struct {
	Threads        int
	Timeout        time.Duration
	RateLimit      int
	Proxy          string
	Cookies        []*models.Cookie
	Headers        map[string]string
	TemplatesDir   string
	WordlistsDir   string
	OutputDir      string
	OutputFormats  []string
	Tags           []string
	ExcludeTags    []string
	Modules        []string
	ExcludeModules []string
	Quiet          bool
	Verbose        bool
	Quick          bool
	DryRun         bool

	// CrawlEnabled turns on the crawl-first stage: before the module pool
	// dispatches, the crawler walks the target within MaxDepth/MaxPages and
	// every discovered URL joins the scan as its own cloned target.
	CrawlEnabled bool
	MaxDepth     int
	MaxPages     int

	// AllowPrivate opts into scanning loopback (127.0.0.0/8, ::1),
	// RFC1918 (10/8, 172.16/12, 192.168/16) and link-local (169.254/16)
	// targets. Private ranges are suppressed by default.
	AllowPrivate bool

	// Aggressive opts into mutating probes: every non-GET request a module
	// wants to send (POST/PUT bodies, method-override tricks, concurrent
	// race hammering) is skipped without it.
	Aggressive bool

	// Client is the shared HTTP client built once per run from the proxy,
	// timeout and rate-limit settings above. The engine owns its lifecycle;
	// modules must use it as-is and never close it.
	Client *fanghttp.Client

	// ScanID and TargetID enable incremental persistence: when both are set
	// the engine writes each finding to the database as soon as its module
	// result aggregates, so a crash mid-scan keeps partial results queryable.
	ScanID   string
	TargetID string
}

type Option func(*Config)

func NewConfig(opts ...Option) *Config {
	cfg := &Config{
		Threads:      20,
		Timeout:      10 * time.Second,
		RateLimit:    50,
		Headers:      make(map[string]string),
		CrawlEnabled: false,
		MaxDepth:     2,
		MaxPages:     200,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func WithThreads(n int) Option {
	return func(c *Config) {
		if n > 0 {
			c.Threads = n
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.Timeout = d
		}
	}
}

func WithRateLimit(n int) Option {
	return func(c *Config) {
		if n > 0 {
			c.RateLimit = n
		}
	}
}

func WithProxy(p string) Option {
	return func(c *Config) {
		c.Proxy = p
	}
}

func WithCookies(cookies []*models.Cookie) Option {
	return func(c *Config) {
		c.Cookies = cookies
	}
}

func WithHeaders(h map[string]string) Option {
	return func(c *Config) {
		c.Headers = h
	}
}

func WithModules(modules ...string) Option {
	return func(c *Config) {
		c.Modules = modules
	}
}

func WithExcludeModules(modules ...string) Option {
	return func(c *Config) {
		c.ExcludeModules = modules
	}
}

func WithQuick(quick bool) Option {
	return func(c *Config) {
		c.Quick = quick
	}
}

func WithCrawlEnabled(enabled bool) Option {
	return func(c *Config) {
		c.CrawlEnabled = enabled
	}
}

func WithMaxDepth(n int) Option {
	return func(c *Config) {
		if n > 0 {
			c.MaxDepth = n
		}
	}
}

func WithMaxPages(n int) Option {
	return func(c *Config) {
		if n > 0 {
			c.MaxPages = n
		}
	}
}

func WithAllowPrivate(allow bool) Option {
	return func(c *Config) {
		c.AllowPrivate = allow
	}
}

func WithAggressive(aggressive bool) Option {
	return func(c *Config) {
		c.Aggressive = aggressive
	}
}

// BuildHTTPClient assembles the shared HTTP client from this config's proxy,
// timeout, rate-limit, header, cookie and concurrency settings. The retry and
// rate-limit middleware chains are wired inside fanghttp.NewClient, so every
// request issued through the returned client is covered.
func (c *Config) BuildHTTPClient() *fanghttp.Client {
	return fanghttp.NewClient(
		fanghttp.WithTimeout(c.Timeout),
		fanghttp.WithRateLimit(c.RateLimit),
		fanghttp.WithProxy(c.Proxy),
		fanghttp.WithHeaders(c.Headers),
		fanghttp.WithCookies(c.Cookies),
		fanghttp.WithMaxConcurrency(c.Threads),
	)
}
