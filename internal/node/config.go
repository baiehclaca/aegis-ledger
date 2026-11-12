package node

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/p2p"
)

// Config is one local validator. Passphrase is never written to the
// config file. Key, when set, is used instead of KeyPath so tests do
// not have to round-trip a key file. A key file is test-network only.
type Config struct {
	Dir         string
	Listen      string
	Client      string
	Peers       []string
	Index       int
	GenesisPath string
	KeyPath     string
	Passphrase  string
	Key         crypto.PrivateKey
	BaseTimeout uint64
	MaxTimeout  uint64
	Skew        int64
	// Meter counts ciphertext bytes when a test sets it. The config
	// file never carries it.
	Meter *p2p.Meter
}

// ParseConfig reads the line-oriented node file. A TOML parser is not
// a dependency of this milestone. Unknown keys are rejected.
func ParseConfig(text string) (Config, error) {
	var cfg Config
	seen := map[string]bool{}
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		if !ok {
			key, val, ok = strings.Cut(line, "=")
		}
		if !ok {
			return Config{}, fmt.Errorf("node: config line %q", line)
		}
		val = strings.TrimSpace(val)
		if seen[key] {
			return Config{}, fmt.Errorf("node: duplicate config key %s", key)
		}
		seen[key] = true
		if err := applyConfig(&cfg, key, val); err != nil {
			return Config{}, err
		}
	}
	if err := s.Err(); err != nil {
		return Config{}, err
	}
	if err := cfg.check(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyConfig(cfg *Config, key, val string) error {
	switch key {
	case "datadir":
		cfg.Dir = val
	case "listen":
		cfg.Listen = val
	case "client":
		cfg.Client = val
	case "peers":
		cfg.Peers = splitList(val)
	case "index":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("node: index: %w", err)
		}
		cfg.Index = n
	case "genesis":
		cfg.GenesisPath = val
	case "keyfile":
		cfg.KeyPath = val
	case "base_timeout":
		n, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return fmt.Errorf("node: base_timeout: %w", err)
		}
		cfg.BaseTimeout = n
	case "max_timeout":
		n, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return fmt.Errorf("node: max_timeout: %w", err)
		}
		cfg.MaxTimeout = n
	case "skew":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("node: skew: %w", err)
		}
		cfg.Skew = n
	default:
		return fmt.Errorf("node: unknown config key %s", key)
	}
	return nil
}

func splitList(val string) []string {
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c Config) check() error {
	if c.Dir == "" || c.Listen == "" || c.Client == "" || c.GenesisPath == "" {
		return fmt.Errorf("node: config is missing a required field")
	}
	if c.KeyPath == "" && c.Key.Algorithm() == 0 {
		return fmt.Errorf("node: config is missing a key")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("node: listen: %w", err)
	}
	if _, _, err := net.SplitHostPort(c.Client); err != nil {
		return fmt.Errorf("node: client: %w", err)
	}
	if c.Index < 0 || c.Index >= len(c.Peers) {
		return fmt.Errorf("node: index is outside the peer list")
	}
	for _, p := range c.Peers {
		if _, _, err := net.SplitHostPort(p); err != nil {
			return fmt.Errorf("node: peer: %w", err)
		}
	}
	return nil
}

// Format renders the config file. The passphrase is not included.
func (c Config) Format() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "datadir %s\n", c.Dir)
	fmt.Fprintf(&b, "listen %s\n", c.Listen)
	fmt.Fprintf(&b, "client %s\n", c.Client)
	fmt.Fprintf(&b, "peers %s\n", strings.Join(c.Peers, ","))
	fmt.Fprintf(&b, "index %d\n", c.Index)
	fmt.Fprintf(&b, "genesis %s\n", c.GenesisPath)
	fmt.Fprintf(&b, "keyfile %s\n", c.KeyPath)
	if c.BaseTimeout != 0 {
		fmt.Fprintf(&b, "base_timeout %d\n", c.BaseTimeout)
	}
	if c.MaxTimeout != 0 {
		fmt.Fprintf(&b, "max_timeout %d\n", c.MaxTimeout)
	}
	if c.Skew != 0 {
		fmt.Fprintf(&b, "skew %d\n", c.Skew)
	}
	return b.Bytes()
}

// WriteFile writes the config in mode 0600.
func (c Config) WriteFile(path string) error {
	if err := c.check(); err != nil {
		return err
	}
	return os.WriteFile(path, c.Format(), 0o600)
}
