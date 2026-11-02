package push

import (
	"fmt"
	"slices"
	"strconv"
	"time"
)

// options は設定ファイルの methods.push の項目（ADR 0104）。
type options struct {
	ChallengeTTL time.Duration
	Window       time.Duration
	PerUser      int64
	PerIP        int64
	DenyWindow   time.Duration
	DenyLimit    int64
}

var defaults = options{ChallengeTTL: 2 * time.Minute, Window: 10 * time.Minute, PerUser: 5, PerIP: 20, DenyWindow: 30 * time.Minute, DenyLimit: 3}

var knownOptions = []string{"challenge_ttl", "rate_window", "per_user", "per_ip", "deny_window", "deny_limit"}

func parseOptions(m map[string]string) (options, error) {
	o := defaults
	for k, v := range m {
		if !slices.Contains(knownOptions, k) {
			return o, fmt.Errorf("unknown option %q (allowed: %v)", k, knownOptions)
		}
		var err error
		switch k {
		case "challenge_ttl":
			o.ChallengeTTL, err = time.ParseDuration(v)
			if err == nil && (o.ChallengeTTL < 30*time.Second || o.ChallengeTTL > 5*time.Minute) {
				err = fmt.Errorf("must be within [30s, 5m]")
			}
		case "rate_window", "deny_window":
			var d time.Duration
			d, err = time.ParseDuration(v)
			if err == nil && d < time.Minute {
				err = fmt.Errorf("must be at least 1m")
			}
			if k == "rate_window" {
				o.Window = d
			} else {
				o.DenyWindow = d
			}
		case "per_user", "per_ip", "deny_limit":
			var n int64
			n, err = strconv.ParseInt(v, 10, 64)
			if err == nil && n < 1 {
				err = fmt.Errorf("must be at least 1")
			}
			switch k {
			case "per_user":
				o.PerUser = n
			case "per_ip":
				o.PerIP = n
			default:
				o.DenyLimit = n
			}
		}
		if err != nil {
			return o, fmt.Errorf("option %s: %w", k, err)
		}
	}
	return o, nil
}
