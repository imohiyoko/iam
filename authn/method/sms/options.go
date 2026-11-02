package sms

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// options は設定ファイルの methods.sms の項目（ADR 0104）。
type options struct {
	CodeTTL        time.Duration
	Digits         int
	Channels       []string
	Countries      []string
	Window         time.Duration
	PerUser        int64
	PerNumber      int64
	PerIP          int64
	ResendInterval time.Duration
}

// 既定値。
var defaults = options{
	CodeTTL: 5 * time.Minute, Digits: 6, Channels: []string{ChannelSMS}, Window: time.Hour,
	PerUser: 5, PerNumber: 5, PerIP: 20, ResendInterval: 30 * time.Second,
}

var knownOptions = []string{"code_ttl", "digits", "channels", "allowed_country_codes", "rate_window", "per_user", "per_number", "per_ip",
	"resend_interval"}

// parseOptions は項目を読み、範囲を確かめる。知らない項目はエラー。
func parseOptions(m map[string]string) (options, error) {
	o := defaults
	o.Channels = slices.Clone(defaults.Channels)
	for k, v := range m {
		if !slices.Contains(knownOptions, k) {
			return o, fmt.Errorf("unknown option %q (allowed: %v)", k, knownOptions)
		}
		var err error
		switch k {
		case "code_ttl":
			o.CodeTTL, err = time.ParseDuration(v)
			if err == nil && (o.CodeTTL < time.Minute || o.CodeTTL > 10*time.Minute) {
				err = fmt.Errorf("must be within [1m, 10m]")
			}
		case "digits":
			o.Digits, err = strconv.Atoi(v)
			if err == nil && (o.Digits < 6 || o.Digits > 8) {
				err = fmt.Errorf("must be within [6, 8]")
			}
		case "channels":
			o.Channels = nil
			for c := range strings.SplitSeq(v, ",") {
				c = strings.TrimSpace(c)
				if c != ChannelSMS && c != ChannelVoice {
					err = fmt.Errorf("unknown channel %q", c)
					break
				}
				if !slices.Contains(o.Channels, c) {
					o.Channels = append(o.Channels, c)
				}
			}
		case "allowed_country_codes":
			for c := range strings.SplitSeq(v, ",") {
				c = strings.TrimPrefix(strings.TrimSpace(c), "+")
				if !countryRE.MatchString(c) {
					err = fmt.Errorf("invalid country code %q", c)
					break
				}
				o.Countries = append(o.Countries, c)
			}
		case "rate_window":
			o.Window, err = time.ParseDuration(v)
			if err == nil && o.Window < time.Minute {
				err = fmt.Errorf("must be at least 1m")
			}
		case "per_user", "per_number", "per_ip":
			var n int64
			n, err = strconv.ParseInt(v, 10, 64)
			if err == nil && n < 1 {
				err = fmt.Errorf("must be at least 1")
			}
			switch k {
			case "per_user":
				o.PerUser = n
			case "per_number":
				o.PerNumber = n
			default:
				o.PerIP = n
			}
		case "resend_interval":
			o.ResendInterval, err = time.ParseDuration(v)
			if err == nil && (o.ResendInterval < time.Second || o.ResendInterval > 10*time.Minute) {
				err = fmt.Errorf("must be within [1s, 10m]")
			}
		}
		if err != nil {
			return o, fmt.Errorf("option %s: %w", k, err)
		}
	}
	if len(o.Channels) == 0 {
		return o, fmt.Errorf("option channels: at least one channel is required")
	}
	return o, nil
}
