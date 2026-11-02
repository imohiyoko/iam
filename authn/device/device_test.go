package device

import (
	"math"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

func TestToken(t *testing.T) {
	tok, err := NewToken()
	if err != nil || !ValidToken(tok) {
		t.Fatalf("NewToken = %q, %v", tok, err)
	}
	for _, s := range []string{"", "short", tok + "A", tok[:len(tok)-1] + "!", tok[:len(tok)-1] + "="} {
		if ValidToken(s) {
			t.Errorf("ValidToken(%q)", s)
		}
	}
}

func TestDistance(t *testing.T) {
	// 東京〜大阪は約 400 km。
	if d := Distance(35.68, 139.76, 34.69, 135.50); math.Abs(d-400) > 15 {
		t.Fatalf("Tokyo-Osaka = %.0f km", d)
	}
	if d := Distance(1, 2, 1, 2); d != 0 {
		t.Fatalf("same point = %f", d)
	}
}

func TestScore(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	s := &Service{Risk: &RiskConfig{NewDeviceScore: 60, UnconfirmedDeviceScore: 30, NewCountryScore: 70, NewASNScore: 30,
		ImpossibleTravelScore: 90, MaxSpeedKmh: 1000}}
	tokyo := known{port.KnownDevice{LastSeenAt: now.Add(-time.Hour)}, Data{Country: "JP", ASN: 64500, HasCoordinates: true, Lat: 35.68, Lon: 139.76}}
	confirmed := tokyo
	confirmed.data.Confirmed = true
	jp := port.GeoLocation{Country: "JP", ASN: 64500, HasCoordinates: true, Latitude: 34.69, Longitude: 135.50}
	for name, c := range map[string]struct {
		devices []known
		cur     int
		located bool
		loc     port.GeoLocation
		want    map[string]int
	}{
		"first device without geo":   {nil, -1, false, port.GeoLocation{}, map[string]int{risk.TypeDevice: 60}},
		"first device with geo":      {nil, -1, true, jp, map[string]int{risk.TypeDevice: 60, risk.TypeIP: 0}},
		"known unconfirmed, same AS": {[]known{tokyo}, 0, true, jp, map[string]int{risk.TypeDevice: 30, risk.TypeIP: 0}},
		"confirmed":                  {[]known{confirmed}, 0, false, port.GeoLocation{}, map[string]int{risk.TypeDevice: 0}},
		"new ASN":                    {[]known{tokyo}, -1, true, port.GeoLocation{Country: "JP", ASN: 64999}, map[string]int{risk.TypeDevice: 60, risk.TypeIP: 30}},
		"new country":                {[]known{tokyo}, -1, true, port.GeoLocation{Country: "US", ASN: 64500}, map[string]int{risk.TypeDevice: 60, risk.TypeIP: 70}},
		// 1 時間で東京からベルリン（約 9000 km）。
		"impossible travel": {[]known{confirmed}, 0, true, port.GeoLocation{Country: "JP", ASN: 64500, HasCoordinates: true, Latitude: 52.52, Longitude: 13.40},
			map[string]int{risk.TypeDevice: 0, risk.TypeIP: 90}},
	} {
		got := s.score(c.devices, c.cur, c.located, c.loc, now)
		if len(got) != len(c.want) {
			t.Errorf("%s: score = %v, want %v", name, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: score = %v, want %v", name, got, c.want)
			}
		}
	}
}
