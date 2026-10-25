package openconnect

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func parseF5TestOptions(t *testing.T, fields string) (*f5TunnelConfiguration, []string, error) {
	t.Helper()
	return parseF5Options([]byte(`<?xml version="1.0" encoding="utf-8"?>
<favorite id="/Common/na"><object ID="ID_PARAMS"><ur_Z>urz</ur_Z><Session_ID>sid</Session_ID><IPV4_0>1</IPV4_0>`+
		fields+`</object></favorite>`), time.Time{})
}

func f5TestRoutePrefixes(routes []TunnelRoute) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, route := range routes {
		prefixes = append(prefixes, route.Prefix)
	}
	return prefixes
}

func TestF5OptionsLists(t *testing.T) {
	t.Parallel()
	configuration, warnings, err := parseF5TestOptions(t,
		`<DNS0>192.0.2.1  192.0.2.2</DNS0><DNS1>192.0.2.3 192.0.2.4</DNS1>`+
			`<WINS0>192.0.2.130 192.0.2.131</WINS0>`+
			`<DNSSuffix0>example.com example.net</DNSSuffix0>`+
			`<LAN0>198.51.100.0/255.255.255.0 203.0.113.7 10.0.0.0/8 10.1.2.3/255.255.0.0</LAN0>`+
			`<LAN6_0>2001:db8:1::/ffff:ffff:ffff:: 2001:db8:2::/48 2001:db8:3::1</LAN6_0>`+
			`<ExcludeSubnets0>198.51.100.128/255.255.255.128</ExcludeSubnets0>`)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %q", warnings)
	}
	expectedDNS := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
	}
	if !slices.Equal(configuration.configuration.DNS, expectedDNS) {
		t.Fatalf("DNS = %v, want %v", configuration.configuration.DNS, expectedDNS)
	}
	expectedNBNS := []netip.Addr{
		netip.MustParseAddr("192.0.2.130"),
		netip.MustParseAddr("192.0.2.131"),
	}
	if !slices.Equal(configuration.configuration.NBNS, expectedNBNS) {
		t.Fatalf("NBNS = %v, want %v", configuration.configuration.NBNS, expectedNBNS)
	}
	if !slices.Equal(configuration.configuration.SearchDomains, []string{"example.com", "example.net"}) {
		t.Fatalf("search domains = %q", configuration.configuration.SearchDomains)
	}
	expectedRoutes := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.7/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("2001:db8:1::/48"),
		netip.MustParsePrefix("2001:db8:2::/48"),
		netip.MustParsePrefix("2001:db8:3::1/128"),
	}
	if routes := f5TestRoutePrefixes(configuration.configuration.Routes); !slices.Equal(routes, expectedRoutes) {
		t.Fatalf("routes = %v, want %v", routes, expectedRoutes)
	}
	expectedExcludedRoutes := []netip.Prefix{netip.MustParsePrefix("198.51.100.128/25")}
	if routes := f5TestRoutePrefixes(configuration.configuration.ExcludedRoutes); !slices.Equal(routes, expectedExcludedRoutes) {
		t.Fatalf("excluded routes = %v, want %v", routes, expectedExcludedRoutes)
	}
}

func TestF5OptionsSkipInvalidOptionalValues(t *testing.T) {
	t.Parallel()
	configuration, warnings, err := parseF5TestOptions(t,
		`<DNS0>not-an-address 192.0.2.1</DNS0>`+
			`<WINS0>192.0.2.130 150.65</WINS0>`+
			`<LAN0>10/8 198.51.100.0/255.0.255.0 198.51.100.0/ffff:: 203.0.113.0/24</LAN0>`+
			`<LAN6_0>2001:db8::/ffff:0:ffff:: 2001:db8:1::/64</LAN6_0>`+
			`<ExcludeSubnets0>bogus 203.0.113.128/25</ExcludeSubnets0>`+
			`<idle_session_timeout>forever</idle_session_timeout>`+
			`<tunnel_dtls>maybe</tunnel_dtls><tunnel_port_dtls>4433x</tunnel_port_dtls>`+
			`<dtls_v1_2_supported>maybe</dtls_v1_2_supported>`)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 11 {
		t.Fatalf("warnings = %q, want 11", warnings)
	}
	if !slices.Equal(configuration.configuration.DNS, []netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
		t.Fatalf("DNS = %v", configuration.configuration.DNS)
	}
	if !slices.Equal(configuration.configuration.NBNS, []netip.Addr{netip.MustParseAddr("192.0.2.130")}) {
		t.Fatalf("NBNS = %v", configuration.configuration.NBNS)
	}
	expectedRoutes := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:1::/64"),
	}
	if routes := f5TestRoutePrefixes(configuration.configuration.Routes); !slices.Equal(routes, expectedRoutes) {
		t.Fatalf("routes = %v, want %v", routes, expectedRoutes)
	}
	expectedExcludedRoutes := []netip.Prefix{netip.MustParsePrefix("203.0.113.128/25")}
	if routes := f5TestRoutePrefixes(configuration.configuration.ExcludedRoutes); !slices.Equal(routes, expectedExcludedRoutes) {
		t.Fatalf("excluded routes = %v, want %v", routes, expectedExcludedRoutes)
	}
	if configuration.configuration.IdleTimeout != 0 || configuration.dtlsEnabled || configuration.dtlsPort != 0 || configuration.dtls12 {
		t.Fatalf("invalid optional values were not ignored: %+v", configuration)
	}
}

func TestF5OptionsStrictValues(t *testing.T) {
	t.Parallel()
	for _, fields := range []string{
		`<IPV6_0>maybe</IPV6_0>`,
		`<hdlc_framing>maybe</hdlc_framing>`,
		`<UseDefaultGateway0>maybe</UseDefaultGateway0>`,
	} {
		_, _, err := parseF5TestOptions(t, fields)
		if err == nil {
			t.Fatalf("expected %s to be rejected", fields)
		}
	}
}
