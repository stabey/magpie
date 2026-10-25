package provider

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// Only parse a callback for the listener belonging to this login. No URL here
// is fetched, and localhost aliases still have to name the exact callback port.
func pastedCallbackURL(raw, redirect string, paths ...string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	expected, _ := url.Parse(redirect)
	if err != nil || u.User != nil || u.Fragment != "" || u.Scheme != "http" || u.Port() != expected.Port() {
		return nil, errors.New("paste the complete localhost callback URL from this sign-in")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("the callback must use this sign-in's localhost address")
	}
	if len(paths) > 0 {
		ok := false
		for _, path := range paths {
			if u.Path == path {
				ok = true
			}
		}
		if !ok {
			return nil, errors.New("invalid callback path")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid callback query")
	}
	for _, values := range q {
		if len(values) != 1 {
			return nil, errors.New("duplicate callback parameter")
		}
	}
	return u, nil
}
