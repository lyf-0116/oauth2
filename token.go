// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2/internal"
)

// defaultExpiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const defaultExpiryDelta = 10 * time.Second

// Token represents the credentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
//
// Most users of this package should not access fields of Token
// directly. They're exported mostly for use by related packages
// implementing derivative OAuth2 flows.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, [TokenSource] implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// ExpiresIn is the OAuth2 wire format "expires_in" field,
	// which specifies how many seconds later the token expires,
	// relative to an unknown time base approximately around "now".
	// It is the application's responsibility to populate
	// `Expiry` from `ExpiresIn` when required.
	ExpiresIn int64 `json:"expires_in,omitempty"`

	// raw optionally contains extra metadata from the server
	// when updating a token.
	raw any

	// expiryDelta is used to calculate when a token is considered
	// expired, by subtracting from Expiry. If zero, defaultExpiryDelta
	// is used.
	expiryDelta time.Duration

	// retrievedAt is the local time (including a monotonic clock reading)
	// at which the token response was received. Tokens built from an
	// "expires_in" field measure elapsed time against this anchor rather
	// than comparing two wall-clock instants, so a wall clock adjusted
	// backwards or forwards cannot resurrect or prematurely expire them.
	retrievedAt time.Time

	// serverTimeOffset is serverTime - localTime observed at retrieval,
	// derived from the HTTP "Date" header. It corrects expiry checks for
	// tokens whose monotonic anchor has been lost (typically after
	// serialization), when the local clock disagrees with the server.
	serverTimeOffset time.Duration

	// hasServerTime reports whether serverTimeOffset is meaningful, i.e. the
	// server provided a usable "Date" header. When false and no monotonic
	// anchor is available, expiry is judged on the local wall clock alone.
	hasServerTime bool
}

// Type returns t.TokenType if non-empty, else "Bearer".
func (t *Token) Type() string {
	if strings.EqualFold(t.TokenType, "bearer") {
		return "Bearer"
	}
	if strings.EqualFold(t.TokenType, "mac") {
		return "MAC"
	}
	if strings.EqualFold(t.TokenType, "basic") {
		return "Basic"
	}
	if t.TokenType != "" {
		return t.TokenType
	}
	return "Bearer"
}

// SetAuthHeader sets the Authorization header to r using the access
// token in t.
//
// This method is unnecessary when using [Transport] or an HTTP Client
// returned by this package.
func (t *Token) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", t.Type()+" "+t.AccessToken)
}

// WithExtra returns a new [Token] that's a clone of t, but using the
// provided raw extra map. This is only intended for use by packages
// implementing derivative OAuth2 flows.
func (t *Token) WithExtra(extra any) *Token {
	t2 := new(Token)
	*t2 = *t
	t2.raw = extra
	return t2
}

// Extra returns an extra field.
// Extra fields are key-value pairs returned by the server as
// part of the token retrieval response.
func (t *Token) Extra(key string) any {
	if raw, ok := t.raw.(map[string]any); ok {
		return raw[key]
	}

	vals, ok := t.raw.(url.Values)
	if !ok {
		return nil
	}

	v := vals.Get(key)
	switch s := strings.TrimSpace(v); strings.Count(s, ".") {
	case 0: // Contains no "."; try to parse as int
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
	case 1: // Contains a single "."; try to parse as float
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}

	return v
}

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

// hasMonotonicReading reports whether t carries a monotonic clock reading.
// Times returned by time.Now do; times reconstructed from a wall-clock value
// (time.Unix, parsed strings, JSON) do not. Round(0) is documented to strip
// the monotonic reading while preserving the wall-clock component. Time
// equality (==) compares every field, unlike Time.Equal which ignores the
// monotonic reading, so t differs from t.Round(0) exactly when it has one.
func hasMonotonicReading(t time.Time) bool {
	return t != t.Round(0)
}

// monotonicSince reports the monotonic-clock elapsed duration since ref.
// It returns the elapsed duration and ok=false if ref or now carries no
// monotonic clock reading (for example, because ref was reconstructed from
// JSON or built manually), in which case a monotonic comparison is
// impossible.
func monotonicSince(ref, now time.Time) (time.Duration, bool) {
	if hasMonotonicReading(ref) && hasMonotonicReading(now) {
		return now.Sub(ref), true
	}
	return 0, false
}

// expired reports whether the token is expired.
// t must be non-nil.
func (t *Token) expired() bool {
	if t.Expiry.IsZero() {
		return false
	}

	expiryDelta := defaultExpiryDelta
	if t.expiryDelta != 0 {
		expiryDelta = t.expiryDelta
	}

	now := timeNow()

	// Strong path: the token was retrieved within this process and therefore
	// has a monotonic anchor. Measure elapsed time against the monotonic
	// clock, which never jumps, so wall-clock adjustments cannot change the
	// verdict. Expiry and retrievedAt were produced from the same clock
	// reading, so their difference is the token's intended lifetime.
	if elapsed, ok := monotonicSince(t.retrievedAt, now); ok {
		lifetime := t.Expiry.Sub(t.retrievedAt)
		return lifetime-elapsed <= expiryDelta
	}

	// Weak path: no monotonic anchor is available. If the server supplied a
	// time at retrieval, estimate the current server time and compare in the
	// server's frame; otherwise compare against the uncorrected local wall
	// clock, which is a weak verdict observable through Token.WeakExpiry.
	if t.hasServerTime {
		now = now.Add(t.serverTimeOffset)
	}
	return t.Expiry.Round(0).Add(-expiryDelta).Before(now.Round(0))
}

// Valid reports whether t is non-nil, has an AccessToken, and is not expired.
func (t *Token) Valid() bool {
	return t != nil && t.AccessToken != "" && !t.expired()
}

// WeakExpiry reports whether the token's expiration is judged solely against
// the local wall clock, without a monotonic-clock anchor or a time supplied
// by the authorization server.
//
// A weak verdict is vulnerable to the local clock being adjusted: setting it
// backwards can make an expired token look valid again, while setting it
// forwards can make a freshly issued token look expired. It occurs when the
// token was reconstructed without retrieval metadata (for example, after
// JSON serialization), or when the token endpoint provided no usable "Date"
// response header at retrieval time.
func (t *Token) WeakExpiry() bool {
	if t == nil {
		return false
	}
	_, hasMonotonic := monotonicSince(t.retrievedAt, timeNow())
	return !hasMonotonic && !t.hasServerTime
}

// SetRetrievalMetadata records the clock context in which the token was
// obtained. retrievedAt is the local time (with a monotonic reading) at which
// the response was received; serverTimeOffset is serverTime - localTime; and
// hasServerTime reports whether that offset was supplied by the server.
//
// This is intended for related packages implementing derivative OAuth2 flows
// that reconstruct a Token from an internal representation. Most callers
// should never need it.
func (t *Token) SetRetrievalMetadata(retrievedAt time.Time, serverTimeOffset time.Duration, hasServerTime bool) {
	if t == nil {
		return
	}
	t.retrievedAt = retrievedAt
	t.serverTimeOffset = serverTimeOffset
	t.hasServerTime = hasServerTime
}

// tokenFromInternal maps an *internal.Token struct into
// a *Token struct.
func tokenFromInternal(t *internal.Token) *Token {
	if t == nil {
		return nil
	}
	return &Token{
		AccessToken:      t.AccessToken,
		TokenType:        t.TokenType,
		RefreshToken:     t.RefreshToken,
		Expiry:           t.Expiry,
		ExpiresIn:        t.ExpiresIn,
		raw:              t.Raw,
		retrievedAt:      t.RetrievedAt,
		serverTimeOffset: t.ServerTimeOffset,
		hasServerTime:    !t.WeakExpiry,
	}
}

// retrieveToken takes a *Config and uses that to retrieve an *internal.Token.
// This token is then mapped from *internal.Token into an *oauth2.Token which is returned along
// with an error.
func retrieveToken(ctx context.Context, c *Config, v url.Values) (*Token, error) {
	tk, err := internal.RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, v, internal.AuthStyle(c.Endpoint.AuthStyle), c.authStyleCache.Get())
	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*RetrieveError)(rErr)
		}
		return nil, err
	}
	return tokenFromInternal(tk), nil
}

// RetrieveError is the error returned when the token endpoint returns a
// non-2XX HTTP status code or populates RFC 6749's 'error' parameter.
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type RetrieveError struct {
	Response *http.Response
	// Body is the body that was consumed by reading Response.Body.
	// It may be truncated.
	Body []byte
	// ErrorCode is RFC 6749's 'error' parameter.
	ErrorCode string
	// ErrorDescription is RFC 6749's 'error_description' parameter.
	ErrorDescription string
	// ErrorURI is RFC 6749's 'error_uri' parameter.
	ErrorURI string
}

func (r *RetrieveError) Error() string {
	if r.ErrorCode != "" {
		s := fmt.Sprintf("oauth2: %q", r.ErrorCode)
		if r.ErrorDescription != "" {
			s += fmt.Sprintf(" %q", r.ErrorDescription)
		}
		if r.ErrorURI != "" {
			s += fmt.Sprintf(" %q", r.ErrorURI)
		}
		return s
	}
	return fmt.Sprintf("oauth2: cannot fetch token: %v\nResponse: %s", r.Response.Status, r.Body)
}
