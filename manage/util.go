package manage

import (
	"net/url"
	"path"
	"strings"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
)

type (
	// ValidateURIHandler validates that redirectURI is contained in baseURI
	ValidateURIHandler      func(baseURI, redirectURI string) error
	ExtractExtensionHandler func(*oauth2.TokenGenerateRequest, oauth2.ExtendableTokenInfo)
)

// DefaultValidateURI validates that redirectURI matches baseURI.
//
// The registered value is compared after normalization, including the scheme,
// host, port, path, query, and fragment. For backwards compatibility, clients
// that registered only a domain without a path (for example
// https://example.com) may still use a path on that exact origin while they
// migrate to registering complete redirect URIs. New clients should register
// the complete redirect URI; use StrictValidateURI once all clients have
// migrated.
func DefaultValidateURI(baseURI string, redirectURI string) error {
	base, err := normalizeURI(baseURI)
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}

	redirect, err := normalizeURI(redirectURI)
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}

	if base == redirect {
		return nil
	}

	// Compatibility for legacy, domain-only registrations. The comparison is
	// performed on normalized origins and never on raw string suffixes, so
	// evilexample.com cannot match example.com and path traversal cannot move
	// the redirect to another origin.
	if base.isDomainOnly() &&
		base.scheme == redirect.scheme &&
		base.host == redirect.host &&
		base.port == redirect.port &&
		redirect.fragment == "" {
		return nil
	}

	return errors.ErrInvalidRedirectURI
}

// StrictValidateURI validates that redirectURI is an exact, normalized match
// of baseURI. It does not allow the legacy domain-only path compatibility.
func StrictValidateURI(baseURI string, redirectURI string) error {
	base, err := normalizeURI(baseURI)
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}

	redirect, err := normalizeURI(redirectURI)
	if err != nil {
		return errors.ErrInvalidRedirectURI
	}

	if base != redirect {
		return errors.ErrInvalidRedirectURI
	}
	return nil
}

type normalizedURI struct {
	scheme     string
	host       string
	port       string
	path       string
	rawQuery   string
	fragment   string
	forceQuery bool
}

func normalizeURI(raw string) (normalizedURI, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return normalizedURI{}, err
	}
	if u.Scheme == "" || u.Host == "" || u.Opaque != "" || u.User != nil {
		return normalizedURI{}, errors.ErrInvalidRedirectURI
	}

	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return normalizedURI{}, errors.ErrInvalidRedirectURI
	}

	return normalizedURI{
		scheme:     strings.ToLower(u.Scheme),
		host:       host,
		port:       u.Port(),
		path:       normalizePath(u.Path),
		rawQuery:   u.RawQuery,
		fragment:   u.Fragment,
		forceQuery: u.ForceQuery,
	}, nil
}

func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	if p == "." || p == ".." {
		return "/"
	}

	trailingSlash := strings.HasSuffix(p, "/") ||
		strings.HasSuffix(p, "/.") ||
		strings.HasSuffix(p, "/..")

	p = path.Clean(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if trailingSlash && p != "/" {
		p += "/"
	}
	return p
}

func (u normalizedURI) isDomainOnly() bool {
	return u.path == "" && u.rawQuery == "" && u.fragment == "" && !u.forceQuery
}
