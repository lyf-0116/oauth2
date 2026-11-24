// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"log"
	"net/http"
	"sync"
)

// Transport is an [http.RoundTripper] that makes OAuth 2.0 HTTP requests,
// wrapping a base [http.RoundTripper] and adding an Authorization header
// with a token from the supplied [TokenSource].
//
// Transport is a low-level mechanism. Most code will use the
// higher-level [Config.Client] method instead.
type Transport struct {
	// Source supplies the token to add to outgoing requests'
	// Authorization headers.
	Source TokenSource

	// Base is the base RoundTripper used to make HTTP requests.
	// If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// BeforeRequest, if non-nil, is invoked on the request that is
	// actually sent, after the incoming request has been cloned and after
	// the Authorization header has been added.
	//
	// The hook owns the request it receives: it must not mutate it in
	// place and instead return the request (cloned or modified) that the
	// Transport should hand to the base RoundTripper. Returning nil, or
	// returning a request other than the one passed in, is supported. A
	// non-nil error aborts the RoundTrip without contacting the server.
	//
	// Because the hook runs against the cloned request, its changes are
	// immune to the clones performed by the Transport itself and by the
	// surrounding http.Client (redirects, retries and authentication
	// injection each work on their own copy). The returned request is the
	// single owner of the hook's modifications for this RoundTrip.
	//
	// The hook runs once per RoundTrip. An http.Client following a
	// redirect enters RoundTrip again for each hop, so the hook is
	// re-invoked on every redirected request and its modifications follow
	// the redirect automatically.
	//
	// If the hook returns a request whose Body differs from the incoming
	// request's Body, the original Body is closed by the Transport; the
	// returned Body is then owned by the base RoundTripper.
	BeforeRequest func(*http.Request) (*http.Request, error)
}

// RoundTrip authorizes and authenticates the request with an
// access token from Transport's Source.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				req.Body.Close()
			}
		}()
	}

	if t.Source == nil {
		return nil, errors.New("oauth2: Transport's Source is nil")
	}
	token, err := t.Source.Token()
	if err != nil {
		return nil, err
	}

	// Clone first, and run every modification against the clone. The
	// caller's request is never mutated, and there is exactly one request
	// instance from this point on, so a hook cannot end up editing a
	// detached copy that the base RoundTripper never sees.
	req2 := req.Clone(req.Context())
	token.SetAuthHeader(req2)
	if t.BeforeRequest != nil {
		var hookedReq *http.Request
		hookedReq, err = t.BeforeRequest(req2)
		if err != nil {
			return nil, err
		}
		if hookedReq == nil {
			return nil, errors.New("oauth2: Transport's BeforeRequest returned a nil request")
		}
		if req2.Body != nil && hookedReq.Body != req2.Body {
			req2.Body.Close()
			reqBodyClosed = true
		}
		req2 = hookedReq
	}

	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true
	return t.base().RoundTrip(req2)
}

var cancelOnce sync.Once

// CancelRequest does nothing. It used to be a legacy cancellation mechanism
// but now only logs on first use to warn that it's deprecated.
//
// Deprecated: use contexts for cancellation instead.
func (t *Transport) CancelRequest(req *http.Request) {
	cancelOnce.Do(func() {
		log.Printf("deprecated: golang.org/x/oauth2: Transport.CancelRequest no longer does anything; use contexts")
	})
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}
