package oauth2

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTransportNilTokenSource(t *testing.T) {
	tr := &Transport{}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	client := &http.Client{Transport: tr}
	resp, err := client.Get(server.URL)
	if err == nil {
		t.Errorf("got no errors, want an error with nil token source")
	}
	if resp != nil {
		t.Errorf("Response = %v; want nil", resp)
	}
}

type readCloseCounter struct {
	CloseCount int
	ReadErr    error
}

func (r *readCloseCounter) Read(b []byte) (int, error) {
	return 0, r.ReadErr
}

func (r *readCloseCounter) Close() error {
	r.CloseCount++
	return nil
}

func TestTransportCloseRequestBody(t *testing.T) {
	tr := &Transport{}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	client := &http.Client{Transport: tr}
	body := &readCloseCounter{
		ReadErr: errors.New("readCloseCounter.Read not implemented"),
	}
	resp, err := client.Post(server.URL, "application/json", body)
	if err == nil {
		t.Errorf("got no errors, want an error with nil token source")
	}
	if resp != nil {
		t.Errorf("Response = %v; want nil", resp)
	}
	if expected := 1; body.CloseCount != expected {
		t.Errorf("Body was closed %d times, expected %d", body.CloseCount, expected)
	}
}

func TestTransportCloseRequestBodySuccess(t *testing.T) {
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	client := &http.Client{Transport: tr}
	body := &readCloseCounter{
		ReadErr: io.EOF,
	}
	resp, err := client.Post(server.URL, "application/json", body)
	if err != nil {
		t.Errorf("got error %v; expected none", err)
	}
	if resp == nil {
		t.Errorf("Response is nil; expected non-nil")
	}
	if expected := 1; body.CloseCount != expected {
		t.Errorf("Body was closed %d times, expected %d", body.CloseCount, expected)
	}
}

func TestTransportTokenSource(t *testing.T) {
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer abc"; got != want {
			t.Errorf("Authorization header = %q; want %q", got, want)
		}
	})
	defer server.Close()
	client := &http.Client{Transport: tr}
	res, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestTransportBeforeRequestHeader(t *testing.T) {
	const tenantToken = "tenant-extra-token"
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
		BeforeRequest: func(req *http.Request) (*http.Request, error) {
			// Return a clone rather than mutating the request in place:
			// ownership of the outgoing request is handed back explicitly.
			req = req.Clone(req.Context())
			req.Header.Set("X-Tenant-Token", tenantToken)
			return req, nil
		},
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer abc"; got != want {
			t.Errorf("Authorization header = %q; want %q", got, want)
		}
		if got, want := r.Header.Get("X-Tenant-Token"), tenantToken; got != want {
			t.Errorf("X-Tenant-Token header = %q; want %q", got, want)
		}
	})
	defer server.Close()
	client := &http.Client{Transport: tr}
	res, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestTransportBeforeRequestDoesNotMutateCallerRequest(t *testing.T) {
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
		BeforeRequest: func(req *http.Request) (*http.Request, error) {
			req = req.Clone(req.Context())
			req.Header.Set("X-Tenant-Token", "from-hook")
			return req, nil
		},
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()

	outReq, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RoundTrip(outReq); err != nil {
		t.Fatal(err)
	}
	if got := outReq.Header.Get("X-Tenant-Token"); got != "" {
		t.Errorf("caller request mutated by hook: X-Tenant-Token = %q; want empty", got)
	}
	if got := outReq.Header.Get("Authorization"); got != "" {
		t.Errorf("caller request mutated by Transport: Authorization = %q; want empty", got)
	}
}

func TestTransportBeforeRequestReplaceRequest(t *testing.T) {
	const replacedPath = "/from-hook"
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
		BeforeRequest: func(req *http.Request) (*http.Request, error) {
			replaced := req.Clone(req.Context())
			replaced.URL.Path = replacedPath
			replaced.Header.Set("X-Tenant-Token", "from-hook")
			return replaced, nil
		},
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != replacedPath {
			t.Errorf("request path = %q; want %q", r.URL.Path, replacedPath)
		}
		if got := r.Header.Get("X-Tenant-Token"); got != "from-hook" {
			t.Errorf("X-Tenant-Token header = %q; want %q", got, "from-hook")
		}
		if got := r.Header.Get("Authorization"); got != "Bearer abc" {
			t.Errorf("Authorization header = %q; want %q", got, "Bearer abc")
		}
	})
	defer server.Close()
	client := &http.Client{Transport: tr}
	res, err := client.Get(server.URL + "/original")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestTransportBeforeRequestError(t *testing.T) {
	hookErr := errors.New("hook refused request")
	var serverCalled bool
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
		BeforeRequest: func(req *http.Request) (*http.Request, error) {
			return nil, hookErr
		},
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
	})
	defer server.Close()
	client := &http.Client{Transport: tr}
	res, err := client.Get(server.URL)
	if !errors.Is(err, hookErr) {
		t.Errorf("err = %v; want %v", err, hookErr)
	}
	if res != nil {
		t.Errorf("Response = %v; want nil", res)
	}
	if serverCalled {
		t.Error("server was contacted even though the hook returned an error")
	}
}

func TestTransportBeforeRequestNilRequest(t *testing.T) {
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
		BeforeRequest: func(req *http.Request) (*http.Request, error) {
			return nil, nil
		},
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {})
	defer server.Close()
	res, err := tr.RoundTrip(mustNewRequest(t, server.URL))
	if err == nil {
		t.Error("got no error for a hook returning a nil request")
	}
	if res != nil {
		t.Errorf("Response = %v; want nil", res)
	}
}

func TestTransportBeforeRequestReplacesBody(t *testing.T) {
	originalBody := &trackingReadCloser{
		readCloser: io.NopCloser(strings.NewReader("original-body")),
	}

	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
		BeforeRequest: func(req *http.Request) (*http.Request, error) {
			replaced := req.Clone(req.Context())
			replaced.Body = io.NopCloser(strings.NewReader("replaced-body"))
			replaced.ContentLength = int64(len("replaced-body"))
			return replaced, nil
		},
	}
	server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading body: %v", err)
		}
		if got, want := string(body), "replaced-body"; got != want {
			t.Errorf("request body = %q; want %q", got, want)
		}
	})
	defer server.Close()
	client := &http.Client{Transport: tr}
	res, err := client.Post(server.URL, "text/plain", originalBody)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if originalBody.closeCount != 1 {
		t.Errorf("original request Body closed %d times; want 1", originalBody.closeCount)
	}
}

type trackingReadCloser struct {
	readCloser io.ReadCloser
	closeCount int
}

func (body *trackingReadCloser) Read(b []byte) (int, error) {
	return body.readCloser.Read(b)
}

func (body *trackingReadCloser) Close() error {
	body.closeCount++
	return body.readCloser.Close()
}

func TestTransportBeforeRequestFollowsRedirects(t *testing.T) {
	var hookHops []string
	tr := &Transport{
		Source: StaticTokenSource(&Token{
			AccessToken: "abc",
		}),
		BeforeRequest: func(req *http.Request) (*http.Request, error) {
			hookHops = append(hookHops, req.URL.Path)
			req = req.Clone(req.Context())
			req.Header.Set("X-Tenant-Token", "from-hook")
			return req, nil
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Tenant-Token"); got != "from-hook" {
			t.Errorf("redirect hop: X-Tenant-Token = %q; want %q", got, "from-hook")
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Tenant-Token"); got != "from-hook" {
			t.Errorf("final hop: X-Tenant-Token = %q; want %q", got, "from-hook")
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{Transport: tr}
	res, err := client.Get(server.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	wantHops := []string{"/redirect", "/final"}
	if !slices.Equal(hookHops, wantHops) {
		t.Errorf("hook invocations = %v; want %v", hookHops, wantHops)
	}
}

func mustNewRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// Test for case-sensitive token types, per https://github.com/golang/oauth2/issues/113
func TestTransportTokenSourceTypes(t *testing.T) {
	const val = "abc"
	tests := []struct {
		key  string
		val  string
		want string
	}{
		{key: "bearer", val: val, want: "Bearer abc"},
		{key: "mac", val: val, want: "MAC abc"},
		{key: "basic", val: val, want: "Basic abc"},
	}
	for _, tc := range tests {
		tr := &Transport{
			Source: StaticTokenSource(&Token{
				AccessToken: tc.val,
				TokenType:   tc.key,
			}),
		}
		server := newMockServer(func(w http.ResponseWriter, r *http.Request) {
			if got, want := r.Header.Get("Authorization"), tc.want; got != want {
				t.Errorf("Authorization header (%q) = %q; want %q", val, got, want)
			}
		})
		defer server.Close()
		client := &http.Client{Transport: tr}
		res, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
}

func TestTokenValidNoAccessToken(t *testing.T) {
	token := &Token{}
	if token.Valid() {
		t.Errorf("got valid with no access token; want invalid")
	}
}

func TestExpiredWithExpiry(t *testing.T) {
	token := &Token{
		Expiry: time.Now().Add(-5 * time.Hour),
	}
	if token.Valid() {
		t.Errorf("got valid with expired token; want invalid")
	}
}

func newMockServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}
