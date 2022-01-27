package auth

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

type forwardAuthRoundTripper struct {
	transport http.RoundTripper
	cache     *badger.DB
	ttl       time.Duration
	vary      map[string]struct{}
}

// NewRoundTripper creates a caching round tripper based on middleware configuration.
func NewRoundTripper(config dynamic.ForwardAuth) (http.RoundTripper, error) {
	if config.Cache.TTL == 0 {
		return http.DefaultTransport, nil
	}

	badgerOptions := badger.DefaultOptions("").WithInMemory(true)
	db, _ := badger.Open(badgerOptions)

	vary := map[string]struct{}{}
	for _, v := range config.Cache.Vary {
		vary[strings.ToLower(v)] = struct{}{}
	}

	rt := forwardAuthRoundTripper{
		transport: http.DefaultTransport,
		cache:     db,
		ttl:       time.Duration(config.Cache.TTL * int64(time.Second)),
		vary:      vary,
	}

	return &rt, nil
}

func (frt *forwardAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	cacheKey := frt.GetCacheKey(req)
	cachedResponse := frt.CachedResponse(req, cacheKey)
	if cachedResponse != nil {
		return cachedResponse, nil
	}

	resp, err := frt.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, nil
	}

	// Delay caching until EOF is reached.
	resp.Body = &cachingReadCloser{
		R: resp.Body,
		OnEOF: func(r io.Reader) {
			re := *resp
			re.Body = ioutil.NopCloser(r)
			frt.Store(&re, cacheKey)
		},
	}

	return resp, nil
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
// (This function copyright goauth2 authors: https://code.google.com/p/goauth2)
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}
	return r2
}

// CachedResponse returns the cached http.Response for req if present, and nil otherwise.
func (frt *forwardAuthRoundTripper) CachedResponse(req *http.Request, cachedKey string) *http.Response {
	clonedReq := cloneRequest(req)
	cachedVal := frt.Get(cachedKey)
	b := bytes.NewBuffer(cachedVal)
	response, _ := http.ReadResponse(bufio.NewReader(b), clonedReq)

	return response
}

// GetCacheKey returns the varied cache key for req and resp.
func (frt forwardAuthRoundTripper) GetCacheKey(req *http.Request) string {
	var headers []string
	method := req.Method
	for i, v := range req.Header {
		lower := strings.ToLower(i)
		_, exists := frt.vary[lower]
		if exists {
			headers = append(headers, fmt.Sprintf("%s:%s", i, v))
		}
	}

	return fmt.Sprintf("%s-%s-%s", method, req.Host, req.RequestURI) + "-" + strings.Join(headers, ";")
}

// Get method returns the populated response if exists, empty response then.
func (frt *forwardAuthRoundTripper) Get(key string) []byte {
	var item *badger.Item
	var result []byte

	e := frt.cache.View(func(txn *badger.Txn) error {
		i, err := txn.Get([]byte(key))
		item = i
		return err
	})

	if errors.Is(e, badger.ErrKeyNotFound) {
		return result
	}

	_ = item.Value(func(val []byte) error {
		result = val
		return nil
	})

	return result
}

// Store method will store the response in cache.
func (frt *forwardAuthRoundTripper) Store(resp *http.Response, key string) {
	respBytes, err := httputil.DumpResponse(resp, true)
	if err == nil {
		frt.Set(key, respBytes)
	}
}

// Set method will store the response in Badger provider.
func (frt *forwardAuthRoundTripper) Set(key string, value []byte) {
	err := frt.cache.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(badger.NewEntry([]byte(key), value).WithTTL(frt.ttl))
	})
	if err != nil {
		panic(fmt.Sprintf("Cannot set value into Badger, %s", err))
	}
}

// cachingReadCloser is a wrapper around ReadCloser R that calls OnEOF
// handler with a full copy of the content read from R when EOF is
// reached.
type cachingReadCloser struct {
	// Underlying ReadCloser.
	R io.ReadCloser
	// OnEOF is called with a copy of the content of R when EOF is reached.
	OnEOF func(io.Reader)

	buf bytes.Buffer // buf stores a copy of the content of R.
}

// Read reads the next len(p) bytes from R or until R is drained. The
// return value n is the number of bytes read. If R has no data to
// return, err is io.EOF and OnEOF is called with a full copy of what
// has been read so far.
func (r *cachingReadCloser) Read(p []byte) (n int, err error) {
	if r.R == nil {
		r.OnEOF(bytes.NewReader(p))
		return 0, io.EOF
	}
	n, err = r.R.Read(p)
	r.buf.Write(p[:n])
	if errors.Is(err, io.EOF) {
		r.Close()
		r.OnEOF(bytes.NewReader(r.buf.Bytes()))
	}
	return
}

func (r *cachingReadCloser) Close() error {
	return r.R.Close()
}
