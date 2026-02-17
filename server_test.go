package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVNCHandler(t *testing.T) {
	testCase := func(url string, expectedStatus int, expectedAddr string, defhost string, defport uint16, allowHosts, allowPorts bool, cidrList []*net.IPNet, isWhitelist bool) func(*testing.T) {
		return func(t *testing.T) {
			r := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()

			var ws bool
			func() {
				defer func() {
					// workaround for websocket library issue with a fake http response
					if err := recover(); strings.Contains(fmt.Sprint(err), "not http.Hijacker") {
						ws = true
					} else if err != nil {
						panic(err)
					}
				}()
				vnc := vncHandler(defhost, defport, false, allowHosts, allowPorts, cidrList, isWhitelist, nil)
				m := http.NewServeMux()
				m.Handle("/vnc", vnc)
				m.Handle("/vnc/{host}", vnc)
				m.Handle("/vnc/{host}/{port}", vnc)
				m.ServeHTTP(w, r)
			}()

			c := w.Result().StatusCode
			if ws && c == 200 {
				c = 101
			}
			if c != expectedStatus {
				t.Errorf("expected status %d, got %d", expectedStatus, c)
			}

			if a := w.Result().Header.Get("X-Target-Addr"); a != expectedAddr {
				t.Errorf("expected addr %#v, got %#v", expectedAddr, a)
			}
		}
	}
	t.Run("Simple", testCase("http://example.com/vnc", 101, "localhost:5900", "localhost", 5900, false, false, nil, false))
	t.Run("SimpleBlockHost", testCase("http://example.com/vnc/test", 401, "", "localhost", 5900, false, false, nil, false))
	t.Run("SimpleBlockHostPort", testCase("http://example.com/vnc/test/1234", 401, "", "localhost", 5900, true, false, nil, false))

	t.Run("Custom", testCase("http://example.com/vnc", 101, "example.com:1234", "example.com", 1234, false, false, nil, false))
	t.Run("CustomHost", testCase("http://example.com/vnc/test", 101, "test:1234", "example.com", 1234, true, false, nil, false))
	t.Run("CustomHostPort", testCase("http://example.com/vnc/test/3456", 101, "test:3456", "example.com", 1234, true, true, nil, false))

	t.Run("CIDRWhitelistAllowIP", testCase("http://example.com/vnc/10.0.0.1", 101, "10.0.0.1:5900", "localhost", 5900, true, true, mustParseCIDRList("192.168.0.0/24,10.0.0.0/24"), true))
	t.Run("CIDRWhitelistBlockIP", testCase("http://example.com/vnc/127.0.0.1", 401, "", "localhost", 5900, true, true, mustParseCIDRList("192.168.0.0/24,10.0.0.0/24"), true))
	t.Run("CIDRBlacklistBlockIP", testCase("http://example.com/vnc/10.0.0.1", 401, "", "localhost", 5900, true, true, mustParseCIDRList("192.168.0.0/24,10.0.0.0/24"), false))
	t.Run("CIDRBlacklistAllowIP", testCase("http://example.com/vnc/127.0.0.1/5900", 101, "127.0.0.1:5900", "localhost", 5900, true, true, mustParseCIDRList("192.168.0.0/24,10.0.0.0/24"), false))

	t.Run("CIDRWhitelistAllowIPv6", testCase("http://example.com/vnc/a%3Ab%3Ac%3Ad%3Aa%3Ab%3Ac%3Ad", 101, "[a:b:c:d:a:b:c:d]:5900", "localhost", 5900, true, true, mustParseCIDRList("a:b:c:d:a:b:c:d/120"), true))
	t.Run("CIDRWhitelistBlockIPv6", testCase("http://example.com/vnc/a%3Ab%3Ac%3Ad%3Aa%3Ab%3Ad%3Ad", 401, "", "localhost", 5900, true, true, mustParseCIDRList("a:b:c:d:a:b:c:d/120"), true))
	t.Run("CIDRBlacklistBlockIPv6", testCase("http://example.com/vnc/a%3Ab%3Ac%3Ad%3Aa%3Ab%3Ac%3Ad", 401, "", "localhost", 5900, true, true, mustParseCIDRList("a:b:c:d:a:b:c:d/120"), false))
	t.Run("CIDRBlacklistAllowIPv6", testCase("http://example.com/vnc/a%3Ab%3Ac%3Ad%3Aa%3Ab%3Ad%3Ad/5900", 101, "[a:b:c:d:a:b:d:d]:5900", "localhost", 5900, true, true, mustParseCIDRList("a:b:c:d:a:b:c:d/120"), false))
}

func TestWebsockify(t *testing.T) {
	defer func() {
		if err := recover(); err != nil && !strings.Contains(fmt.Sprint(err), "not implemented") {
			panic(err)
		}
	}()
	websockify("google.com:80", []byte(nil)).ServeHTTP(nilResponseWriter{}, httptest.NewRequest("GET", "/", nil))
}

type nilResponseWriter struct{}

func (nilResponseWriter) Write(buf []byte) (int, error) {
	return len(buf), nil
}
func (nilResponseWriter) WriteHeader(int) {}
func (nilResponseWriter) Header() http.Header {
	return http.Header{}
}
func (nilResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("not implemented")
}

func TestLogf(t *testing.T) {
	for _, c := range []struct {
		Cond   bool
		Format string
		Args   []interface{}
	}{
		{false, "test\n", nil},
		{true, "test\n", nil},
		{true, "test %s\n", []interface{}{"test"}},
	} {
		logf(c.Cond, c.Format, c.Args...)
	}
}

func TestNoCache(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/go.mod", nil)
	w := httptest.NewRecorder()

	noCache(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})).ServeHTTP(w, r)

	if cc := w.Result().Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("wrong Cache-Control header: %#v", cc)
	}
}

func TestServerHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/go.mod", nil)
	w := httptest.NewRecorder()

	serverHeader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})).ServeHTTP(w, r)

	if cc := w.Result().Header.Get("Server"); cc != "easy-novnc" {
		t.Errorf("wrong Server header: %#v", cc)
	}
}

func TestBasicAuth(t *testing.T) {
	handler := basicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "admin", "secret")

	t.Run("NoCredentials", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Result().StatusCode)
		}
	})

	t.Run("WrongCredentials", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.SetBasicAuth("admin", "wrong")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Result().StatusCode)
		}
	})

	t.Run("CorrectCredentials", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.SetBasicAuth("admin", "secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Result().StatusCode)
		}
	})

	t.Run("HealthzBypassesAuth", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/healthz", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("expected 200 for /healthz without auth, got %d", w.Result().StatusCode)
		}
	})
}

func TestConnectionLimiting(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{} // fill the semaphore

	vnc := vncHandler("localhost", 5900, false, false, false, nil, false, sem)

	r := httptest.NewRequest("GET", "http://example.com/vnc", nil)
	w := httptest.NewRecorder()
	vnc.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when connections full, got %d", w.Result().StatusCode)
	}

	<-sem // free the slot
}

func TestNoVNCEmbed(t *testing.T) {
	sub, err := fs.Sub(novncFS, "novnc")
	if err != nil {
		t.Fatalf("could not get novnc sub-filesystem: %v", err)
	}

	// Check vnc.html exists and has content
	f, err := sub.Open("vnc.html")
	if err != nil {
		t.Fatalf("could not open vnc.html: %v", err)
	}
	defer f.Close()

	buf, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("could not read vnc.html: %v", err)
	}

	if len(buf) < 100 {
		t.Errorf("vnc.html is too small (%d bytes)", len(buf))
	}

	// Check that custom script was injected
	if !bytes.Contains(buf, []byte("not websocket")) {
		t.Errorf("vnc.html does not contain injected script")
	}

	// Walk all files to verify integrity
	count := 0
	err = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			count++
		}
		return nil
	})
	if err != nil {
		t.Errorf("could not walk embedded filesystem: %v", err)
	}
	if count < 10 {
		t.Errorf("expected at least 10 embedded files, got %d", count)
	}
	t.Logf("embedded %d noVNC files", count)
}

func TestCopyCh(t *testing.T) {
	testCase := func(r *testReader, shouldError bool) func(*testing.T) {
		return func(t *testing.T) {
			dst := new(bytes.Buffer)
			src := r
			ch := make(chan error)

			go copyCh(dst, src, ch)
			n := time.Now()

			select {
			case err := <-ch:
				if !shouldError && err != nil {
					t.Errorf("unexpected error: %v", err)
				} else if shouldError && err == nil {
					t.Errorf("expected error")
				}
				if time.Since(n) < r.MinTime() {
					t.Errorf("returned too fast")
				}
			case <-time.After(time.Second):
				t.Errorf("error channel not written to")
			}
		}
	}
	t.Run("NoError", testCase(&testReader{5, time.Millisecond * 50, 0, 0}, false))
	t.Run("Error", testCase(&testReader{5, time.Millisecond * 50, 2, 0}, true))
}

func TestCIDRBlackWhiteList(t *testing.T) {
	testCase := func(cidrList []*net.IPNet, isWhitelist bool, hosts []string, shouldFail bool) func(t *testing.T) {
		return func(t *testing.T) {
			for _, host := range hosts {
				err := checkCIDRBlackWhiteListHost(host, cidrList, isWhitelist)
				if err == nil && shouldFail {
					t.Errorf("expected %s to fail test for cidr list (isWhitelist=%t) %s", host, isWhitelist, cidrList)
				} else if err != nil && !shouldFail {
					t.Errorf("expected %s not to fail test for cidr list (isWhitelist=%t) %s", host, isWhitelist, cidrList)
				}
			}
		}
	}
	t.Run("WhitelistAllow", testCase(mustParseCIDRList("10.0.0.0/24,127.0.0.0/16"), true, []string{"10.0.0.1", "127.0.1.1"}, false))
	t.Run("WhitelistBlock", testCase(mustParseCIDRList("10.0.0.0/24,127.0.0.0/16"), true, []string{"11.0.0.1", "1.0.1.1"}, true))
	t.Run("BlacklistAllow", testCase(mustParseCIDRList("10.0.0.0/24,127.0.0.0/16"), false, []string{"11.0.0.1", "1.0.1.1"}, false))
	t.Run("BlacklistBlock", testCase(mustParseCIDRList("10.0.0.0/24,127.0.0.0/16"), false, []string{"10.0.0.1", "127.0.1.1"}, true))
	t.Run("WhitelistAllowv6", testCase(mustParseCIDRList("a:b:c:d:a:b:c:d/120"), true, []string{"a:b:c:d:a:b:c:d", "a:b:c:d:a:b:c:a"}, false))
	t.Run("WhitelistBlockv6", testCase(mustParseCIDRList("a:b:c:d:a:b:c:d/120"), true, []string{"a:b:c:d:a:b:d:d", "a:b:c:d:a:b:d:a"}, true))
	t.Run("BlacklistAllowv6", testCase(mustParseCIDRList("a:b:c:d:a:b:c:d/120"), false, []string{"a:b:c:d:a:b:d:d", "a:b:c:d:a:b:d:a"}, false))
	t.Run("BlacklistBlockv6", testCase(mustParseCIDRList("a:b:c:d:a:b:c:d/120"), false, []string{"a:b:c:d:a:b:c:d", "a:b:c:d:a:b:c:a"}, true))
}

func TestParseCIDRList(t *testing.T) {
	strs := []string{
		"127.0.0.0/16",
		"192.168.0.0/24",
		"a:b:c:d:a:b:c:0/120",
	}
	cidrs, err := parseCIDRList(strs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	for i, expected := range strs {
		if actual := cidrs[i].String(); expected != actual {
			t.Errorf("expected cidr %s at index %d, got %s", expected, i, actual)
		}
	}

	strs = []string{
		"127.0.0.0/16",
		"192.168.0.0.123.4/24",
		"a:b:c:d:a:b:c:d/120",
	}
	_, err = parseCIDRList(strs)
	if err == nil {
		t.Errorf("expected error: when parsing erroneous list")
	}
}

func TestMagicCheck(t *testing.T) {
	for _, tc := range []struct {
		Name string

		Magic []byte
		Input []byte

		EOFAt  int
		Failed bool
	}{
		{"Good_BothEmpty", []byte(""), []byte(""), 0, false},
		{"Good_EmptyMagicWithInput", []byte(""), []byte(" "), 1, false},
		{"Good_EmptyInputWithMagic", []byte("RFB"), []byte(""), 0, false},
		{"Good_ExactMatch", []byte("RFB"), []byte("RFB"), 3, false},
		{"Good_ExactMatchWithExtra", []byte("RFB"), []byte("RFB 005.000"), 11, false},
		{"Bad_NoMatch", []byte("RFB"), []byte("..."), 0, true},
		{"Bad_PartialMatch", []byte("RFB"), []byte("R.."), 1, true},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			m := newMagicCheck(bytes.NewReader(tc.Input), tc.Magic)
			var buf []byte

			rbuf := make([]byte, 1)
			for {
				n, err := m.Read(rbuf)
				if err == io.EOF {
					if n, err := m.Read(rbuf); err != io.EOF || n != 0 {
						t.Errorf("expected io.EOF to stick with no bytes read")
					}
					if tc.EOFAt < 0 {
						t.Errorf("unexpected eof after %d bytes", len(buf))
					} else if len(buf) != tc.EOFAt {
						t.Errorf("unexpected eof after %d bytes, expected %d bytes (buf: %s)", len(buf), tc.EOFAt, string(buf))
					} else if m.Failed() != tc.Failed {
						t.Errorf("expected failed=%t, got %t", tc.Failed, m.Failed())
					} else if !m.Failed() && len(tc.Input) >= len(tc.Magic) && !bytes.Equal(m.Magic(), tc.Magic) {
						t.Errorf("shouldn't have passed the magic check: %s != %s", string(m.Magic()), string(tc.Magic))
					}
					break
				} else if err != nil {
					panic(err)
				} else if n > 0 {
					buf = append(buf, rbuf[:n]...)
				}
			}
		})
	}
}

// testReader is a custom io.Reader which throttles the reads and can return
// an error at a specific point.
type testReader struct {
	N     int
	Delay time.Duration
	Errn  int
	v     int
}

func (t *testReader) Read(buf []byte) (int, error) {
	if t.v >= t.N {
		return 0, io.EOF
	}

	t.v++
	time.Sleep(t.Delay)

	if t.Errn == t.v {
		return 1, errors.New("test error")
	}

	buf[0] = 0xFF
	return 1, nil
}

func (t *testReader) MinTime() time.Duration {
	if t.Errn < t.N {
		return t.Delay * time.Duration(t.Errn)
	}
	return t.Delay * time.Duration(t.N)
}

func mustParseCIDRList(str string) []*net.IPNet {
	cidrs, err := parseCIDRList(strings.Split(str, ","))
	if err != nil {
		panic(err)
	}
	return cidrs
}
