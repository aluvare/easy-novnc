package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/net/websocket"
)

//go:generate go run novnc_generate.go

//go:embed novnc
var novncFS embed.FS

//go:embed index.html
var indexHTML string

var indexTMPL = template.Must(template.New("index").Parse(indexHTML))

func main() {
	pflag.Usage = func() {
		fmt.Printf("Usage: %s [options]\n\nOptions:\n", os.Args[0])
		pflag.PrintDefaults()
	}

	arbitraryHosts := pflag.BoolP("arbitrary-hosts", "H", false, "Allow connection to other hosts")
	arbitraryPorts := pflag.BoolP("arbitrary-ports", "P", false, "Allow connections to arbitrary ports (requires arbitrary-hosts)")
	cidrWhitelist := pflag.StringSliceP("cidr-whitelist", "c", []string{}, "CIDR whitelist for when arbitrary hosts are enabled (comma separated) (conflicts with blacklist)")
	cidrBlacklist := pflag.StringSliceP("cidr-blacklist", "C", []string{}, "CIDR blacklist for when arbitrary hosts are enabled (comma separated) (conflicts with whitelist)")
	host := pflag.StringP("host", "h", "localhost", "The host/ip to connect to by default")
	port := pflag.Uint16P("port", "p", 5900, "The port to connect to by default")
	addr := pflag.StringP("addr", "a", ":8080", "The address to listen on")
	basicUI := pflag.BoolP("basic-ui", "u", false, "Hide connection options from the main screen")
	verbose := pflag.BoolP("verbose", "v", false, "Show extra log info")
	noURLPassword := pflag.Bool("no-url-password", false, "Do not allow password in URL params")
	novncParams := pflag.StringSlice("novnc-params", nil, "Extra URL params for noVNC (advanced) (comma separated key-value pairs) (e.g. resize=remote)")
	defaultViewOnly := pflag.Bool("default-view-only", false, "Use view-only by default")
	tlsCert := pflag.String("tls-cert", "", "Path to TLS certificate file")
	tlsKey := pflag.String("tls-key", "", "Path to TLS key file")
	authUser := pflag.String("basic-auth-user", "", "Username for HTTP basic auth")
	authPass := pflag.String("basic-auth-password", "", "Password for HTTP basic auth")
	maxConns := pflag.Int("max-connections", 0, "Maximum concurrent VNC connections (0 = unlimited)")
	help := pflag.Bool("help", false, "Show this help text")

	envmap := map[string]string{
		"arbitrary-hosts":     "NOVNC_ARBITRARY_HOSTS",
		"arbitrary-ports":     "NOVNC_ARBITRARY_PORTS",
		"cidr-whitelist":      "NOVNC_CIDR_WHITELIST",
		"cidr-blacklist":      "NOVNC_CIDR_BLACKLIST",
		"host":                "NOVNC_HOST",
		"port":                "NOVNC_PORT",
		"addr":                "NOVNC_ADDR",
		"basic-ui":            "NOVNC_BASIC_UI",
		"no-url-password":     "NOVNC_NO_URL_PASSWORD",
		"novnc-params":        "NOVNC_PARAMS",
		"default-view-only":   "NOVNC_DEFAULT_VIEW_ONLY",
		"verbose":             "NOVNC_VERBOSE",
		"tls-cert":            "NOVNC_TLS_CERT",
		"tls-key":             "NOVNC_TLS_KEY",
		"basic-auth-user":     "NOVNC_BASIC_AUTH_USER",
		"basic-auth-password": "NOVNC_BASIC_AUTH_PASSWORD",
		"max-connections":     "NOVNC_MAX_CONNECTIONS",
	}

	if val, ok := os.LookupEnv("PORT"); ok {
		val = ":" + val
		fmt.Printf("Setting --addr from PORT to %#v\n", val)
		if err := pflag.Set("addr", val); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(2)
		}
	}

	pflag.VisitAll(func(flag *pflag.Flag) {
		if env, ok := envmap[flag.Name]; ok {
			flag.Usage += fmt.Sprintf(" (env %s)", env)
			if val, ok := os.LookupEnv(env); ok {
				fmt.Printf("Setting --%s from %s to %#v\n", flag.Name, env, val)
				if err := flag.Value.Set(val); err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(2)
				}
			}
		}
	})

	pflag.Parse()

	if *help {
		pflag.Usage()
		os.Exit(1)
	}

	if *arbitraryPorts && !*arbitraryHosts {
		fmt.Printf("Error: arbitrary-ports requires arbitrary-hosts to be enabled.\n")
		os.Exit(2)
	}

	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Printf("Error: both --tls-cert and --tls-key must be specified.\n")
		os.Exit(2)
	}

	if (*authUser == "") != (*authPass == "") {
		fmt.Printf("Error: both --basic-auth-user and --basic-auth-password must be specified.\n")
		os.Exit(2)
	}

	cidrList, isWhitelist, err := parseCIDRBlackWhiteList(*cidrBlacklist, *cidrWhitelist)
	if err != nil {
		fmt.Printf("Error: error parsing cidr blacklist/whitelist: %v.\n", err)
		os.Exit(2)
	}

	if len(cidrList) != 0 {
		if err := checkCIDRBlackWhiteListHost(*host, cidrList, isWhitelist); err != nil {
			fmt.Printf("Warning: default host does not parse cidr blacklist/whitelist: %v.\n", err)
		}
	}

	novncParamsMap := map[string]string{
		"resize": "scale",
	}
	for _, p := range *novncParams {
		spl := strings.SplitN(p, "=", 2)
		if len(spl) != 2 {
			fmt.Printf("Error: error parsing noVNC params: must be in key=value format.\n")
			os.Exit(2)
		}

		switch spl[0] {
		case "resize", "logging", "repeaterID", "reconnect_delay", "view_clip", "quality", "compression", "shared":
			novncParamsMap[spl[0]] = spl[1]
		case "encrypt", "reconnect", "path", "password", "view_only", "show_dot", "bell", "autoconnect":
			fmt.Printf("Error: error parsing noVNC params: option %#v reserved for use by easy-novnc.\n", spl[0])
			os.Exit(2)
		default:
			fmt.Printf("Error: error parsing noVNC params: unknown option %#v.\n", spl[0])
			os.Exit(2)
		}
	}

	// Connection limiter
	var connSem chan struct{}
	if *maxConns > 0 {
		connSem = make(chan struct{}, *maxConns)
	}

	// Setup routes
	mux := http.NewServeMux()

	vnc := vncHandler(*host, *port, *verbose, *arbitraryHosts, *arbitraryPorts, cidrList, isWhitelist, connSem)
	mux.Handle("/vnc", vnc)
	mux.Handle("/vnc/{host}", vnc)
	mux.Handle("/vnc/{host}/{port}", vnc)

	// Health check endpoint (bypasses auth)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// Index page
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		indexTMPL.Execute(w, map[string]interface{}{
			"arbitraryHosts":  *arbitraryHosts,
			"arbitraryPorts":  *arbitraryPorts,
			"host":            *host,
			"port":            *port,
			"addr":            *addr,
			"basicUI":         *basicUI,
			"noURLPassword":   *noURLPassword,
			"defaultViewOnly": *defaultViewOnly,
			"params":          novncParamsMap,
		})
	})

	// Serve noVNC static files
	novncSub, err := fs.Sub(novncFS, "novnc")
	if err != nil {
		fmt.Printf("Error: failed to access embedded noVNC files: %v\n", err)
		os.Exit(1)
	}
	mux.Handle("/", http.FileServer(http.FS(novncSub)))

	// Apply middleware
	var handler http.Handler = mux
	handler = noCache(handler)
	handler = serverHeader(handler)
	if *authUser != "" {
		handler = basicAuth(handler, *authUser, *authPass)
	}

	// Create server
	srv := &http.Server{
		Addr:    *addr,
		Handler: handler,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		logf(true, "Received %s, shutting down...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	fmt.Printf("Listening on http://%s\n", *addr)
	if !*arbitraryHosts && !*arbitraryPorts && *host == "localhost" && *port == 5900 && !*basicUI {
		fmt.Printf("Run with --help for more options\n")
	}

	if *tlsCert != "" {
		fmt.Printf("TLS enabled\n")
		err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logf(true, "Error: %v.\n", err)
		os.Exit(1)
	}
}

// vncHandler creates a handler for vnc connections. If host and port are set in
// the URL path, they will be used if allowed.
func vncHandler(defhost string, defport uint16, verbose, allowHosts, allowPorts bool, cidrList []*net.IPNet, isWhitelist bool, connSem chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var host, port string

		if host = r.PathValue("host"); host == "" {
			host = defhost
		} else if !allowHosts {
			logf(verbose, "connect %s disabled\n", host)
			http.Error(w, "--arbitrary-hosts disabled", http.StatusUnauthorized)
			return
		}

		if port = r.PathValue("port"); port == "" {
			port = fmt.Sprint(defport)
		} else if !allowPorts {
			logf(verbose, "connect %s:%s disabled\n", host, port)
			http.Error(w, "--arbitrary-ports disabled", http.StatusUnauthorized)
			return
		}

		if len(cidrList) != 0 {
			if err := checkCIDRBlackWhiteListHost(host, cidrList, isWhitelist); err != nil {
				logf(verbose, "connect %s:%s not allowed: %v\n", host, port, err)
				http.Error(w, fmt.Sprintf("connect %s:%s not allowed: %v\n", host, port, err), http.StatusUnauthorized)
				return
			}
		}

		addr := host + ":" + port
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			addr = "[" + host + "]:" + port
		}

		// Connection limiting
		if connSem != nil {
			select {
			case connSem <- struct{}{}:
				defer func() { <-connSem }()
			default:
				http.Error(w, "too many connections", http.StatusServiceUnavailable)
				return
			}
		}

		logf(verbose, "connect %s\n", addr)
		w.Header().Set("X-Target-Addr", addr)
		websockify(addr, []byte("RFB")).ServeHTTP(w, r)
	})
}

// logf calls fmt.Printf with the date if the condition is true.
func logf(cond bool, format string, a ...interface{}) {
	if cond {
		fmt.Printf("%s: %s", time.Now().Format("Jan 02 15:04:05"), fmt.Sprintf(format, a...))
	}
}

// noCache disables caching on a http.Handler.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// serverHeader sets the Server header for a http.Handler.
func serverHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "easy-novnc")
		next.ServeHTTP(w, r)
	})
}

// basicAuth adds HTTP Basic Authentication to a http.Handler.
func basicAuth(next http.Handler, user, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="easy-novnc"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// websockify returns an http.Handler which proxies websocket requests to a tcp
// address and checks magic bytes.
func websockify(to string, magic []byte) http.Handler {
	return websocket.Server{
		Handshake: wsProxyHandshake,
		Handler:   wsProxyHandler(to, magic),
	}
}

// wsProxyHandshake is a handshake handler for a websocket.Server.
func wsProxyHandshake(config *websocket.Config, r *http.Request) error {
	if r.Header.Get("Sec-WebSocket-Protocol") != "" {
		config.Protocol = []string{"binary"}
	}
	r.Header.Set("Access-Control-Allow-Origin", "*")
	r.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
	return nil
}

// wsProxyHandler is a websocket.Handler which proxies to a tcp address with a
// magic byte check.
func wsProxyHandler(to string, magic []byte) websocket.Handler {
	return func(ws *websocket.Conn) {
		conn, err := net.Dial("tcp", to)
		if err != nil {
			ws.Close()
			return
		}

		ws.PayloadType = websocket.BinaryFrame

		m := newMagicCheck(conn, magic)

		done := make(chan error)
		go copyCh(conn, ws, done)
		go copyCh(ws, m, done)

		err = <-done
		if m.Failed() {
			logf(true, "attempt to connect to non-VNC port (%s, %#v)\n", to, string(m.Magic()))
		} else if err != nil {
			logf(true, "%v\n", err)
		}

		conn.Close()
		ws.Close()
		<-done
	}
}

// copyCh is like io.Copy, but it writes to a channel when finished.
func copyCh(dst io.Writer, src io.Reader, done chan error) {
	_, err := io.Copy(dst, src)
	done <- err
}

// checkCIDRBlackWhiteListHost checks the provided host/ip against a blacklist/whitelist.
func checkCIDRBlackWhiteListHost(host string, cidrList []*net.IPNet, isWhitelist bool) error {
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if err := checkCIDRBlackWhiteList(ip, cidrList, isWhitelist); err != nil {
			return err
		}
	}
	return nil
}

// checkCIDRBlackWhiteList checks an IP against a blacklist/whitelist.
func checkCIDRBlackWhiteList(ip net.IP, cidrList []*net.IPNet, isWhitelist bool) error {
	var matchedCIDR *net.IPNet
	for _, cidr := range cidrList {
		if cidr.Contains(ip) {
			matchedCIDR = cidr
			break
		}
	}
	if matchedCIDR == nil && isWhitelist {
		return fmt.Errorf("ip %s does not match any whitelisted cidr", ip)
	} else if matchedCIDR != nil && !isWhitelist {
		return fmt.Errorf("ip %s matches blacklisted cidr %s", ip, matchedCIDR)
	}
	return nil
}

// parseCIDRBlackWhiteList returns either a parsed blacklist or whitelist of
// CIDRs. If neither is specified, isWhitelist is false and the slice is empty.
func parseCIDRBlackWhiteList(blacklist []string, whitelist []string) (cidrs []*net.IPNet, isWhitelist bool, err error) {
	if len(blacklist) != 0 && len(whitelist) != 0 {
		err = errors.New("only one of blacklist/whitelist can be specified")
		return
	}
	if len(whitelist) != 0 {
		isWhitelist = true
		cidrs, err = parseCIDRList(whitelist)
	} else {
		cidrs, err = parseCIDRList(blacklist)
	}
	return
}

// parseCIDRList parses a list of CIDRs.
func parseCIDRList(cidrs []string) ([]*net.IPNet, error) {
	res := make([]*net.IPNet, len(cidrs))
	for i, str := range cidrs {
		_, cidr, err := net.ParseCIDR(str)
		if err != nil {
			return nil, fmt.Errorf("error parsing CIDR '%s': %v", str, err)
		}
		res[i] = cidr
	}
	return res, nil
}

// magicCheck implements an efficient wrapper around an io.Reader which checks
// for magic bytes at the beginning, and will return a sticky io.EOF and stop
// reading from the original reader as soon as a mismatch starts.
type magicCheck struct {
	rdr io.Reader
	exp []byte
	len int
	rem int
	act []byte
	fld bool
}

func newMagicCheck(r io.Reader, magic []byte) *magicCheck {
	return &magicCheck{r, magic, len(magic), len(magic), make([]byte, len(magic)), false}
}

// Failed returns true if the magic check has failed (note that it returns false
// if the source io.Reader reached io.EOF before the check was complete).
func (m *magicCheck) Failed() bool {
	return m.fld
}

// Magic returns the magic which was read so far.
func (m *magicCheck) Magic() []byte {
	return m.act
}

func (m *magicCheck) Read(buf []byte) (n int, err error) {
	if m.fld {
		return 0, io.EOF
	}
	n, err = m.rdr.Read(buf)
	if err == nil && n > 0 && m.rem > 0 {
		m.rem -= copy(m.act[m.len-m.rem:], buf[:n])
		for i := 0; i < m.len-m.rem; i++ {
			if m.act[i] != m.exp[i] {
				m.fld = true
				return 0, io.EOF
			}
		}
	}
	return n, err
}
