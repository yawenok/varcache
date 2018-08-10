package router

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	CONNECT = "CONNECT"
	DELETE  = "DELETE"
	GET     = "GET"
	HEAD    = "HEAD"
	OPTIONS = "OPTIONS"
	PATCH   = "PATCH"
	POST    = "POST"
	PUT     = "PUT"
	TRACE   = "TRACE"
	ANY     = "*"
)

type HandlerFunc func(http.ResponseWriter, *http.Request, interface{})

type IHandlerInterceptor interface {
	PreHandleFunc(http.ResponseWriter, *http.Request) bool

	PostHandleFunc(http.ResponseWriter, *http.Request)
}

type IServeFileInterceptor interface {
	PreServeFileFunc(http.ResponseWriter, *http.Request) bool

	PostServeFileFunc(http.ResponseWriter, *http.Request, *FileData)
}

type FileData struct {
	Data []byte
	Type string
}

type Pattern struct {
	regex  *regexp.Regexp
	params map[int]string
}

type Router struct {
	pattern *Pattern
	method  string
	handler HandlerFunc
	bind    interface{}
}

type Interceptor struct {
	pattern             *Pattern
	iHandlerInterceptor IHandlerInterceptor
}

type Server struct {
	addr         string
	listener     net.Listener
	config       *tls.Config
	logger       *log.Logger
	routers      []*Router
	interceptors []*Interceptor
}

func NewServer() *Server {
	return &Server{
		addr:   ":8888",
		logger: log.New(os.Stdout, "", log.Ldate|log.Ltime),
	}
}

func (s *Server) Run() {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Fatal("Listen: ", err)
		return
	}

	s.listener = listener
	log.Println("Listening on http://" + s.addr)

	err = http.Serve(s.listener, s)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func (s *Server) RunTLS() {
	if s.config == nil {
		log.Fatal("Tls config is nil!")
		return
	}

	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Fatal("Listen: ", err)
		return
	}

	s.listener = tls.NewListener(listener, s.config)
	log.Println("Listening on https://" + s.addr)

	err = http.Serve(s.listener, s)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}

func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
	}
}

func (s *Server) SetAddress(args ...interface{}) {
	addr := s.parseAddress(args...)
	if addr == "" {
		log.Fatal("Address error:" + addr)
		return
	}

	s.addr = addr
}

func (s *Server) SetTLS(certFile, keyFile string) {
	config, err := s.parseTLSCertificates(certFile, keyFile)
	if err != nil {
		log.Fatal("Load certificate:", err)
		return
	}

	s.config = config
}

func (s *Server) SetLogger(logger *log.Logger) {
	s.logger = logger
}

func (s *Server) Version() string {
	return "0.0.1"
}

func (s *Server) Connect(route string, handlerFunc HandlerFunc, bind interface{}) {
	s.AddRoute(CONNECT, route, handlerFunc, bind)
}

func (s *Server) Delete(route string, handlerFunc HandlerFunc, bind interface{}) {
	s.AddRoute(DELETE, route, handlerFunc, bind)
}

func (s *Server) Get(route string, handlerFunc HandlerFunc, bind interface{}) {
	s.AddRoute(GET, route, handlerFunc, bind)
}

func (s *Server) Head(route string, handlerFunc HandlerFunc, bind interface{}) {
	s.AddRoute(HEAD, route, handlerFunc, bind)
}

func (s *Server) Options(route string, handlerFunc HandlerFunc, bind interface{}) {
	s.AddRoute(OPTIONS, route, handlerFunc, bind)
}

func (s *Server) Patch(route string, handlerFunc HandlerFunc, bind interface{}) {
	s.AddRoute(PATCH, route, handlerFunc, bind)
}

func (s *Server) Post(route string, handlerFunc HandlerFunc, bind interface{}) {
	s.AddRoute(POST, route, handlerFunc, bind)
}

func (s *Server) Put(route string, handlerFunc HandlerFunc, bind interface{}) {
	s.AddRoute(PUT, route, handlerFunc, bind)
}

func (s *Server) Any(route string, handlerFunc HandlerFunc, bind interface{}) {
	s.AddRoute(ANY, route, handlerFunc, bind)
}

func (s *Server) Static(route, root, index string, iServeFileInterceptor IServeFileInterceptor) {
	bind := make(map[string]interface{})

	bind["root"] = root
	bind["index"] = index
	bind["iServeFileInterceptor"] = iServeFileInterceptor

	s.AddRoute(GET, route+"(.*)", s.serveFile, bind)
}

func (s *Server) AddRoute(method, route string, handlerFunc HandlerFunc, bind interface{}) {
	// parse pattern
	pattern, err := s.parsePattern(route)
	if err != nil {
		return
	}

	// add router
	router := &Router{}
	router.pattern = pattern
	router.method = method
	router.handler = handlerFunc
	router.bind = bind

	s.routers = append(s.routers, router)
}

func (s *Server) AddFilter(route string, iHandlerInterceptor IHandlerInterceptor) {
	// parse pattern
	pattern, err := s.parsePattern(route)
	if err != nil {
		return
	}

	interceptor := &Interceptor{}
	interceptor.pattern = pattern
	interceptor.iHandlerInterceptor = iHandlerInterceptor

	s.interceptors = append(s.interceptors, interceptor)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Varcache")
	w.Header().Set("Date", s.formatTime(time.Now().UTC()))

	isServe := true
	isFound := false

	// parse match interceptor
	matchInterceptors := make([]*Interceptor, 0)
	for _, interceptor := range s.interceptors {
		if s.matchPattern(r, interceptor.pattern) {
			matchInterceptors = append(matchInterceptors, interceptor)
		}
	}

	// prehandle the request
	for _, interceptor := range matchInterceptors {
		if interceptor.iHandlerInterceptor != nil {
			if !interceptor.iHandlerInterceptor.PreHandleFunc(w, r) {
				isServe = false
				continue
			}
		}
	}

	// not serve the request
	if !isServe {
		http.Error(w, "Can't serve!", 403)
		return
	}

	// serve the request
	for _, router := range s.routers {
		// match the route
		if s.matchPattern(r, router.pattern) {
			if router.method == ANY || router.method == r.Method {
				// handle the request
				handler := router.handler
				if handler != nil {
					handler(w, r, router.bind)
				}
				isFound = true
			}
		}
	}

	// not found
	if !isFound {
		http.NotFound(w, r)
		return
	}

	// posthandle the the request
	for _, interceptor := range matchInterceptors {
		if interceptor.iHandlerInterceptor != nil {
			interceptor.iHandlerInterceptor.PostHandleFunc(w, r)
		}
	}
}

func (s *Server) parsePattern(route string) (*Pattern, error) {
	// split the url into sections
	parts := strings.Split(route, "/")

	// find params that start with ":"
	// replace with regular expressions
	j := 0
	params := make(map[int]string)
	for i, part := range parts {
		if strings.HasPrefix(part, ":") {
			expr := "([^/]+)"
			// a user may choose to override the defult expression
			// similar to expressjs: ‘/user/:id([0-9]+)’
			if n := strings.Index(part, "("); n != -1 {
				expr = part[n:]
				part = part[:n]
			}
			params[j] = part
			parts[i] = expr
			j++
		}
	}

	// re create the url route, with parameters replaced
	route = strings.Join(parts, "/")

	// check the pattern
	regex, err := regexp.Compile(route)
	if err != nil {
		panic(err)
		return nil, err
	}

	return &Pattern{regex: regex, params: params}, nil
}

func (s *Server) matchPattern(r *http.Request, p *Pattern) bool {
	regex := p.regex
	params := p.params

	requestPath := r.URL.Path
	queryValues := r.URL.Query()

	if !regex.MatchString(requestPath) {
		return false
	}

	// get submatches (params)
	matches := regex.FindStringSubmatch(requestPath)

	// double check that the Route matches the URL pattern
	if len(matches[0]) != len(requestPath) {
		return false
	}

	for i, param := range params {
		queryValues.Set(param, matches[1+i])
	}

	return true
}

func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, bind interface{}) {
	// check the bind type
	bindData, ok := bind.(map[string]interface{})
	if !ok {
		return
	}

	root := bindData["root"]
	rootData, ok := root.(string)
	if !ok {
		return
	}

	index := bindData["index"]
	indexData, ok := index.(string)
	if !ok {
		return
	}

	iServeFileInterceptor := bindData["iServeFileInterceptor"]
	iServeFileInterceptorData, ok := iServeFileInterceptor.(IServeFileInterceptor)

	// pre serve file
	if ok && iServeFileInterceptorData != nil {
		if !iServeFileInterceptorData.PreServeFileFunc(w, r) {
			return
		}
	}

	// deal the file path
	filePath := s.joinPath(rootData, r.RequestURI)
	if s.isDirExists(filePath) {
		filePath = s.joinPath(filePath, indexData)
	}

	// check the file
	if s.isFileExists(filePath) {
		// serve the file
		fileData, err := s.getFileData(filePath)
		if err != nil {
			panic(err)
		}

		if fileData != nil {
			w.Header().Set("content-Type", fileData.Type)
			w.Header().Set("Content-Length", strconv.Itoa(len(fileData.Data)))
			w.Write(fileData.Data)

			// post serve file
			if ok && iServeFileInterceptorData != nil {
				iServeFileInterceptorData.PostServeFileFunc(w, r, fileData)
			}

			return
		}
	}

	http.NotFound(w, r)
}

func (s *Server) parseAddress(args ...interface{}) string {
	host := "0.0.0.0"
	port := "8888"

	if len(args) == 1 {
		switch arg := args[0].(type) {
		case string:
			addrs := strings.Split(args[0].(string), ":")
			if len(addrs) == 1 {
				host = addrs[0]
			} else if len(addrs) >= 2 {
				port = addrs[1]
			}
		case int:
			port = strconv.Itoa(arg)
		}
	} else if len(args) >= 2 {
		if arg, ok := args[0].(string); ok {
			host = arg
		}
		if arg, ok := args[1].(int); ok {
			port = strconv.Itoa(arg)
		}
	}

	return host + ":" + port
}

func (s *Server) parseTLSCertificates(certFile, keyFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{}

	config.NextProtos = []string{"http/1.1"}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = certificate

	return config, nil
}

func (s *Server) formatTime(t time.Time) string {
	webTime := t.Format(time.RFC1123)
	if strings.HasSuffix(webTime, "UTC") {
		webTime = webTime[0:len(webTime)-3] + "GMT"
	}

	return webTime
}

func (s *Server) joinPath(elem ...string) string {
	return filepath.Join(elem...)
}

func (s *Server) isDirExists(dirPath string) bool {
	info, err := os.Stat(dirPath)
	if err != nil {
		return false
	}

	return info.IsDir()
}

func (s *Server) isFileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	return !info.IsDir()
}

func (s *Server) getFileData(filePath string) (*FileData, error) {
	// serve the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	defer file.Close()
	fileData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	fileExt := path.Ext(filePath)
	fileType := mime.TypeByExtension(fileExt)

	return &FileData{Data: fileData, Type: fileType}, nil
}
