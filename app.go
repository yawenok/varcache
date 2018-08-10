package main

import (
	"net/http"
	"time"
	"./server"
)

type Ihi struct {
}

func (i *Ihi) PreHandleFunc(w http.ResponseWriter, r *http.Request) bool {
	return true
}

func (i *Ihi) PostHandleFunc(w http.ResponseWriter, r *http.Request) {
	str := "\r\nHello world post handle!\r\n" + time.Now().UTC().Format(time.RFC1123)
	w.Write([]byte(str))
}

func HelloServe(w http.ResponseWriter, r *http.Request, bind interface{}) {
	str := "Hello world!\r\n" + time.Now().UTC().Format(time.RFC1123)
	w.Write([]byte(str))
}

func main() {
	server := router.NewServer()

	server.Any("/(.*)", HelloServe, nil)
	server.AddFilter("/hello(.*)", &Ihi{})
	server.SetAddress(":8088")
	server.Run()
}
