package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	var socketPath string

	if len(os.Args) < 2 {
		socketPath = ""
	} else {
		socketPath = os.Args[1]
	}

	if socketPath == "" {
		socketPath = filepath.Join(os.TempDir(), "apple-ssl.sock")
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalln("error listening:", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<h1>Your SSN and CC are safe here<h1><input type="text"><br><input type="submit">`)
	})

	server := http.Server{}
	if err := server.Serve(ln); err != nil {
		log.Fatalln("error serving", err)
	}
}
