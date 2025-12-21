package main

import (
	"net/http"
)

func main() {
	http.ListenAndServe(":7860", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello World \n"))
		},
	))
}

