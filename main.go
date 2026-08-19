package main

import (
	"fmt"
	"net/http"
	"os"

	"repass-backend/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Route all API requests to the handler
	http.HandleFunc("/api/", api.Handler)

	// Health check for the root domain
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "ok", "message": "Repass Backend is running!"}`))
			return
		}
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})

	fmt.Printf("Server listening on port %s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
	}
}
