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

	fmt.Printf("Server listening on port %s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
	}
}
