package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"fmt"
	"bytes"
	"os"
	"sync"
	"embed"
	"github.com/golang-jwt/jwt/v5"
)

//go:embed data/users.json data/passwords.json
var content embed.FS

var jwtSecret = []byte("super-secret-jwt-key-replace-in-prod")

type User struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

type PasswordEntry struct {
	Id       string `json:"id"`
	UserId   string `json:"userId"`
	Title    string `json:"title"`
	Username string `json:"username"`
	Password string `json:"password"`
	Category string `json:"category"`
	Notes    string `json:"notes"`
	CreatedAt int64 `json:"createdAt"`
}

var (
	users     = make([]User, 0)
	passwords = make([]PasswordEntry, 0)
	storeMu   sync.Mutex
	loaded    bool
)

func loadFromKV(key string, target interface{}) bool {
	url := os.Getenv("KV_REST_API_URL")
	token := os.Getenv("KV_REST_API_TOKEN")
	if url == "" || token == "" {
		return false
	}
	req, _ := http.NewRequest("GET", url+"/get/"+key, nil)
	req.Header.Add("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	defer resp.Body.Close()
	var res struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil || res.Result == "" || res.Result == "null" {
		return false
	}
	if err := json.Unmarshal([]byte(res.Result), target); err != nil {
		return false
	}
	return true
}

func saveToKV(key string, data interface{}) {
	url := os.Getenv("KV_REST_API_URL")
	token := os.Getenv("KV_REST_API_TOKEN")
	if url == "" || token == "" {
		return
	}
	b, _ := json.Marshal(data)
	payload, _ := json.Marshal([]string{"SET", key, string(b)})
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, _ := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
}

func initStore() {
	if loaded {
		return
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if loaded {
		return
	}
	
	if !loadFromKV("users", &users) {
		uData, err := content.ReadFile("data/users.json")
		if err == nil {
			json.Unmarshal(uData, &users)
		}
	}
	
	if !loadFromKV("passwords", &passwords) {
		pData, err := content.ReadFile("data/passwords.json")
		if err == nil {
			json.Unmarshal(pData, &passwords)
		}
	}
	
	loaded = true
}

type Claims struct {
	Id       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func getClaims(r *http.Request) *Claims {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		return nil
	}
	
	token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	
	if err != nil {
		return nil
	}
	
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims
	}
	return nil
}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	initStore()
	path := r.URL.Path
	if route := r.URL.Query().Get("route"); route != "" {
		path = "/api/" + route
	}

	w.Header().Set("Content-Type", "application/json")

	if strings.HasPrefix(path, "/api/auth/login") && r.Method == "POST" {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Type     string `json:"type"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		var foundUser *User
		for _, u := range users {
			if strings.EqualFold(u.Username, req.Username) {
				foundUser = &u
				break
			}
		}

		if foundUser == nil || foundUser.Password != req.Password {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid username or password"})
			return
		}

		if foundUser.Status == "Inactive" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Your account has been deactivated."})
			return
		}

		role := foundUser.Role
		if role == "" {
			role = "User"
		}

		if req.Type == "Admin" && role != "Admin" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Access denied: Admin only"})
			return
		}
		if req.Type == "User" && role == "Admin" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Admins must use the Admin login page"})
			return
		}

		expirationTime := time.Now().Add(5 * 24 * time.Hour)
		claims := &Claims{
			Id:       foundUser.Id,
			Username: foundUser.Username,
			Role:     role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(jwtSecret)

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    tokenString,
			Expires:  expirationTime,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		})

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"user": map[string]interface{}{
				"id": foundUser.Id, "name": foundUser.Name, "username": foundUser.Username, "role": role,
			},
		})
		return
	}

	if strings.HasPrefix(path, "/api/auth/logout") && r.Method == "POST" {
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    "",
			Expires:  time.Unix(0, 0),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		})
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}

	claims := getClaims(r)
	if claims == nil {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Unauthorized"})
		return
	}

	if strings.HasPrefix(path, "/api/auth/me") && r.Method == "GET" {
		var foundUser *User
		for _, u := range users {
			if u.Id == claims.Id {
				foundUser = &u
				break
			}
		}
		if foundUser == nil {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": foundUser.Id, "name": foundUser.Name, "username": foundUser.Username, "role": claims.Role,
		})
		return
	}

	if strings.HasPrefix(path, "/api/passwords") {
		storeMu.Lock()
		defer storeMu.Unlock()

		if r.Method == "GET" {
			filtered := make([]PasswordEntry, 0)
			if claims.Role == "Admin" {
				for _, p := range passwords {
					if p.Category == "Organization" || (p.UserId == claims.Id && p.Category == "Personal") {
						filtered = append(filtered, p)
					}
				}
			} else {
				for _, p := range passwords {
					if p.UserId == claims.Id {
						filtered = append(filtered, p)
					}
				}
			}
			json.NewEncoder(w).Encode(filtered)
			return
		}

		if r.Method == "POST" {
			var req PasswordEntry
			json.NewDecoder(r.Body).Decode(&req)
			req.Id = fmt.Sprintf("%d", time.Now().UnixNano()) // dummy id
			req.UserId = claims.Id
			req.CreatedAt = time.Now().UnixMilli()
			passwords = append(passwords, req)
			saveToKV("passwords", passwords)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(req)
			return
		}

		if r.Method == "PUT" {
			parts := strings.Split(path, "/")
			if len(parts) >= 4 {
				id := parts[3]
				var req PasswordEntry
				json.NewDecoder(r.Body).Decode(&req)
				
				for i, p := range passwords {
					if p.Id == id {
						if p.UserId != claims.Id && (claims.Role != "Admin" || p.Category != "Organization") {
							w.WriteHeader(403)
							return
						}
						
						passwords[i].Title = req.Title
						passwords[i].Username = req.Username
						passwords[i].Password = req.Password
						passwords[i].Notes = req.Notes
						passwords[i].Category = req.Category
						
						saveToKV("passwords", passwords)
						json.NewEncoder(w).Encode(passwords[i])
						return
					}
				}
				w.WriteHeader(404)
				return
			}
		}

		if r.Method == "DELETE" {
			parts := strings.Split(path, "/")
			if len(parts) >= 4 {
				id := parts[3]
				for i, p := range passwords {
					if p.Id == id {
						if p.UserId != claims.Id && (claims.Role != "Admin" || p.Category != "Organization") {
							w.WriteHeader(403)
							return
						}
						
						passwords = append(passwords[:i], passwords[i+1:]...)
						saveToKV("passwords", passwords)
						json.NewEncoder(w).Encode(map[string]bool{"success": true})
						return
					}
				}
				w.WriteHeader(404)
				return
			}
		}
	}

	if strings.HasPrefix(path, "/api/users") {
		storeMu.Lock()
		defer storeMu.Unlock()

		if claims.Role != "Admin" {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"error": "Admin access required"})
			return
		}

		parts := strings.Split(path, "/")
		
		if r.Method == "GET" && len(parts) == 3 {
			json.NewEncoder(w).Encode(users)
			return
		}

		if r.Method == "POST" && len(parts) == 3 {
			var req User
			json.NewDecoder(r.Body).Decode(&req)
			req.Id = fmt.Sprintf("%d", time.Now().UnixNano())
			req.Status = "Active"
			users = append(users, req)
			saveToKV("users", users)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(req)
			return
		}

		if r.Method == "PUT" && len(parts) == 4 {
			id := parts[3]
			var req User
			json.NewDecoder(r.Body).Decode(&req)
			
			for i, u := range users {
				if u.Id == id {
					if req.Name != "" { users[i].Name = req.Name }
					if req.Username != "" { users[i].Username = req.Username }
					if req.Role != "" { users[i].Role = req.Role }
					if req.Status != "" { users[i].Status = req.Status }
					saveToKV("users", users)
					json.NewEncoder(w).Encode(users[i])
					return
				}
			}
			w.WriteHeader(404)
			return
		}

		if r.Method == "POST" && len(parts) == 5 && parts[4] == "reset-password" {
			id := parts[3]
			var req struct { NewPassword string `json:"newPassword"` }
			json.NewDecoder(r.Body).Decode(&req)
			
			for i, u := range users {
				if u.Id == id {
					users[i].Password = req.NewPassword
					saveToKV("users", users)
					json.NewEncoder(w).Encode(map[string]bool{"success": true})
					return
				}
			}
			w.WriteHeader(404)
			return
		}

		if r.Method == "DELETE" && len(parts) == 4 {
			id := parts[3]
			for i, u := range users {
				if u.Id == id {
					users = append(users[:i], users[i+1:]...)
					saveToKV("users", users)
					json.NewEncoder(w).Encode(map[string]bool{"success": true})
					return
				}
			}
			w.WriteHeader(404)
			return
		}
	}

	w.WriteHeader(404)
	json.NewEncoder(w).Encode(map[string]string{"error": "Not found"})
}
