package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type RegRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var db *sql.DB

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Ошибка загрузки .env файла")
	}

	connStr := "user=postgres dbname=Cursovoy2 sslmode=disable password=Djcmvfv583746 host=localhost port=5432"

	fmt.Println("Connection string:", connStr)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Ошибка при подключении к базе данных: %v", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("Ошибка Ping: %v", err)
	}

	fmt.Println("Подключение к PostgreSQL успешно!")

	r := gin.Default()

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET не найден в .env")
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:8081"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "Range"},
		ExposeHeaders:    []string{"Content-Length", "Content-Range"},
		AllowCredentials: true,
	}))

	r.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "-1")
		c.Next()
	})

	r.Static("/static", "../frontend")

	r.GET("/", func(c *gin.Context) {
		c.File("../frontend/public/login.html")
	})
	r.GET("/register", func(c *gin.Context) {
		c.File("../frontend/public/register.html")
	})

	port := "8081"

	fmt.Printf("Сервер запущен на порту %s\n", port)

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Ошибка при запуске сервера: %v", err)
	}
}

func RegisterHandler(c *gin.Context) {
	var req RegRequest

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 OR username = $2)", req.Email, req.Username).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Email or username already exists"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password hashing failed"})
		return
	}

	ip := c.ClientIP()

	_, err = db.Exec(`INSERT INTO users (email, username, password_hash, role, registration_date, ip_address) VALUES ($1, $2, $3, 'user', NOW(), $4)`, req.Email, req.Username, string(hashedPassword), ip)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func AuthHandler(c *gin.Context) {
	var req AuthRequest
	if err := c.BindJSON(&req); err != nil {
		log.Printf("Ошибка привязки JSON: %v", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}

	log.Printf("Поиск пользователя: %s", req.Email)
	var userID string
	var passwordHash string
	var logoURL string
	var username string
	err := db.QueryRow("SELECT id, password_hash, username, COALESCE(NULLIF(logo_url, ''), 'https://i.imgur.com/k8NBJSm.jpg') as logo_url FROM users WHERE LOWER(email) = LOWER($1)", req.Email).Scan(&userID, &passwordHash, &username, &logoURL)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Пользователь не найден: %s", req.Email)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Пользователь не найден"})
		} else {
			log.Printf("Ошибка базы данных: %v", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		log.Printf("Неверный пароль: %s", userID)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
		return
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	token, err := GenerateJWT(userID, jwtSecret)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Ошибка генерации токена"})
		return
	}

	_, err = db.Exec("UPDATE users SET last_login_date = NOW() WHERE id = $1", userID)
	if err != nil {
		log.Printf("Ошибка обновления last_login_date: %v", err)
	}

	c.SetCookie(
		"authToken",
		token,
		36000,
		"/",
		"",
		false,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"token":   token,
		"user":    username,
		"logoURL": logoURL,
	})
}

func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("authToken")
		if err != nil {
			log.Print("Токен отсутствует в куках")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Отсутствует токен"})
			return
		}

		log.Print("Токен из куки: ", tokenString)

		claims, err := validateToken(tokenString, jwtSecret)
		if err != nil {
			log.Printf("Ошибка валидации токена: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
			return
		}
		c.Set("userClaims", claims)
		c.Next()
	}
}

func validateToken(tokenString, jwtSecret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неожиданный метод подписи: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("токен недействителен")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("неверный формат claims")
	}

	return claims, nil
}

func GenerateJWT(userID string, jwtSecret string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().UTC().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(jwtSecret))
	return signedToken, err
}
