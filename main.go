package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string `json:"id" bson:"_id"`
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
	Email    string `json:"email" bson:"email"`
}

type StudyGroup struct {
	ID          string   `json:"id" bson:"_id"`
	Name        string   `json:"name" bson:"name"`
	Description string   `json:"description" bson:"description"`
	Members     []string `json:"members" bson:"members"`
}

var db *mongo.Client
var userCollection *mongo.Collection
var groupCollection *mongo.Collection

func main() {
	// Connect to MongoDB
	clientOptions := options.Client().ApplyURI("mongodb+srv://krintox:shanks@cluster0.xbzutsa.mongodb.net/")
	var err error
	db, err = mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Disconnect(context.Background())

	// Initialize Gin router
	router := gin.Default()

	// Load HTML templates
	router.LoadHTMLGlob("templates/*")

	// Serve static files
	router.Static("/static", "./static")

	// Routes
	router.GET("/", indexHandler)
	router.POST("/register", register)
	router.POST("/login", login)

	authorized := router.Group("/api")
	authorized.Use(authMiddleware)
	{
		authorized.GET("/study-groups", getStudyGroups)
		authorized.POST("/study-groups", createStudyGroup)
	}

	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

// Middleware to check if user is authenticated
func authMiddleware(c *gin.Context) {
	// Get JWT token from request header
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		c.Abort()
		return
	}

	// Parse and validate JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check token signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Provide the secret key used to sign the token
		return []byte("your-secret-key"), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	// Token is valid, continue with the next handler
	c.Next()
}

func indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

func register(c *gin.Context) {
	var newUser User
	if err := c.BindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash the password before storing in the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	newUser.Password = string(hashedPassword)

	// Insert user into database
	userCollection := db.Database("studyhub").Collection("users")
	_, err = userCollection.InsertOne(context.Background(), newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.Status(http.StatusCreated)
}

func login(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Retrieve user from the database by username
	userCollection := db.Database("studyhub").Collection("users")
	err := userCollection.FindOne(context.Background(), bson.M{"username": user.Username}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Compare hashed password with input password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(user.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = user.Username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expiry time

	// Sign the token with a secret key
	signedToken, err := token.SignedString([]byte("your-secret-key"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Return the token in the response
	c.JSON(http.StatusOK, gin.H{"token": signedToken})
}

func getStudyGroups(c *gin.Context) {
	// Retrieve study groups from the database
	groupCollection := db.Database("studyhub").Collection("study_groups")
	cursor, err := groupCollection.Find(context.Background(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve study groups"})
		return
	}
	defer cursor.Close(context.Background())

	var studyGroups []StudyGroup
	if err := cursor.All(context.Background(), &studyGroups); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve study groups"})
		return
	}

	c.JSON(http.StatusOK, studyGroups)
}

func createStudyGroup(c *gin.Context) {
	var newGroup StudyGroup
	if err := c.BindJSON(&newGroup); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate ID for the new study group
	newGroup.ID = strconv.FormatInt(time.Now().Unix(), 10)

	// Insert study group into database
	groupCollection := db.Database("studyhub").Collection("study_groups")
	_, err := groupCollection.InsertOne(context.Background(), newGroup)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create study group"})
		return
	}

	c.Status(http.StatusCreated)
}
