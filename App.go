package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"io"

	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
)

var clientID, clientSecret, redirectURI string
var accessToken string

// Event yapısı
type Event struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Repo struct {
		Name string `json:"name"`
	} `json:"repo"`
}

// User bilgisi
type User struct {
	Login string `json:"login"`
	Name  string `json:"name"`
}

func init() {
	// .env dosyasını yükle
	err := godotenv.Load()
	if err != nil {
		log.Fatalf(".env dosyası yüklenemedi: %v", err)
	}

	// Ortam değişkenlerini al
	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	redirectURI = os.Getenv("REDIRECT_URI")

	if clientID == "" || clientSecret == "" || redirectURI == "" {
		log.Fatalf("Gerekli ortam değişkenleri eksik!")
	}
}

func main() {
	r := gin.Default()

	// Ana sayfa, GitHub'a yönlendiren linki verir
	r.GET("/", func(c *gin.Context) {
		authUrl := fmt.Sprintf(
			"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=read:user",
			clientID, redirectURI,
		)
		c.Redirect(http.StatusTemporaryRedirect, authUrl)
	})

	// GitHub'dan gelen callback (yetkilendirme kodunu alır ve erişim token'ı alır)
	r.GET("/callback", func(c *gin.Context) {
		code := c.DefaultQuery("code", "")
		if code == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "code parametresi eksik"})
			return
		}

		token, err := getAccessToken(code)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		accessToken = token
		c.Redirect(http.StatusTemporaryRedirect, "/user")
	})

	// Kullanıcı bilgilerini çekme
	r.GET("/user", func(c *gin.Context) {
		client := resty.New()
		resp, err := client.R().
			SetHeader("Authorization", "token "+accessToken).
			Get("https://api.github.com/user")

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Kullanıcı bilgilerini çözümle
		var user User
		err = json.Unmarshal(resp.Body(), &user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User bilgisi çözümlenemedi"})
			return
		}

		// Kullanıcı bilgilerini JSON olarak döndür
		c.JSON(http.StatusOK, user)
	})

	// Kullanıcı etkinliklerini çekme
	r.GET("/events", func(c *gin.Context) {
		client := resty.New()
		resp, err := client.R().
			SetHeader("Authorization", "token "+accessToken).
			Get("https://api.github.com/user")

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Kullanıcı bilgilerini çözümle
		var user User
		err = json.Unmarshal(resp.Body(), &user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User bilgisi çözümlenemedi"})
			return
		}

		// Kullanıcı adını alarak etkinlikleri çek
		events, err := getUserEvents(accessToken, user.Login)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Etkinlikleri yazdır
		for _, event := range events {
			fmt.Printf("Event ID: %s, Type: %s, Repo: %s\n", event.ID, event.Type, event.Repo.Name)
		}
		c.JSON(http.StatusOK, events)
	})

	r.Run(":8000") // Uygulama portu
}

// Access token'ı almak için GitHub API'ye istek
func getAccessToken(code string) (string, error) {
	client := resty.New()
	resp, err := client.R().
		SetFormData(map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"code":          code,
			"redirect_uri":  redirectURI,
		}).
		SetHeader("Accept", "application/json").
		Post("https://github.com/login/oauth/access_token")

	// GitHub yanıtını yazdır
	fmt.Println("GitHub API Yanıtı:", string(resp.Body()))

	if err != nil {
		return "", err
	}

	var responseData map[string]string
	err = json.Unmarshal(resp.Body(), &responseData)
	if err != nil {
		return "", err
	}

	// Access token'ı döndür
	return responseData["access_token"], nil
}

// Kullanıcı etkinliklerini çekme
func getUserEvents(accessToken, username string) ([]Event, error) {
	// GitHub API'den etkinlikleri çekme URL'si
	url := fmt.Sprintf("https://api.github.com/users/%s/events", username)

	// HTTP isteği oluştur
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Authorization başlığını ekle
	req.Header.Add("Authorization", "token "+accessToken)

	// HTTP isteğini gönder
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Yanıtı oku
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Yanıtın içeriğini kontrol et
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API yanıtı hata verdi: %s", resp.Status)
	}

	// JSON yanıtını çözümle
	var events []Event
	err = json.Unmarshal(body, &events)
	if err != nil {
		return nil, err
	}

	return events, nil
}
