package main

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

// OTPGenerator интерфейс для генерации OTP
type OTPGenerator interface {
	GenerateOTP(secret string, counter int64) (string, error)
}

// CustomOTPGenerator реализует генерацию OTP с кастомной логикой
type CustomOTPGenerator struct{}

// GenerateOTP генерирует OTP-код, длина которого равна длине секретного ключа
func (g *CustomOTPGenerator) GenerateOTP(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	// Генерируем OTP-код с длиной, равной длине ключа
	otp := make([]byte, len(key))
	for i, b := range key {
		otp[i] = b ^ byte(counter&0xFF) // Используем младшие 8 бит counter для XOR
	}

	return base32.StdEncoding.EncodeToString(otp), nil
}

// Флаг для правильного ответа

// Секретный ключ и генератор OTP-кодов
var secret = generateSecret()
var otpGenerator OTPGenerator = &CustomOTPGenerator{}

// Структура для запроса и ответа JSON
type OTPRequest struct {
	OTP string `json:"otp"`
}

type Response struct {
	Message         string      `json:"message"`
	Flag            string      `json:"flag,omitempty"`
	Otp_now         string      `json:"otp_now"`
	ExpectedRequest *OTPRequest `json:"expected_request,omitempty"`
}

// Обработчик для возвращения текущего OTP
func otpNowHandler(w http.ResponseWriter, r *http.Request) {
	counter := time.Now().Unix() / 60
	currentOTP, err := otpGenerator.GenerateOTP(secret, counter)
	if err != nil {
		http.Error(w, "Ошибка генерации OTP", http.StatusInternalServerError)
		return
	}

	response := Response{
		Message: "Текущий OTP сгенерирован.",
		Otp_now: currentOTP,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Обработчик для проверки OTP на 10 минут вперед
func otp10Handler(w http.ResponseWriter, r *http.Request) {
	var userRequest OTPRequest
	if err := json.NewDecoder(r.Body).Decode(&userRequest); err != nil {
		response := Response{
			Message:         "Неверный формат запроса. Ожидаемая структура:",
			ExpectedRequest: &OTPRequest{OTP: "your_otp_here"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Генерируем OTP для времени через 10 минут
	futureCounter := (time.Now().Unix() / 60) + 10
	expectedOTP, err := otpGenerator.GenerateOTP(secret, futureCounter)
	if err != nil {
		http.Error(w, "Ошибка генерации OTP", http.StatusInternalServerError)
		return
	}
	fmt.Println(expectedOTP)
	// Проверка OTP-кода
	var response Response
	if userRequest.OTP == expectedOTP {
		response.Message = "OTP верен!"
		response.Flag = os.Getenv("FLAG")
	} else {
		response.Message = "Неверный OTP-код. Попробуйте еще раз."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Генерация случайного секретного ключа
func generateSecret() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	secret := make([]byte, 16)
	for i := range secret {
		secret[i] = charset[rand.Intn(len(charset))]
	}
	return base32.StdEncoding.EncodeToString(secret)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	fmt.Println("Секретный ключ для задачи:", secret) // Показываем секрет для тестирования

	http.HandleFunc("/otp_now", otpNowHandler) // Маршрут для текущего OTP
	http.HandleFunc("/otp_10", otp10Handler)   // Маршрут для проверки OTP на 10 минут вперёд
	fmt.Println("Сервер запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
