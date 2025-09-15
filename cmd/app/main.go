package main

import (
	"context"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/joho/godotenv"
	"go-http-pgsql-krb5/internal/handlers"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	err := godotenv.Overload()
	if err != nil {
		log.Println("Error loading .env file")
		return
	}

	krb5confPath := os.Getenv("KRB5_CONFIG_PATH")
	if krb5confPath == "" {
		krb5confPath = "/etc/krb5.conf"
	}
	keytabPath := os.Getenv("KRB5_KEYTAB_PATH")
	if keytabPath == "" {
		keytabPath = "/etc/apache2/keytab"
	}
	// SPN вашего сервиса: должен совпадать с записью в keytab

	spn := os.Getenv("KRB5_SPN")

	kt, err := keytab.Load(keytabPath)
	if err != nil {
		log.Fatalf("load keytab: %v", err)
	}
	//krbCfg, err := config.Load(krb5confPath)
	//if err != nil {
	//	log.Fatalf("load krb5.conf: %v", err)
	//}

	// Настройки сервиса: отключаем PAC-decode как быстрый фикс
	//s := service.NewSettings(
	//	kt,
	//	service.SName(spn),
	//	service.DecodePAC(false), // ключевая строка: не пытаться читать PAC
	//	// service.Logger(log.New(os.Stdout, "[krb] ", log.LstdFlags)), // включите при отладке
	//)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /user_show", handlers.IpaUserHandler)
	mux.HandleFunc("GET /test_db", handlers.TestSelectHandler)

	protected := spnego.SPNEGOKRB5Authenticate(mux, kt,
		service.SName(spn),
		service.DecodePAC(false),
	)

	server := &http.Server{
		Addr:    ":9080",
		Handler: protected,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("http server err: %v", err)
			return
		}
	}()

	<-sigChan
	server.Shutdown(context.Background())
}
