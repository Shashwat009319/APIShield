package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Shashwat009319/apishield/internal/database"
	"github.com/Shashwat009319/apishield/internal/httpapi"
	"github.com/joho/godotenv"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	_ = godotenv.Load()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is not configured")
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	dbCtx, cancelDB := context.WithTimeout(ctx, 10*time.Second)
	defer cancelDB()

	db, err := database.Open(dbCtx, databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	log.Println("PostgreSQL connected successfully")

	server := httpapi.NewWithDatabase("127.0.0.1:8080", db)
	serverErr := make(chan error, 1)

	go func() {
		log.Println("APIShield running on http://127.0.0.1:8080")
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cancel()

		log.Println("Shutting down APIShield...")
		return server.Shutdown(shutdownCtx)
	}
}
