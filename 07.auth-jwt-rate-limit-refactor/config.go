package main

import (
	"fmt"
	"os"
)

func loadConfig() Config {
	cfg := Config{}
	cfg.JWTSecret = os.Getenv("JWT_SECRET")
	if cfg.JWTSecret == "" {
		panic("❌ JWT_SECRET required (.env or ENV)")
	}
	cfg.RefreshSecret = os.Getenv("REFRESH_SECRET")
	if cfg.RefreshSecret == "" {
		panic("❌ REFRESH_SECRET required")
	}
	cfg.RateLimit = os.Getenv("RATE_LIMIT")
	if cfg.RateLimit == "" {
		cfg.RateLimit = "100:1m"
	}
	cfg.Port = os.Getenv("PORT")
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	fmt.Printf("🚀 Config: PORT=%s, RATE=%s\n", cfg.Port, cfg.RateLimit)
	return cfg
}