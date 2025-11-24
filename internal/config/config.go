package config

import (
	"log"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Brokers      	string
	InputTopic   	string
	OutputTopic   	string
	GroupID      	string
	WorkerCount  	int
	MISPURL      	string
	MISPAPIKey   	string
	EPSSURL      	string
	MISPEnabled  	bool
	EPSSEnabled  	bool
	RedisEnabled 	bool
    RedisAddr    	string
    RedisPassword 	string
    RedisDB      	int
}

// Load loads all config from env or defaults
func Load() Config {
	v := viper.New()

	v.SetDefault("KAFKA_BROKER", "localhost:9092")
	v.SetDefault("KAFKA_INPUT_TOPIC", "normalized-logs")
	v.SetDefault("KAFKA_OUTPUT_TOPIC", "enriched-logs")
	v.SetDefault("KAFKA_GROUP_ID", "enrich-soc-group")
	v.SetDefault("WORKER_COUNT", 16)
	v.SetDefault("MISP_URL", "")
	v.SetDefault("MISP_API_KEY", "")
	v.SetDefault("EPSS_URL", "https://api.first.org/data/v1/epss?cve=")
	v.SetDefault("REDIS_ENABLED", false)
	v.SetDefault("REDIS_ADDR", "localhost:6379")
	v.SetDefault("MISP_ENABLED", true)
	v.SetDefault("EPSS_ENABLED", true)

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	cfg := Config{
		Brokers:     v.GetString("KAFKA_BROKER"),
		InputTopic:  v.GetString("KAFKA_INPUT_TOPIC"),
		OutputTopic: v.GetString("KAFKA_OUTPUT_TOPIC"),
		GroupID:     v.GetString("KAFKA_GROUP_ID"),
		WorkerCount: v.GetInt("WORKER_COUNT"),
		MISPURL:     v.GetString("MISP_URL"),
		MISPAPIKey:  v.GetString("MISP_API_KEY"),
		EPSSURL:     v.GetString("EPSS_URL"),
		MISPEnabled: v.GetBool("MISP_ENABLED"),
		EPSSEnabled: v.GetBool("EPSS_ENABLED"),
	}

	cfg.RedisEnabled = v.GetBool("REDIS_ENABLED")
	cfg.RedisAddr = v.GetString("REDIS_ADDR")
	cfg.RedisPassword = v.GetString("REDIS_PASSWORD")
	cfg.RedisDB = v.GetInt("REDIS_DB")

	log.Printf("[config] Loaded: brokers=%s misp=%v epss=%v", cfg.Brokers, cfg.MISPEnabled, cfg.EPSSEnabled)
	return cfg
}
