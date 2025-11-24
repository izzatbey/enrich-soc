package enrich

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"

	"github.com/izzatbey/enrich-soc/internal/config"
	"github.com/izzatbey/enrich-soc/internal/enricher"
)

type Service struct {
	consumer *kafka.Consumer
	producer *kafka.Producer
	enricher *enricher.Enricher

	inputTopic  string
	outputTopic string

	pool     pond.Pool
	msgCount uint64
}

func New(cfg config.Config, enr *enricher.Enricher) (*Service, error) {
	admin, err := kafka.NewAdminClient(&kafka.ConfigMap{"bootstrap.servers": cfg.Brokers})
	if err == nil {
		ctxAdmin, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		topics := []kafka.TopicSpecification{
			{
				Topic: cfg.OutputTopic, 
				NumPartitions: 1, 
				ReplicationFactor: 1,
				Config: map[string]string{
					"retention.bytes": "1073741824",
				},
			},
		}

		if _, err := admin.CreateTopics(ctxAdmin, topics); err != nil {
			log.Printf("⚠️ Topic creation warning: %v", err)
		} else {
			log.Printf("✅ Topics OK: %s -> %s", cfg.InputTopic, cfg.OutputTopic)
		}

		admin.Close()
	}
	
	// --- Consumer ---
	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":  cfg.Brokers,
		"group.id":           cfg.GroupID,
		"auto.offset.reset":  "earliest",
		"enable.auto.commit": false,
	})
	if err != nil {
		return nil, err
	}

	if err := consumer.Subscribe(cfg.InputTopic, nil); err != nil {
		consumer.Close()
		return nil, err
	}

	// --- Producer ---
	producer, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers":  cfg.Brokers,
		"enable.idempotence": true,
		"linger.ms":          10,
		"compression.type":   "lz4",
		"retries":            5,
	})
	if err != nil {
		consumer.Close()
		return nil, err
	}

	// --- Worker pool ---
	workers := cfg.WorkerCount
	if workers <= 0 {
		workers = 16
	}
	log.Printf("[enrich] workers=%d", workers)

	return &Service{
		consumer:   consumer,
		producer:   producer,
		enricher:   enr,
		inputTopic: cfg.InputTopic,
		outputTopic: cfg.OutputTopic,
		pool:       pond.NewPool(workers),
	}, nil
}

// Run starts the main loop: consume → enrich → produce
func (s *Service) Run(ctx context.Context) {
	log.Printf("🚀 enrich-soc started (%s → %s)", s.inputTopic, s.outputTopic)
	
	go s.metricsLoop()
	go s.deliveryReportLoop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[enrich] shutdown requested")
			s.shutdown()
			return

		default:
			ev := s.consumer.Poll(100)
			if ev == nil {
				continue
			}

			switch e := ev.(type) {
			case *kafka.Message:
				msg := e
				s.pool.Submit(func() {
					s.processMessage(msg)
				})

			case kafka.Error:
				log.Printf("[Kafka error] %v", e)

			default:
				// ignore other event types (stats, etc)
			}
		}
	}
}

// processMessage runs inside worker pool goroutines
func (s *Service) processMessage(msg *kafka.Message) {
	raw := string(msg.Value)

	// Enrich log
	enriched := s.enricher.Apply(raw)

	// Produce to output topic
	err := s.producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{
			Topic:     &s.outputTopic,
			Partition: kafka.PartitionAny,
		},
		Key:       msg.Key,
		Value:     []byte(enriched),
		Timestamp: msg.Timestamp,
	}, nil)

	if err != nil {
		log.Printf("[Produce error] %v", err)
		return
	}

	// Commit offset
	if _, err := s.consumer.CommitMessage(msg); err != nil {
		log.Printf("[Commit error] %v", err)
	}

	atomic.AddUint64(&s.msgCount, 1)
}

// metricsLoop: logs throughput and periodically flushes the producer
func (s *Service) metricsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var last uint64

	for range ticker.C {
		current := atomic.LoadUint64(&s.msgCount)
		rate := float64(current-last) / 5.0
		last = current

		// 🔄 IMPORTANT: flush pending records every 5s
		s.producer.Flush(500) // wait up to 500ms

		log.Printf(
			"[metrics] rate=%.2f msg/sec | total=%d | workers=%d | queued=%d",
			rate,
			current,
			s.pool.RunningWorkers(),
			s.pool.WaitingTasks(),
		)
	}
}

// deliveryReportLoop: logs async delivery errors from producer
func (s *Service) deliveryReportLoop() {
	for e := range s.producer.Events() {
		switch ev := e.(type) {
		case *kafka.Message:
			if ev.TopicPartition.Error != nil {
				log.Printf("[delivery error] %v", ev.TopicPartition.Error)
			}
		}
	}
}

// shutdown: graceful stop on ctx cancel
func (s *Service) shutdown() {
	log.Println("[enrich] stopping workers...")
	s.pool.StopAndWait()

	log.Println("[enrich] flushing producer...")
	remaining := s.producer.Flush(5000) // 120s
	if remaining > 0 {
		log.Printf("[enrich] %d messages not flushed", remaining)
	}

	log.Println("[enrich] closing producer...")
	s.producer.Close()

	log.Println("[enrich] closing consumer...")
	s.consumer.Close()
}
