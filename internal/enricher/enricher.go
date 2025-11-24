package enricher

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/izzatbey/enrich-soc/internal/cache"
	"github.com/izzatbey/enrich-soc/internal/config"
)

var (
	redisCache *cache.RedisCache
	localCache = cache.NewEnrichCache(1 * time.Hour)
    PositiveTTL = 24 * time.Hour
    NegativeTTL = 1 * time.Hour
)

type Enricher struct {
	cfg    config.Config
	client *http.Client
}

func New(cfg config.Config) *Enricher {
    if cfg.RedisEnabled {
        redisCache = cache.NewRedisCache(
            cfg.RedisAddr,
            cfg.RedisPassword,
            cfg.RedisDB,
            PositiveTTL,
        )
    }

    return &Enricher{
        cfg:    cfg,
        client: &http.Client{Timeout: 4 * time.Second},
    }
}


func (e *Enricher) Apply(raw string) string {
	if e.cfg.MISPEnabled {
		raw = e.enrichWithMISP(raw)
	}
	if e.cfg.EPSSEnabled {
		raw = e.enrichWithEPSS(raw)
	}

	mispObj := gjson.Get(raw, "misp")
	if mispObj.Exists() && len(mispObj.Raw) > 2 {
		raw, _ = sjson.Set(raw, "rule.level", 13)
		raw, _ = sjson.Set(raw, "rule.severity", "high")
	}
	return raw
}

//
// ======================================================================
//                          MISP ENRICHMENT
// ======================================================================
//

func (e *Enricher) enrichWithMISP(raw string) string {

    iocFields := []string{
        "source.ip",
        "destination.ip",
        "file.hash.md5",
        "file.hash.sha1",
        "file.hash.sha256",
        "dns.question.name",
    }

    for _, path := range iocFields {
		value := gjson.Get(raw, path).String()
		if value == "" || isPrivate(value) || !isValidIOC(value) {
			continue
		}

		cacheKey := "misp::" + value

		if cached, ok := e.cacheLookup(cacheKey); ok {
			if len(cached) > 0 {
				jsonStr, _ := json.Marshal(cached)
				raw, _ = sjson.SetRaw(raw, "misp", string(jsonStr))
				break
			}
			continue
		}

		result := e.callMISP(value)
		if result == nil {
			result = map[string]interface{}{}
		}

		if len(result) == 0 {
			e.cacheStore(cacheKey, result, NegativeTTL)
			continue
		} else {
			e.cacheStore(cacheKey, result, PositiveTTL)
			jsonStr, _ := json.Marshal(result)
			raw, _ = sjson.SetRaw(raw, "misp", string(jsonStr))
			break
		}
	}


    return raw
}


//
// ======================================================================
//               MISP API CALL + BUILD CLEAN NESTED OBJECT
// ======================================================================
//

func (e *Enricher) callMISP(ioc string) map[string]interface{} {

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    2,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:  30 * time.Second,
			DisableCompression: true,
			MaxConnsPerHost: 2,
			ForceAttemptHTTP2: false,
		},
	}

	req, err := http.NewRequest("GET", e.cfg.MISPURL+ioc, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Authorization", e.cfg.MISPAPIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[MISP] error: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)

	// First attribute only (most MISP searches return 1)
	attr := gjson.GetBytes(body, "response.Attribute.0")
	if !attr.Exists() {
		return nil
	}

	// ---------- Build the correct nested object ----------
	mispObj := map[string]interface{}{
		"Event": map[string]interface{}{
			"id":               attr.Get("Event.id").Int(),
			"info":             attr.Get("Event.info").String(),
			"uuid":             attr.Get("Event.uuid").String(),
			"org_id":           attr.Get("Event.org_id").Int(),
			"orgc_id":          attr.Get("Event.orgc_id").Int(),
			"user_id":          attr.Get("Event.user_id").Int(),
			"publish_timestamp": attr.Get("Event.publish_timestamp").Int(),
			"distribution":     attr.Get("Event.distribution").Int(),
		},
		"category":            attr.Get("category").String(),
		"type":                attr.Get("type").String(),
		"value":               attr.Get("value").String(),
		"comment":             attr.Get("comment").String(),
		"deleted":             attr.Get("deleted").Bool(),
		"disable_correlation": attr.Get("disable_correlation").Bool(),
		"timestamp":           attr.Get("timestamp").Int(),
		"distribution":        attr.Get("distribution").Int(),
		"to_ids":              attr.Get("to_ids").Bool(),
		"id":                  attr.Get("id").Int(),
		"uuid":                attr.Get("uuid").String(),
		"object_id":           attr.Get("object_id").Int(),
		"sharing_group_id":    attr.Get("sharing_group_id").Int(),
	}

	return mispObj
}

//
// ======================================================================
//                                EPSS
// ======================================================================
//

func (e *Enricher) enrichWithEPSS(raw string) string {
	cve := gjson.Get(raw, "data.vulnerability.cve").String()
	if cve == "" {
		return raw
	}

	cacheKey := "epss::" + cve

	// cache hit
	if cached, ok := e.cacheLookup(cacheKey); ok {
		raw, _ = sjson.Set(raw, "epss", cached)
		return raw
	}

	url := e.cfg.EPSSURL + cve
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return raw
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return raw
	}

	body, _ := io.ReadAll(resp.Body)

	res := map[string]interface{}{
		"score":      gjson.GetBytes(body, "data.0.epss").String(),
		"percentile": gjson.GetBytes(body, "data.0.percentile").String(),
	}

	e.cacheStore(cacheKey, res, PositiveTTL)
	raw, _ = sjson.SetRaw(raw, "epss", toJSON(res))

	return raw
}

//
// ======================================================================
//                        CACHE HELPERS (FIXED)
// ======================================================================
//

// Return parsed JSON as map[string]interface{}
func (e *Enricher) cacheLookup(key string) (map[string]interface{}, bool) {

    // --- Redis first ---
    if redisCache != nil {
        if s, ok := redisCache.Get(key); ok {
            var m map[string]interface{}
            if json.Unmarshal([]byte(s), &m) == nil {
                return m, true
            }
        }
    }

    // --- Local LRU (stores string) ---
    if v, ok := localCache.Get(key); ok {
        if str, ok2 := v.(string); ok2 {
            var m map[string]interface{}
            if json.Unmarshal([]byte(str), &m) == nil {
                return m, true
            }
        }
    }

    return nil, false
}

// Store ONLY JSON string in both caches
func (e *Enricher) cacheStore(key string, obj map[string]interface{}, ttl time.Duration) {
    b, _ := json.Marshal(obj)
    jsonStr := string(b)

    // Redis accepts TTL per write
    if redisCache != nil {
        redisCache.SetWithTTL(key, jsonStr, ttl)
    }

    // Local cache always uses a single TTL → store JSON string
    localCache.Set(key, jsonStr)
}



//
// ======================================================================
//                                 UTIL
// ======================================================================
//

func isPrivate(ip string) bool {
	private := []string{"10.", "192.168.", "172.16.", "127."}
	for _, p := range private {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func isValidIOC(v string) bool {
    if v == "" {
        return false
    }

    invalid := []string{"?", "-", "null", "n/a", "none", "unknown", "\"\"", " ", "\t"}

    l := strings.ToLower(v)
    for _, bad := range invalid {
        if l == bad {
            return false
        }
    }

    if len(v) < 3 {
        return false
    }

    return true
}
