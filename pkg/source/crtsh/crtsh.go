package crtsh

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	// postgres driver
	jsoniter "github.com/json-iterator/go"
	_ "github.com/lib/pq"

	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	contextutil "github.com/projectdiscovery/utils/context"
)

var extractor *regexp.Regexp

type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
}

func (s *Source) Run(ctx context.Context, query string, sess *session.Session) <-chan source.Result {
	results := make(chan source.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		extractor, _ = regexp.Compile(`(?i)[a-zA-Z0-9\*_.-]+\.` + query)
		count := s.getSubdomainsFromSQL(ctx, query, results)
		if count > 0 {
			return
		}
		_ = s.getSubdomainsFromHTTP(ctx, query, sess, results)

	}()

	return results
}

func (s *Source) getSubdomainsFromSQL(ctx context.Context, query string, results chan source.Result) int {
	db, err := sql.Open("postgres", "host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes")
	if err != nil {
		results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
		s.errors++
		return 0
	}

	defer db.Close()

	limitClause := ""
	if all, ok := ctx.Value(contextutil.ContextArg("All")).(contextutil.ContextArg); ok {
		if allBool, err := strconv.ParseBool(string(all)); err == nil && !allBool {
			limitClause = "LIMIT 10000"
		}
	}

	sqlQuery := fmt.Sprintf(`WITH ci AS (
				SELECT min(sub.CERTIFICATE_ID) ID,
					min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
					array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
					x509_commonName(sub.CERTIFICATE) COMMON_NAME,
					x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
					x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
					encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER
					FROM (SELECT *
							FROM certificate_and_identities cai
							WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
								AND cai.NAME_VALUE ILIKE ('%%' || $1 || '%%')
								%s
						) sub
					GROUP BY sub.CERTIFICATE
			)
			SELECT array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE
				FROM ci
						LEFT JOIN LATERAL (
							SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
								FROM ct_log_entry ctle
								WHERE ctle.CERTIFICATE_ID = ci.ID
						) le ON TRUE,
					ca
				WHERE ci.ISSUER_CA_ID = ca.ID
				ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;`, limitClause)
	rows, err := db.QueryContext(ctx, sqlQuery, query)
	if err != nil {
		results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
		s.errors++
		return 0
	}
	if err := rows.Err(); err != nil {
		results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
		s.errors++
		return 0
	}

	var count int
	var data string
	// Parse all the rows getting subdomains
	for rows.Next() {

		err := rows.Scan(&data)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			return count
		}

		count++
		for _, domains := range strings.Split(data, "\n") {
			for _, value := range extractor.FindAllString(domains, -1) {
				if value != "" {
					results <- source.Result{Source: s.Name(), Type: source.Domain, Value: strings.ToLower(value)}
					s.results++
				}
			}
		}
	}
	return count
}

type domainEntry struct {
	ID        int    `json:"id"`
	NameValue string `json:"name_value"`
}

func (s *Source) getSubdomainsFromHTTP(ctx context.Context, query string, sess *session.Session, results chan source.Result) bool {
	resp, err := sess.SimpleGet(ctx, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", query))
	if err != nil {
		results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
		s.errors++
		sess.DiscardHTTPResponse(resp)
		return false
	}

	var domains []domainEntry
	err = jsoniter.NewDecoder(resp.Body).Decode(&domains)
	if err != nil {
		results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
		s.errors++
		resp.Body.Close()
		return false
	}

	resp.Body.Close()

	for _, domain := range domains {
		for _, value := range strings.Split(domain.NameValue, "\n") {
			for _, value := range extractor.FindAllString(value, -1) {
				if value != "" {
					results <- source.Result{Source: s.Name(), Type: source.Domain, Value: value}
				}
				s.results++
			}
		}
	}

	return true
}

func (s *Source) Name() string {
	return "crtsh"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) SupportedDiscoveryModes() []source.DiscoveryMode {
	return []source.DiscoveryMode{source.DNSMode}
}

func (s *Source) DiscoveryType() source.DiscoveryType {
	return source.Passive
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() source.Statistics {
	return source.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}
