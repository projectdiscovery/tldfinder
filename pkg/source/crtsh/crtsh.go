package crtsh

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	// postgres driver
	_ "github.com/lib/pq"

	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	contextutil "github.com/projectdiscovery/utils/context"
)

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

		db, err := sql.Open("postgres", "host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes")
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
		}
		defer db.Close()

		limitClause := ""
		if all, ok := ctx.Value(contextutil.ContextArg("All")).(contextutil.ContextArg); ok {
			if allBool, err := strconv.ParseBool(string(all)); err == nil && !allBool {
				limitClause = "LIMIT 10000"
			}
		}

		sqlQuery := fmt.Sprintf(`SELECT DISTINCT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci
	 WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%%.%s')) %s`, query, limitClause)
		rows, err := db.Query(sqlQuery)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
		}
		if rows != nil {
			if err := rows.Err(); err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
			}

			var data string
			for rows.Next() {
				err := rows.Scan(&data)
				if err != nil {
					results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
					s.errors++
				}
				for _, domains := range strings.Split(data, "\n") {
					for _, value := range sess.Extractor.Extract(domains) {
						if value != "" {
							results <- source.Result{Source: s.Name(), Type: source.Domain, Value: value}
							s.results++
						}
					}
				}
			}
		}

	}()

	return results
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
