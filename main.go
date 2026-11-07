package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type BucketReport struct {
	Name                          string
	PublicPolicy, IncompleteBlock bool
	Errors                        []string
	PolicyState, BlockState       string
}

func (r BucketReport) Status() (string, string) {
	if len(r.Errors) > 0 {
		return "Unknown / incomplete", "Review"
	}
	if r.PublicPolicy {
		return "Public policy detected", "High"
	}
	if r.IncompleteBlock {
		return "Block configuration incomplete", "Review"
	}
	return "Checked controls enabled", "Low (limited scope)"
}

type bucketAPI interface {
	GetBucketPolicyStatus(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

func codeIs(err error, code string) bool {
	var e smithy.APIError
	return errors.As(err, &e) && e.ErrorCode() == code
}
func inspect(ctx context.Context, c bucketAPI, name string) BucketReport {
	r := BucketReport{Name: name, PolicyState: "unknown", BlockState: "unknown"}
	if ctx.Err() != nil {
		r.Errors = append(r.Errors, "inspection cancelled before collection")
		return r
	}
	p, err := c.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: aws.String(name)})
	switch {
	case codeIs(err, "NoSuchBucketPolicy"):
		r.PolicyState = "no bucket policy"
	case err != nil:
		r.Errors = append(r.Errors, "policy: "+err.Error())
	case p == nil || p.PolicyStatus == nil || p.PolicyStatus.IsPublic == nil:
		r.Errors = append(r.Errors, "policy: empty API response")
	default:
		r.PublicPolicy = aws.ToBool(p.PolicyStatus.IsPublic)
		r.PolicyState = "not public according to policy status"
		if r.PublicPolicy {
			r.PolicyState = "public according to policy status"
		}
	}
	b, err := c.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)})
	switch {
	case codeIs(err, "NoSuchPublicAccessBlockConfiguration"):
		r.IncompleteBlock = true
		r.BlockState = "configuration absent"
	case err != nil:
		r.Errors = append(r.Errors, "block: "+err.Error())
	case b == nil || b.PublicAccessBlockConfiguration == nil:
		r.Errors = append(r.Errors, "block: empty API response")
	default:
		v := b.PublicAccessBlockConfiguration
		if v.BlockPublicAcls == nil || v.BlockPublicPolicy == nil || v.IgnorePublicAcls == nil || v.RestrictPublicBuckets == nil {
			r.Errors = append(r.Errors, "block: missing flag in API response")
			return r
		}
		r.IncompleteBlock = !(aws.ToBool(v.BlockPublicAcls) && aws.ToBool(v.BlockPublicPolicy) && aws.ToBool(v.IgnorePublicAcls) && aws.ToBool(v.RestrictPublicBuckets))
		r.BlockState = "all four flags enabled"
		if r.IncompleteBlock {
			r.BlockState = "one or more flags disabled"
		}
	}
	return r
}
func audit(ctx context.Context, c bucketAPI, names []string, workers int) []BucketReport {
	unique := map[string]bool{}
	filtered := []string{}
	for _, n := range names {
		if !unique[n] {
			unique[n] = true
			filtered = append(filtered, n)
		}
	}
	names = filtered
	if workers > 64 {
		workers = 64
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(names) {
		workers = len(names)
	}
	jobs := make(chan string)
	results := make(chan BucketReport, len(names))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				cx, cancel := context.WithTimeout(ctx, 30*time.Second)
				results <- inspect(cx, c, name)
				cancel()
			}
		}()
	}
	for _, n := range names {
		select {
		case jobs <- n:
		case <-ctx.Done():
			results <- BucketReport{Name: n, Errors: []string{"scan cancelled; not assessed"}, PolicyState: "unknown", BlockState: "unknown"}
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	var reports []BucketReport
	for r := range results {
		reports = append(reports, r)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	return reports
}
func writeReports(out, errs io.Writer, reports []BucketReport, now time.Time) error {
	if _, err := fmt.Fprintln(out, "# S3 Public Access Configuration Audit\n\nScope: bucket policy status and bucket-level Public Access Block only. These checks do not establish effective anonymous access. Review account controls, ACLs, access points, and API errors separately.\n\n| Bucket | Status | Risk | Public policy | Incomplete block | Audited (UTC) |\n| --- | --- | --- | --- | --- | --- |"); err != nil {
		return err
	}
	clean := func(s string) string { return strings.NewReplacer("|", "/", "\n", " ", "\r", " ").Replace(s) }
	for _, r := range reports {
		status, risk := r.Status()
		if _, err := fmt.Fprintf(out, "| %s | %s | %s | %t | %t | %s |\n", clean(r.Name), status, risk, r.PublicPolicy, r.IncompleteBlock, now.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		for _, e := range r.Errors {
			if _, err := fmt.Fprintf(errs, "[%s] %s: %s\n", now.UTC().Format(time.RFC3339), r.Name, e); err != nil {
				return err
			}
		}
	}
	return nil
}
func run() error {
	bucket := flag.String("bucket", "", "Scan one bucket")
	list := flag.String("csv", "", "One bucket name per line, no header")
	workers := flag.Int("workers", 8, "Concurrent checks (1-64)")
	demo := flag.String("demo", "", "Synthetic reports JSON; no AWS calls")
	flag.Parse()
	if *workers < 1 || *workers > 64 {
		return fmt.Errorf("workers must be 1-64")
	}
	if *bucket != "" && *list != "" {
		return fmt.Errorf("choose -bucket or -csv")
	}
	var reports []BucketReport
	if *demo != "" {
		if *bucket != "" || *list != "" {
			return fmt.Errorf("demo cannot be combined with AWS targets")
		}
		data, err := os.ReadFile(*demo)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(data, &reports); err != nil {
			return err
		}
		sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	} else {
		ctx := context.Background()
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return err
		}
		client := s3.NewFromConfig(cfg)
		var names []string
		switch {
		case *bucket != "":
			names = []string{*bucket}
		case *list != "":
			f, err := os.Open(*list)
			if err != nil {
				return err
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				if n := strings.TrimSpace(scanner.Text()); n != "" {
					names = append(names, n)
				}
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		default:
			pager := s3.NewListBucketsPaginator(client, &s3.ListBucketsInput{})
			for pager.HasMorePages() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return err
				}
				for _, b := range page.Buckets {
					if b.Name != nil {
						names = append(names, *b.Name)
					}
				}
			}
		}
		reports = audit(ctx, client, names, *workers)
	}
	out, err := os.Create("audit_results.md")
	if err != nil {
		return err
	}
	defer out.Close()
	errs, err := os.OpenFile("error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer errs.Close()
	if err := writeReports(out, errs, reports, time.Now()); err != nil {
		return err
	}
	fmt.Printf("Reviewed %d buckets. See audit_results.md and error.log.\n", len(reports))
	return nil
}
func main() {
	if len(os.Args) == 1 || (len(os.Args) == 2 && os.Args[1] == "-ui") {
		if err := launch(); err != nil {
			log.Print(err)
			fmt.Println("Press Enter to close.")
			bufio.NewReader(os.Stdin).ReadString('\n')
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
