package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type BucketReport struct {
	Name                     string
	IsPublicPolicy           bool
	MissingPublicAccessBlock bool
	Error                    error
}

func main() {
	bucketFlag := flag.String("bucket", "", "Scan a single bucket")
	csvFlag := flag.String("csv", "", "CSV file containing a list of buckets")
	flag.Parse()

	ctx := context.TODO()

	// Initialize AWS SDK config, triggering the Default Credential Chain
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config: %v", err)
	}

	// The SDK documentation states we should try to retrieve credentials to verify they exist
	if cfg.Credentials != nil {
		_, err = cfg.Credentials.Retrieve(ctx)
		if err != nil {
			fmt.Println("> \"Your AWS account credentials should be in your environment variables. Credentials are not accepted here for security concerns.\"")
			os.Exit(1)
		}
	} else {
		fmt.Println("> \"Your AWS account credentials should be in your environment variables. Credentials are not accepted here for security concerns.\"")
		os.Exit(1)
	}

	s3Client := s3.NewFromConfig(cfg)
	var targetBuckets []string

	// Determine bucket target list
	if *bucketFlag != "" {
		targetBuckets = append(targetBuckets, *bucketFlag)
	} else if *csvFlag != "" {
		file, err := os.Open(*csvFlag)
		if err != nil {
			log.Fatalf("failed to open CSV file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targetBuckets = append(targetBuckets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("error reading CSV file: %v", err)
		}
	} else {
		bucketsOutput, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			// ListBuckets may also fail due to insufficient permissions or invalid missing identity on STS boundary
			// if so, catching it here is a good fallback.
			log.Fatalf("failed to list buckets: %v", err)
		}
		for _, b := range bucketsOutput.Buckets {
			if b.Name != nil {
				targetBuckets = append(targetBuckets, *b.Name)
			}
		}
	}

	if len(targetBuckets) == 0 {
		fmt.Println("No buckets to scan.")
		return
	}

	// Scanner code starts here
	fmt.Printf("Starting S3 bucket scan on %d buckets...\n", len(targetBuckets))

	// Channel to gather concurrent results
	reportsCh := make(chan BucketReport, len(targetBuckets))
	var wg sync.WaitGroup

	for _, bName := range targetBuckets {
		wg.Add(1)
		go func(bucketName string) {
			defer wg.Done()
			fmt.Printf("Scanning bucket: %s...\n", bucketName)

			isPublicPolicy := false
			missingPublicAccessBlock := false
			var bucketErr error

			// Check bucket policy status
			policyStatus, err := s3Client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				// Record network/API errors that indicate actual connection issues vs just "no policy exists"
				if !strings.Contains(err.Error(), "NoSuchBucketPolicy") {
					bucketErr = err
				}
			} else if policyStatus.PolicyStatus != nil && policyStatus.PolicyStatus.IsPublic != nil {
				isPublicPolicy = *policyStatus.PolicyStatus.IsPublic
			}

			// Check public access block
			pab, err := s3Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
				Bucket: aws.String(bucketName),
			})
			if err != nil {
				missingPublicAccessBlock = true
				if !strings.Contains(err.Error(), "NoSuchPublicAccessBlockConfiguration") {
					if bucketErr == nil {
						bucketErr = err
					} else {
						bucketErr = fmt.Errorf("Policy Error: %v | PAB Error: %v", bucketErr, err)
					}
				}
			} else if pab.PublicAccessBlockConfiguration != nil {
				// Check if any block setting explicitly permits public access
				conf := pab.PublicAccessBlockConfiguration
				if (conf.BlockPublicAcls != nil && !*conf.BlockPublicAcls) ||
					(conf.BlockPublicPolicy != nil && !*conf.BlockPublicPolicy) ||
					(conf.IgnorePublicAcls != nil && !*conf.IgnorePublicAcls) ||
					(conf.RestrictPublicBuckets != nil && !*conf.RestrictPublicBuckets) {
					missingPublicAccessBlock = true
				}
			} else {
				missingPublicAccessBlock = true
			}

			reportsCh <- BucketReport{
				Name:                     bucketName,
				IsPublicPolicy:           isPublicPolicy,
				MissingPublicAccessBlock: missingPublicAccessBlock,
				Error:                    bucketErr,
			}
		}(bName)
	}

	// Separate goroutine to monitor waitgroup and securely close channel
	go func() {
		wg.Wait()
		close(reportsCh)
	}()

	// Read outputs from channel until closed
	var allReports []BucketReport
	for r := range reportsCh {
		allReports = append(allReports, r)
	}

	// Reporter code starts here
	fmt.Println("\nScan completed. Generating report...")

	reportFile, err := os.Create("audit_results.md")
	if err != nil {
		log.Fatalf("failed to create audit_results.md: %v", err)
	}
	defer reportFile.Close()

	errorFile, err := os.OpenFile("error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to create error.log: %v", err)
	}
	defer errorFile.Close()

	reportFile.WriteString("# S3 Public Access Audit Results\n\n")
	reportFile.WriteString("| Bucket Name | Status | Risk Level | Last Audited |\n")
	reportFile.WriteString("| ----------- | ------ | ---------- | ------------ |\n")

	timestamp := time.Now().UTC().Format(time.RFC3339)

	for _, r := range allReports {
		if r.Error != nil {
			errorFile.WriteString(fmt.Sprintf("[%s] Error scanning bucket %s: %v\n", timestamp, r.Name, r.Error))
		}

		status := "Private"
		riskLevel := "Low"

		if r.IsPublicPolicy || r.MissingPublicAccessBlock {
			status = "Public"
			riskLevel = "High"
		}

		reportFile.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", r.Name, status, riskLevel, timestamp))
	}

	fmt.Println("Audit report generated at audit_results.md")
	fmt.Println("Any errors encountered were logged to error.log")
}
