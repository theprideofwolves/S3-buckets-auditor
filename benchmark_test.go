package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// These benchmarks contain no AWS SDK transport or real credentials. Each fake
// read waits for a 1ms timer; scheduler and Go runtime overhead are measured too.
type benchmarkAPI struct{ fakeAPI }

func benchmarkDelay(ctx context.Context) error {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (a benchmarkAPI) GetBucketPolicyStatus(ctx context.Context, in *s3.GetBucketPolicyStatusInput, opts ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	if err := benchmarkDelay(ctx); err != nil {
		return nil, err
	}
	return a.fakeAPI.GetBucketPolicyStatus(ctx, in, opts...)
}
func (a benchmarkAPI) GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if err := benchmarkDelay(ctx); err != nil {
		return nil, err
	}
	return a.fakeAPI.GetPublicAccessBlock(ctx, in, opts...)
}

var benchmarkReports []BucketReport

func BenchmarkSyntheticCollection(b *testing.B) {
	for _, size := range []struct{ buckets, workers int }{{100, 1}, {100, 8}, {1000, 8}} {
		b.Run(fmt.Sprintf("buckets=%d/workers=%d", size.buckets, size.workers), func(b *testing.B) {
			names := make([]string, size.buckets)
			for i := range names {
				names[i] = fmt.Sprintf("synthetic-bucket-%04d", i)
			}
			api := benchmarkAPI{}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchmarkReports = audit(context.Background(), api, names, size.workers)
			}
			b.StopTimer()
			if len(benchmarkReports) != size.buckets {
				b.Fatal("collector lost buckets")
			}
		})
	}
}

func benchmarkHistory(scanCount, bucketCount int) []Scan {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scans := make([]Scan, scanCount)
	for i := range scans {
		scan := Scan{ID: fmt.Sprintf("scan-%03d", i), Scope: "SYNTHETIC BENCHMARK", Demo: true, At: at.Add(time.Duration(i) * time.Hour), Reports: []BucketReport{}}
		for j := 0; j < bucketCount; j++ {
			if i%4 == 2 && j%2 == 0 {
				continue
			}
			report := demoReport(fmt.Sprintf("synthetic-bucket-%04d", j), i%4 == 0 && j%3 == 0, i%4 == 0 && j%5 == 0)
			if i%4 == 1 && j%2 == 0 {
				report.Controls = &BucketControls{}
				report.Errors = []string{"synthetic read denied"}
				report.PolicyState = "unknown"
				report.BlockState = "unknown"
			}
			scan.Reports = append(scan.Reports, report)
		}
		scans[i] = scan
	}
	return scans
}

func BenchmarkVerificationReplay(b *testing.B) {
	for _, size := range []struct{ scans, buckets int }{{10, 100}, {10, 1000}, {25, 1000}} {
		b.Run(fmt.Sprintf("scans=%d/buckets=%d", size.scans, size.buckets), func(b *testing.B) {
			history := benchmarkHistory(size.scans, size.buckets)
			id := history[len(history)-1].ID
			var benchmarkRecord VerificationRecord
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var err error
				benchmarkRecord, err = verification(history, id)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if len(benchmarkRecord.Buckets) != size.buckets {
				b.Fatal("replay lost buckets")
			}
		})
	}
}

func BenchmarkHistorySave(b *testing.B) {
	for _, size := range []struct{ scans, buckets int }{{10, 100}, {10, 1000}} {
		b.Run(fmt.Sprintf("scans=%d/buckets=%d", size.scans, size.buckets), func(b *testing.B) {
			history := benchmarkHistory(size.scans, size.buckets)
			app, err := loadApp(filepath.Join(b.TempDir(), "history.json"))
			if err != nil {
				b.Fatal(err)
			}
			app.state.Scans = history
			// Measure replacement of an existing history, not only the initial write.
			if err := app.save(); err != nil {
				b.Fatal(err)
			}
			encoded, err := json.MarshalIndent(app.state, "", "  ")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := app.save(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(len(encoded)), "history_bytes/op")
			restored, err := loadApp(app.file)
			if err != nil || len(restored.state.Scans) != size.scans {
				b.Fatal("saved history did not reload", err)
			}
		})
	}
}
