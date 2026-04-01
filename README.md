# S3-buckets-auditor
I built this portable tool in Go to find public S3 buckets. it uses goroutines to scan fast and creates a professional report for GRC audits. it is safe because it uses the official AWS SDK and the default credential chain. i recommend using short lived keys or other methods depending on the confidence you have in your environment security.
