# Portable S3 Public Access Auditor

I built this tool to help security people find S3 buckets that are open to the public. if a bucket is public anyone can see the data. this tool finds those risks and makes a report.

## Why this tool is good

* **fast scanning** It uses goroutines to check many buckets at the same time.
* **security first** it uses the official AWS SDK and the default credential chain. it is very safe.
* **flexible security** I recommend using short lived keys or any other method based on how much confidence you have in your own environment security.
* **GRC ready** it creates a file called audit_results.md with a table. you can use this as evidence for your security audit.

## how it works

The tool checks two things for every bucket
1. **bucket policy status** to see if the policy allows public access.
2. **public access block** to see if the master switch is on or off.

if either of these is risky the tool marks it as **High Risk**.

## how to use it

### step 1 setup your keys
Make sure your AWS keys are active in your terminal. the tool uses the **default credential chain** so it looks for keys in your environment variables or your local aws config file.

### step 2 run the tool
You can run the code directly if you have Go installed
`go run main.go`

Or you can run the program file directly
`./main`

### step 3: check the results
after it finishes, look for a file named **audit_results.md**. it will have a table like this

| Bucket Name | Status | Risk Level | Last Audited |
| :--- | :--- | :--- | :--- |
| my test bucket | Public | High | 2026 04 01 |

## flags
you can also scan specific targets
* scan one bucket `go run main.go -bucket my-secret-bucket`
* scan a list from a file `go run main.go -csv my_list.csv`
