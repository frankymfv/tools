# S3 Bucket Audit Script

This repository contains a Python script for auditing Amazon S3 buckets in an AWS account. The script retrieves all S3 buckets and checks their security posture, including public access block settings, encryption, versioning, and tags. It generates a comprehensive report to help you identify buckets that may require attention to improve security.

## Features

- Lists all S3 buckets in your AWS account
- Checks each bucket's public access block configuration
- Reports on encryption and versioning status
- Displays bucket tags
- Outputs results in table, JSON, or CSV format
- Summarizes secure and insecure buckets

## Requirements

- Python 3
- boto3 library
- AWS credentials configured (via environment variables, AWS CLI, or IAM role)

## Usage

```bash
python3 s3_audit_script.py [--output-format json|csv|table] [--region REGION] [--profile PROFILE]
```

### Examples

- Basic audit with table output:
  ```bash
  python3 s3_audit_script.py
  ```
- Output as JSON:
  ```bash
  python3 s3_audit_script.py --output-format json
  ```
- Save JSON to file:
  ```bash
  python3 s3_audit_script.py --output-format json --output-file s3_audit_report.json
  ```
- Use specific AWS profile:
  ```bash
  python3 s3_audit_script.py --profile production
  ```
- Specify region:
  ```bash
  python3 s3_audit_script.py --region ap-northeast-1
  ```

## Output

- Table: Prints a formatted table of bucket security status
- JSON: Outputs a detailed JSON report (optionally saved to a file)
- CSV: Outputs a CSV report (optionally saved to a file)
- Summary: Shows the number of secure and insecure buckets

## License

Specify your license here.
