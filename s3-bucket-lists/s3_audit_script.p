#!/usr/bin/env python3
"""
S3 Bucket Audit Script

This script retrieves all S3 buckets in an AWS account and checks their 
block public access settings. It generates a comprehensive report showing
the security posture of each bucket.

Requirements:
    - boto3
    - AWS credentials configured (via environment variables, AWS CLI, or IAM role)

Usage:
    python3 s3_audit_script.py [--output-format json|csv|table] [--region REGION] [--profile PROFILE]
"""

import boto3
import json
import csv
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Optional
from botocore.exceptions import ClientError, NoCredentialsError


class S3Auditor:
    """Class to audit S3 buckets and their public access settings."""
    
    def __init__(self, profile: Optional[str] = None, region: Optional[str] = None):
        """
        Initialize the S3 auditor.
        
        Args:
            profile: AWS profile name to use
            region: AWS region to use (default: us-east-1)
        """
        try:
            session_kwargs = {}
            if profile:
                session_kwargs['profile_name'] = profile
            if region:
                session_kwargs['region_name'] = region
            
            session = boto3.Session(**session_kwargs)
            self.s3_client = session.client('s3')
            self.region = region or session.region_name or 'us-east-1'
            print(f"✓ Successfully connected to AWS (Region: {self.region})")
        except NoCredentialsError:
            print("✗ Error: AWS credentials not found. Please configure your credentials.")
            sys.exit(1)
        except Exception as e:
            print(f"✗ Error initializing AWS client: {str(e)}")
            sys.exit(1)
    
    def get_all_buckets(self) -> List[Dict]:
        """
        Retrieve all S3 buckets in the account.
        
        Returns:
            List of bucket information dictionaries
        """
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            print(f"✓ Found {len(buckets)} S3 bucket(s)")
            return buckets
        except ClientError as e:
            print(f"✗ Error listing buckets: {e}")
            return []
    
    def get_bucket_location(self, bucket_name: str) -> str:
        """
        Get the region of a specific bucket.
        
        Args:
            bucket_name: Name of the bucket
            
        Returns:
            Region name or 'Unknown' if unable to determine
        """
        try:
            response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            location = response.get('LocationConstraint')
            # S3 returns None for us-east-1
            return location if location else 'us-east-1'
        except ClientError:
            return 'Unknown'
    
    def get_bucket_public_access_block(self, bucket_name: str) -> Dict:
        """
        Get the public access block configuration for a bucket.
        
        Args:
            bucket_name: Name of the bucket
            
        Returns:
            Dictionary containing public access block settings
        """
        try:
            response = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = response.get('PublicAccessBlockConfiguration', {})
            return {
                'BlockPublicAcls': config.get('BlockPublicAcls', False),
                'IgnorePublicAcls': config.get('IgnorePublicAcls', False),
                'BlockPublicPolicy': config.get('BlockPublicPolicy', False),
                'RestrictPublicBuckets': config.get('RestrictPublicBuckets', False),
                'Status': 'Configured'
            }
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'NoSuchPublicAccessBlockConfiguration':
                return {
                    'BlockPublicAcls': False,
                    'IgnorePublicAcls': False,
                    'BlockPublicPolicy': False,
                    'RestrictPublicBuckets': False,
                    'Status': 'Not Configured'
                }
            else:
                return {
                    'BlockPublicAcls': None,
                    'IgnorePublicAcls': None,
                    'BlockPublicPolicy': None,
                    'RestrictPublicBuckets': None,
                    'Status': f'Error: {error_code}'
                }
    
    def get_bucket_encryption(self, bucket_name: str) -> str:
        """
        Get the encryption configuration for a bucket.
        
        Args:
            bucket_name: Name of the bucket
            
        Returns:
            String describing encryption status
        """
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            if rules:
                encryption = rules[0].get('ApplyServerSideEncryptionByDefault', {})
                algorithm = encryption.get('SSEAlgorithm', 'Unknown')
                kms_key = encryption.get('KMSMasterKeyID', '')
                if kms_key:
                    return f"{algorithm} (KMS)"
                return algorithm
            return 'None'
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'ServerSideEncryptionConfigurationNotFoundError':
                return 'None'
            return 'Unknown'
    
    def get_bucket_versioning(self, bucket_name: str) -> str:
        """
        Get the versioning status for a bucket.
        
        Args:
            bucket_name: Name of the bucket
            
        Returns:
            Versioning status (Enabled, Suspended, or Disabled)
        """
        try:
            response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = response.get('Status', 'Disabled')
            return status
        except ClientError:
            return 'Unknown'
    
    def get_bucket_tags(self, bucket_name: str) -> Dict[str, str]:
        """
        Get tags for a bucket.
        
        Args:
            bucket_name: Name of the bucket
            
        Returns:
            Dictionary of tags
        """
        try:
            response = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
            tags = {tag['Key']: tag['Value'] for tag in response.get('TagSet', [])}
            return tags
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'NoSuchTagSet':
                return {}
            return {}
    
    def is_bucket_secure(self, public_access_config: Dict) -> bool:
        """
        Determine if a bucket has all public access blocks enabled.
        
        Args:
            public_access_config: Public access block configuration
            
        Returns:
            True if all blocks are enabled, False otherwise
        """
        if public_access_config.get('Status') != 'Configured':
            return False
        
        return (
            public_access_config.get('BlockPublicAcls') and
            public_access_config.get('IgnorePublicAcls') and
            public_access_config.get('BlockPublicPolicy') and
            public_access_config.get('RestrictPublicBuckets')
        )
    
    def audit_all_buckets(self) -> List[Dict]:
        """
        Audit all S3 buckets and gather comprehensive information.
        
        Returns:
            List of dictionaries containing bucket audit information
        """
        buckets = self.get_all_buckets()
        audit_results = []
        
        print(f"\n{'=' * 80}")
        print("Starting bucket audit...")
        print(f"{'=' * 80}\n")
        
        for idx, bucket in enumerate(buckets, 1):
            bucket_name = bucket['Name']
            creation_date = bucket['CreationDate'].isoformat()
            
            print(f"[{idx}/{len(buckets)}] Auditing: {bucket_name}")
            
            # Gather all information
            location = self.get_bucket_location(bucket_name)
            public_access = self.get_bucket_public_access_block(bucket_name)
            encryption = self.get_bucket_encryption(bucket_name)
            versioning = self.get_bucket_versioning(bucket_name)
            tags = self.get_bucket_tags(bucket_name)
            is_secure = self.is_bucket_secure(public_access)
            
            audit_result = {
                'BucketName': bucket_name,
                'CreationDate': creation_date,
                'Region': location,
                'BlockPublicAcls': public_access.get('BlockPublicAcls'),
                'IgnorePublicAcls': public_access.get('IgnorePublicAcls'),
                'BlockPublicPolicy': public_access.get('BlockPublicPolicy'),
                'RestrictPublicBuckets': public_access.get('RestrictPublicBuckets'),
                'PublicAccessBlockStatus': public_access.get('Status'),
                'Encryption': encryption,
                'Versioning': versioning,
                'IsSecure': is_secure,
                'Tags': tags
            }
            
            audit_results.append(audit_result)
            
            # Print status indicator
            status_icon = '✓' if is_secure else '⚠'
            print(f"  {status_icon} Security Status: {'SECURE' if is_secure else 'NEEDS ATTENTION'}")
        
        print(f"\n{'=' * 80}")
        print(f"Audit completed: {len(audit_results)} bucket(s) audited")
        print(f"{'=' * 80}\n")
        
        return audit_results


def print_summary(audit_results: List[Dict]):
    """
    Print a summary of the audit results.
    
    Args:
        audit_results: List of audit result dictionaries
    """
    total_buckets = len(audit_results)
    secure_buckets = sum(1 for result in audit_results if result['IsSecure'])
    insecure_buckets = total_buckets - secure_buckets
    
    print("\n" + "=" * 80)
    print("AUDIT SUMMARY")
    print("=" * 80)
    print(f"Total Buckets:          {total_buckets}")
    print(f"Secure Buckets:         {secure_buckets} ✓")
    print(f"Buckets Needing Review: {insecure_buckets} ⚠")
    
    if insecure_buckets > 0:
        print(f"\n{'=' * 80}")
        print("BUCKETS REQUIRING ATTENTION:")
        print("=" * 80)
        for result in audit_results:
            if not result['IsSecure']:
                print(f"\n• {result['BucketName']}")
                print(f"  Region: {result['Region']}")
                print(f"  Status: {result['PublicAccessBlockStatus']}")
                if result['PublicAccessBlockStatus'] == 'Configured':
                    issues = []
                    if not result['BlockPublicAcls']:
                        issues.append("BlockPublicAcls: False")
                    if not result['IgnorePublicAcls']:
                        issues.append("IgnorePublicAcls: False")
                    if not result['BlockPublicPolicy']:
                        issues.append("BlockPublicPolicy: False")
                    if not result['RestrictPublicBuckets']:
                        issues.append("RestrictPublicBuckets: False")
                    print(f"  Issues: {', '.join(issues)}")
    
    print("\n" + "=" * 80)


def output_as_table(audit_results: List[Dict]):
    """
    Print audit results as a formatted table.
    
    Args:
        audit_results: List of audit result dictionaries
    """
    print("\n" + "=" * 80)
    print("DETAILED AUDIT RESULTS (TABLE FORMAT)")
    print("=" * 80 + "\n")
    
    # Header
    header = f"{'Bucket Name':<40} {'Secure':<8} {'Region':<15} {'Encryption':<15}"
    print(header)
    print("-" * 80)
    
    # Rows
    for result in audit_results:
        status = "✓ Yes" if result['IsSecure'] else "⚠ No"
        row = f"{result['BucketName']:<40} {status:<8} {result['Region']:<15} {result['Encryption']:<15}"
        print(row)


def output_as_json(audit_results: List[Dict], filename: Optional[str] = None):
    """
    Output audit results as JSON.
    
    Args:
        audit_results: List of audit result dictionaries
        filename: Optional filename to save JSON output
    """
    output_data = {
        'AuditDate': datetime.now().isoformat(),
        'TotalBuckets': len(audit_results),
        'SecureBuckets': sum(1 for r in audit_results if r['IsSecure']),
        'Buckets': audit_results
    }
    
    json_output = json.dumps(output_data, indent=2, default=str)
    
    if filename:
        with open(filename, 'w') as f:
            f.write(json_output)
        print(f"✓ JSON output saved to: {filename}")
    else:
        print("\n" + "=" * 80)
        print("JSON OUTPUT")
        print("=" * 80)
        print(json_output)


def output_as_csv(audit_results: List[Dict], filename: Optional[str] = None):
    """
    Output audit results as CSV.
    
    Args:
        audit_results: List of audit result dictionaries
        filename: Optional filename to save CSV output
    """
    if not audit_results:
        print("No results to output.")
        return
    
    fieldnames = [
        'BucketName', 'Region', 'CreationDate', 'IsSecure',
        'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy',
        'RestrictPublicBuckets', 'PublicAccessBlockStatus',
        'Encryption', 'Versioning'
    ]
    
    # Create CSV rows without Tags for simplicity
    csv_rows = []
    for result in audit_results:
        row = {k: v for k, v in result.items() if k in fieldnames}
        csv_rows.append(row)
    
    if filename:
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"✓ CSV output saved to: {filename}")
    else:
        print("\n" + "=" * 80)
        print("CSV OUTPUT")
        print("=" * 80)
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
        print(output.getvalue())


def main():
    """Main function to run the S3 audit script."""
    parser = argparse.ArgumentParser(
        description='Audit S3 buckets and check their public access block settings.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic audit with table output
  python3 s3_audit_script.py
  
  # Output as JSON
  python3 s3_audit_script.py --output-format json
  
  # Save JSON to file
  python3 s3_audit_script.py --output-format json --output-file s3_audit_report.json
  
  # Use specific AWS profile
  python3 s3_audit_script.py --profile production
  
  # Specify region
  python3 s3_audit_script.py --region ap-northeast-1
        """
    )
    
    parser.add_argument(
        '--output-format',
        choices=['table', 'json', 'csv'],
        default='table',
        help='Output format for the audit results (default: table)'
    )
    
    parser.add_argument(
        '--output-file',
        type=str,
        help='File to save output (only for json and csv formats)'
    )
    
    parser.add_argument(
        '--profile',
        type=str,
        help='AWS profile name to use'
    )
    
    parser.add_argument(
        '--region',
        type=str,
        help='AWS region to use (default: from profile or us-east-1)'
    )
    
    parser.add_argument(
        '--no-summary',
        action='store_true',
        help='Skip printing the summary'
    )
    
    args = parser.parse_args()
    
    # Print script header
    print("\n" + "=" * 80)
    print("S3 BUCKET SECURITY AUDIT SCRIPT")
    print("=" * 80 + "\n")
    
    # Initialize auditor and run audit
    auditor = S3Auditor(profile=args.profile, region=args.region)
    audit_results = auditor.audit_all_buckets()
    
    if not audit_results:
        print("No buckets found or unable to audit buckets.")
        sys.exit(1)
    
    # Output results in requested format
    if args.output_format == 'json':
        output_as_json(audit_results, args.output_file)
    elif args.output_format == 'csv':
        output_as_csv(audit_results, args.output_file)
    else:  # table
        output_as_table(audit_results)
    
    # Print summary unless --no-summary is specified
    if not args.no_summary:
        print_summary(audit_results)
    
    print("\n✓ Audit completed successfully!\n")


if __name__ == '__main__':
    main()

