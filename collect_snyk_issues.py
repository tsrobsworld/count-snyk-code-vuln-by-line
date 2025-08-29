#!/usr/bin/env python3
#
# MIT License
#
# Copyright (c) 2024 vuln-count-by-line contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Collect Snyk Issues - Organization Vulnerable Lines Counter

This script counts vulnerable lines of code by Snyk organization and severity level.
It can work at both group level (all orgs in group) or single organization level.

Usage:
    python3 collect_snyk_issues.py --group-id YOUR_GROUP_ID
    python3 collect_snyk_issues.py --org-id YOUR_ORG_ID
    python3 collect_snyk_issues.py --group-id YOUR_GROUP_ID --output org_summary.json
    python3 collect_snyk_issues.py --org-id YOUR_ORG_ID --verbose
"""

import requests
import json
import argparse
import time
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SnykAPI:
    """Snyk API client for collecting issues."""
    
    def __init__(self, token: str, region: str = "SNYK-US-01"):
        self.token = token
        self.base_url = self._get_base_url(region)
        
        # Create session with retry logic and connection pooling
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            backoff_factor=1,  # Wait 1, 2, 4 seconds between retries
            status_forcelist=[500, 502, 503, 504],  # Retry on server errors (not 429)
            allowed_methods=["GET", "POST"],  # Only retry safe methods
            respect_retry_after_header=True,  # Respect rate limit headers
        )
        
        # Configure connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,  # Number of connection pools to cache
            pool_maxsize=20,      # Maximum number of connections per pool
        )
        
        # Set reasonable timeouts
        self.session.timeout = (30, 60)  # (connect_timeout, read_timeout)
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers
        self.session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': '*/*'
        })
    
    def _get_base_url(self, region: str) -> str:
        """Get the appropriate API base URL for the region."""
        region_urls = {
            "SNYK-US-01": "https://api.snyk.io",
            "SNYK-US-02": "https://api.us.snyk.io", 
            "SNYK-EU-01": "https://api.eu.snyk.io",
            "SNYK-AU-01": "https://api.au.snyk.io"
        }
        return region_urls.get(region, "https://api.snyk.io")
    
    def get_issues_for_org(self, org_id: str, issue_type: str = "code", version: str = "2024-10-15") -> Dict:
        """
        Get all issues for a single Snyk organization, handling pagination.
        """
        url = f"{self.base_url}/rest/orgs/{org_id}/issues"
        params = {
            'version': version,
            'type': issue_type,
            'limit': 100,
            'status': 'open'
        }
        all_data = []
        next_url = url
        next_params = params
        while next_url:
            try:
                response = self.session.get(next_url, params=next_params)
                response.raise_for_status()
                data = response.json()
                all_data.extend(data.get('data', []))
                links = data.get('links', {})
                next_url = links.get('next')
                next_params = None
                if next_url:
                    if next_url.startswith('http'):
                        pass  # use as-is
                    elif next_url.startswith('/'):
                        next_url = self.base_url + next_url
                    else:
                        next_url = self.base_url + '/' + next_url.lstrip('/')
                else:
                    next_url = None
            except requests.exceptions.RequestException as e:
                print(f"   ❌ Error fetching issues for org {org_id}: {e}")
                if hasattr(e, 'response') and e.response is not None:
                    print(f"      Status code: {e.response.status_code}")
                    if e.response.status_code == 429:  # Rate limited
                        print(f"      🚫 Rate limited by Snyk - waiting 61 seconds...")
                        time.sleep(61)  # Snyk requires at least 61 seconds
                    elif e.response.status_code >= 500:  # Server error
                        print(f"      Server error - waiting 2 seconds...")
                        time.sleep(2)
                    else:
                        # Wait before retrying other errors
                        time.sleep(2)
                else:
                    # Wait before retrying connection errors
                    time.sleep(2)
                continue
        return {'data': all_data}

    def get_all_orgs(self, group_id: str, version: str = "2024-10-15") -> list:
        """
        Fetch all organizations for a group, handling pagination. Returns a list of orgs.
        """
        url = f"{self.base_url}/rest/groups/{group_id}/orgs"
        params = {'version': version, 'limit': 100}
        all_orgs = []
        next_url = url
        next_params = params
        while next_url:
            try:
                response = self.session.get(next_url, params=next_params)
                response.raise_for_status()
                data = response.json()
                all_orgs.extend(data.get('data', []))
                links = data.get('links', {})
                next_url = links.get('next')
                next_params = None
                if next_url:
                    if next_url.startswith('http'):
                        pass
                    elif next_url.startswith('/'):
                        next_url = self.base_url + next_url
                    else:
                        next_url = self.base_url + '/' + next_url.lstrip('/')
                else:
                    next_url = None
            except requests.exceptions.RequestException as e:
                print(f"   ❌ Error fetching orgs for group {group_id}: {e}")
                if hasattr(e, 'response') and e.response is not None:
                    print(f"      Status code: {e.response.status_code}")
                    if e.response.status_code == 429:  # Rate limited
                        print(f"      🚫 Rate limited by Snyk - waiting 61 seconds...")
                        time.sleep(61)  # Snyk requires at least 61 seconds
                    elif e.response.status_code >= 500:  # Server error
                        print(f"      Server error - waiting 2 seconds...")
                        time.sleep(2)
                    else:
                        # Wait before retrying other errors
                        time.sleep(2)
                else:
                    # Wait before retrying connection errors
                    time.sleep(2)
                continue
        return all_orgs
    
    def get_org_slug(self, org_id: str) -> str:
        """
        Fetch the organization slug for a given org_id using the correct version parameter.
        """
        url = f"{self.base_url}/rest/orgs/{org_id}"
        params = {'version': '2024-10-15'}
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            slug = data.get('data', {}).get('attributes', {}).get('slug')
            if slug:
                return slug
            else:
                print(f"   ⚠️  No slug found for org {org_id}, using org_id as fallback.")
                return org_id
        except requests.exceptions.RequestException as e:
            print(f"   ⚠️  Could not fetch slug for org {org_id}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"      Status code: {e.response.status_code}")
                if e.response.status_code == 429:  # Rate limited
                    print(f"      🚫 Rate limited by Snyk - waiting 61 seconds...")
                    time.sleep(61)  # Snyk requires at least 61 seconds
            return org_id

    def get_issue_details(self, org_id: str, project_id: str, issue_id: str, version: str = "2022-04-06~experimental") -> Dict:
        """
        Fetch detailed information for a specific code issue.
        Args:
            org_id: Organization ID
            project_id: Project ID (scan_item)
            issue_id: Issue problem ID (from attributes.problems[0].id for issue details API)
            version: API version (default: 2022-04-06~experimental - required for issue details)
        Returns:
            Dictionary containing the issue details
        """
        url = f"{self.base_url}/rest/orgs/{org_id}/issues/detail/code/{issue_id}"
        params = {
            'project_id': project_id,
            'version': version
        }
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Error fetching issue details: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"      Status code: {e.response.status_code}")
                if e.response.status_code == 429:  # Rate limited
                    print(f"      🚫 Rate limited by Snyk - waiting 61 seconds...")
                    time.sleep(61)  # Snyk requires at least 61 seconds
                elif e.response.status_code >= 500:  # Server error
                    print(f"      Server error - waiting 2 seconds...")
                    time.sleep(2)
            return None


def process_org_issues(snyk_api: SnykAPI, org_id: str, org_slug: str, verbose: bool = False, debug: bool = False, rate_limit: float = 0.1) -> Dict:
    """
    Process all code issues for a single organization and return vulnerable lines summary.
    Returns: {severity: line_count, total: total_count}
    """
    print(f"🔍 Processing organization: {org_slug} ({org_id})")
    
    # Get all code issues for this org
    issues_data = snyk_api.get_issues_for_org(
        org_id=org_id,
        issue_type="code",
        version="2024-10-15"  # Use latest version for issues endpoint
    )
    
    issues = issues_data.get('data', [])
    print(f"   📋 Found {len(issues)} code issues")
    
    # Save all collected issues to file for debugging (only with --debug flag)
    if debug:
        debug_filename = f"debug_issues_{org_slug}_{org_id[:8]}.json"
        try:
            with open(debug_filename, 'w') as f:
                json.dump(issues_data, f, indent=2)
            print(f"   🔍 Debug: Saved all {len(issues)} issues to {debug_filename}")
        except Exception as e:
            print(f"   ⚠️  Could not save debug file: {e}")
    
    if verbose and issues:
        print(f"   [DEBUG] Sample issues:")
        for i, issue in enumerate(issues[:2]):
            attrs = issue.get('attributes', {})
            main_id = issue.get('id')
            key_id = attrs.get('key')
            print(f"   [DEBUG] Issue {i+1}: id={main_id} key={key_id} title={attrs.get('title', 'No title')}")
    
    # Count vulnerable lines
    org_vulnerable_lines = {
        'high': 0,
        'medium': 0, 
        'low': 0,
        'total': 0
    }
    
    processed_count = 0
    skipped_count = 0
    error_count = 0
    
    print(f"   🔄 Processing {len(issues)} issues...")
    
    for i, issue in enumerate(issues, 1):
        # Progress indicator
        if i % 25 == 0 or i == len(issues):
            print(f"   📊 Progress: {i}/{len(issues)} issues processed ({i/len(issues)*100:.1f}%)")
        
        try:
            # Add jitter to rate limiting to prevent thundering herd
            if rate_limit > 0:
                jitter = random.uniform(0, rate_limit * 0.1)  # 10% jitter
                time.sleep(rate_limit + jitter)
            
            relationships = issue.get('relationships', {})
            attributes = issue.get('attributes', {})
            
            # Extract exactly as specified:
            # org_id: relationships.organization.data.id (we already have this as parameter)
            # project_id: relationships.scan_item.data.id  
            # issue_id: attributes.problems[0].id
            project_id = relationships.get('scan_item', {}).get('data', {}).get('id')
            problems = attributes.get('problems', [])
            issue_id = problems[0].get('id') if problems and len(problems) > 0 else None
            main_id = issue.get('id')  # Main issue ID for reference
            
            # Debug: Print extracted values according to specification (only with --debug flag)
            if debug:
                title = attributes.get('title', 'No title')
                org_id_from_issue = relationships.get('organization', {}).get('data', {}).get('id')
                print(f"   [DEBUG] Issue {i}:")
                print(f"           Title:                    {title}")
                print(f"           org_id (from param):      {org_id}")
                print(f"           org_id (from issue):      {org_id_from_issue}")  
                print(f"           project_id (scan_item):   {project_id}")
                print(f"           issue_id (problems[0]):   {issue_id}")
                print(f"           API URL will be: /orgs/{org_id}/issues/detail/code/{issue_id}?project_id={project_id}")
                print()
            
            if not (project_id and issue_id):
                if verbose:
                    print(f"   ⚠️  Skipping issue {i}: missing project_id or issue_id")
                skipped_count += 1
                continue
            
            # Get issue details to extract line information
            details = snyk_api.get_issue_details(org_id, project_id, issue_id, version="2022-04-06~experimental")
            if details is None:
                if verbose:
                    print(f"   ⚠️  Skipping issue {issue_id}: could not fetch details")
                skipped_count += 1
                continue
                
            # Extract line range and severity
            attrs = details.get('data', {}).get('attributes', {})
            region = attrs.get('primaryRegion', {})
            start_line = region.get('startLine')
            end_line = region.get('endLine')
            severity = attrs.get('severity', 'unknown').lower()
            
            if not (start_line and end_line):
                if verbose:
                    print(f"   ⚠️  Skipping issue {issue_id}: missing line range")
                skipped_count += 1
                continue
            
            # Calculate vulnerable lines count
            vulnerable_lines = end_line - start_line + 1
            
            # Add to appropriate severity bucket
            if severity in ['high', 'medium', 'low']:
                org_vulnerable_lines[severity] += vulnerable_lines
                org_vulnerable_lines['total'] += vulnerable_lines
            else:
                if verbose:
                    print(f"   ⚠️  Unknown severity '{severity}' for issue {issue_id}")
                skipped_count += 1
                continue
                
            processed_count += 1
            
            if verbose and processed_count <= 3:
                print(f"   ✅ Processed issue {issue_id[:8]}...: {vulnerable_lines} {severity} lines")
        
        except requests.exceptions.ConnectionError as e:
            error_count += 1
            if verbose:
                print(f"   🔌 Connection error processing issue {i}: {e}")
            # Wait longer for connection issues
            time.sleep(2)
            continue
        except requests.exceptions.Timeout as e:
            error_count += 1
            if verbose:
                print(f"   ⏰ Timeout processing issue {i}: {e}")
            # Wait longer for timeout issues
            time.sleep(3)
            continue
        except Exception as e:
            error_count += 1
            if verbose:
                print(f"   ❌ Error processing issue {i}: {e}")
            continue
    
    print(f"   ✅ Processed {processed_count} issues, skipped {skipped_count} issues, errors {error_count} issues")
    return org_vulnerable_lines


def save_org_summary_to_file(summary_data: Dict, filename: str):
    """Save organization vulnerable lines summary to a JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump(summary_data, f, indent=2)
        print(f"✅ Successfully saved organization vulnerable lines summary to {filename}")
    except Exception as e:
        print(f"❌ Error saving file: {e}")
        sys.exit(1)


def display_org_summary(summary_data: Dict, verbose: bool = False):
    """Display a summary of vulnerable lines by organization."""
    
    if not summary_data:
        print("ℹ️  No organizations with vulnerable lines found")
        return
    
    print(f"\n📊 Vulnerable Lines Summary by Organization:")
    print(f"===========================================")
    
    total_orgs = len(summary_data)
    grand_total_lines = 0
    
    for org_key, severity_counts in summary_data.items():
        total_lines = severity_counts.get('total', 0)
        grand_total_lines += total_lines
        
        print(f"\n🏢 {org_key}")
        print(f"   🔴 High: {severity_counts.get('high', 0):,} vulnerable lines")
        print(f"   🟡 Medium: {severity_counts.get('medium', 0):,} vulnerable lines")  
        print(f"   🟢 Low: {severity_counts.get('low', 0):,} vulnerable lines")
        print(f"   📊 Total: {total_lines:,} vulnerable lines")
    
    print(f"\n📈 Grand Summary:")
    print(f"   Organizations: {total_orgs}")
    print(f"   Total Vulnerable Lines: {grand_total_lines:,}")


def main():
    parser = argparse.ArgumentParser(
        description="Count vulnerable lines of code by Snyk organization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --group-id YOUR_GROUP_ID
  %(prog)s --org-id YOUR_ORG_ID
  %(prog)s --group-id YOUR_GROUP_ID --output org_vuln_lines.json
  %(prog)s --org-id YOUR_ORG_ID --verbose
  %(prog)s --org-id YOUR_ORG_ID --debug
  %(prog)s --org-id YOUR_ORG_ID --rate-limit 0.2 --timeout 120
        """
    )
    
    parser.add_argument('--group-id',
                       help='Snyk group ID (process all orgs in group)')
    parser.add_argument('--org-id',
                       help='Snyk organization ID (process single org)')
    parser.add_argument('--output',
                       help='Output JSON file to save organization summary (optional)')
    parser.add_argument('--snyk-region', default='SNYK-US-01',
                       help='Snyk API region (default: SNYK-US-01)')
    parser.add_argument('--api-version', default='2024-10-15',
                       help='Snyk API version to use (default: 2024-10-15)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed information and debug messages')
    parser.add_argument('--debug', action='store_true',
                       help='Show detailed debugging output for issue extraction')
    parser.add_argument('--rate-limit', type=float, default=0.1,
                       help='Rate limiting delay between API calls in seconds (default: 0.1)')
    parser.add_argument('--timeout', type=int, default=60,
                       help='Request timeout in seconds (default: 60)')
    
    # Add connection resilience info
    parser.add_argument('--help-resilience', action='store_true',
                       help='Show information about connection resilience features')
    
    args = parser.parse_args()
    
    # Show resilience help if requested
    if args.help_resilience:
        print("🔧 Connection Resilience Features:")
        print("=================================")
        print("• Automatic retry with exponential backoff for server errors")
        print("• Connection pooling to reuse HTTP connections")
        print("• Rate limiting to prevent overwhelming the Snyk API")
        print("• 61-second backoff when Snyk returns 429 (rate limited)")
        print("• Jitter in delays to prevent thundering herd problems")
        print("• Specific handling for connection errors and timeouts")
        print("• Configurable timeouts and rate limiting delays")
        print("\nRecommended settings for large organizations:")
        print("• --rate-limit 0.2 (200ms between requests)")
        print("• --timeout 120 (2 minutes for slow responses)")
        print("• --verbose (to see progress and error details)")
        print("\nNote: Snyk enforces 61-second backoff on 429 responses")
        print("      This is handled automatically by the script")
        sys.exit(0)
    
    # Validate arguments
    if not args.group_id and not args.org_id:
        print("❌ Error: Either --group-id or --org-id must be specified")
        parser.print_help()
        sys.exit(1)
    
    if args.group_id and args.org_id:
        print("❌ Error: Cannot specify both --group-id and --org-id. Use one or the other.")
        sys.exit(1)
    
    # Get Snyk token from environment
    snyk_token = os.environ.get('SNYK_TOKEN')
    if not snyk_token:
        print("❌ Error: SNYK_TOKEN environment variable is required")
        sys.exit(1)
    
    # Initialize Snyk API client
    print(f"🔧 Initializing Snyk API client (region: {args.snyk_region})...")
    snyk_api = SnykAPI(snyk_token, args.snyk_region)
    
    # Update timeout if specified
    if args.timeout:
        snyk_api.session.timeout = (30, args.timeout)
        print(f"   ⏱️  Request timeout set to {args.timeout} seconds")
    
    # Show rate limiting info
    if args.rate_limit > 0:
        print(f"   🐌 Rate limiting: {args.rate_limit:.3f}s between API calls")
    else:
        print(f"   ⚡ No rate limiting (not recommended for large orgs)")
    
    print(f"   🚫 Snyk 429 handling: 61-second automatic backoff")
    
    # Determine organizations to process
    orgs_to_process = []
    
    if args.group_id:
        print(f"🚀 Group mode: Fetching all organizations in group {args.group_id}...")
        all_orgs = snyk_api.get_all_orgs(args.group_id)
        print(f"✅ Found {len(all_orgs)} organizations in group")
        
        for org in all_orgs:
            org_id = org.get('id')
            org_attributes = org.get('attributes', {})
            org_slug = org_attributes.get('slug', org_id)
            if org_id:
                orgs_to_process.append({'id': org_id, 'slug': org_slug})
                if args.verbose:
                    print(f"   📋 Will process: {org_slug} ({org_id})")
    
    elif args.org_id:
        print(f"🎯 Single org mode: Processing organization {args.org_id}...")
        org_slug = snyk_api.get_org_slug(args.org_id)
        orgs_to_process.append({'id': args.org_id, 'slug': org_slug})
    
    if not orgs_to_process:
        print("❌ Error: No organizations found to process")
        sys.exit(1)
    
    # Process each organization
    print(f"\n🔎 Processing {len(orgs_to_process)} organization(s)...")
    all_org_summaries = {}
    
    for i, org_info in enumerate(orgs_to_process, 1):
        org_id = org_info['id']
        org_slug = org_info['slug']
        
        print(f"\n[{i}/{len(orgs_to_process)}] " + "="*50)
        
        # Process this organization
        org_summary = process_org_issues(snyk_api, org_id, org_slug, args.verbose, args.debug, args.rate_limit)
        
        # Create organization key: "org-slug (org-id)"
        org_key = f"{org_slug} ({org_id})"
        all_org_summaries[org_key] = org_summary
    
    # Display summary
    display_org_summary(all_org_summaries, args.verbose)
    
    # Save to file
    if args.output:
        save_org_summary_to_file(all_org_summaries, args.output)
    else:
        # Generate default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        mode = "group" if args.group_id else "org"
        default_filename = f"org_vulnerable_lines_{mode}_{timestamp}.json"
        save_org_summary_to_file(all_org_summaries, default_filename)
    
    print(f"\n🎉 Organization vulnerable lines analysis completed successfully!")


if __name__ == '__main__':
    main() 