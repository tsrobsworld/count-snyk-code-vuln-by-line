# Snyk Organization Vulnerable Lines Counter

This tool counts vulnerable lines of code by Snyk organization and severity level. It can operate in two modes:

- **Group Mode**: Process all organizations within a Snyk group
- **Single Org Mode**: Process just one specific organization

For each organization, it calculates the total number of vulnerable lines (based on issue line ranges) grouped by severity level.

## Features

- **Dual Processing Modes**: Group-level (all orgs) or single organization
- Count vulnerable lines of code by Snyk organization
- Group results by severity level (high, medium, low)
- Support for different Snyk regions
- Verbose mode for detailed processing information
- Export to JSON format with optional custom filename

## Prerequisites

1. **Snyk API Token**: You need a Snyk API token with appropriate permissions
2. **Group ID or Org ID**: Your Snyk group ID (for group mode) or organization ID (for single org mode)
3. **Python 3.6+**: The script requires Python 3.6 or higher

## Installation

1. Clone or download the script files
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Set up your environment variables:

```bash
export SNYK_TOKEN="your-snyk-api-token"
```

## Usage

### Group Mode (Process All Organizations in Group)

Count vulnerable lines for all organizations in a group:
```bash
python3 collect_snyk_issues.py --group-id YOUR_GROUP_ID
```

Save group results to a custom file:
```bash
python3 collect_snyk_issues.py --group-id YOUR_GROUP_ID --output group_summary.json
```

### Single Organization Mode

Count vulnerable lines for a specific organization:
```bash
python3 collect_snyk_issues.py --org-id YOUR_ORG_ID
```

Save single org results to a custom file:
```bash
python3 collect_snyk_issues.py --org-id YOUR_ORG_ID --output single_org_summary.json
```

### Advanced Usage

Run with verbose output (either mode):
```bash
python3 collect_snyk_issues.py --group-id YOUR_GROUP_ID --verbose
python3 collect_snyk_issues.py --org-id YOUR_ORG_ID --verbose
```

Use different Snyk region:
```bash
python3 collect_snyk_issues.py --group-id YOUR_GROUP_ID --snyk-region SNYK-EU-01
```

### Command Line Options

- `--group-id`: Snyk group ID (process all orgs in group)
- `--org-id`: Snyk organization ID (process single org)
- `--output`: Output JSON file (optional, defaults to timestamped filename)
- `--snyk-region`: Snyk API region (default: SNYK-US-01)
- `--api-version`: Snyk API version (default: 2024-10-14)
- `--verbose, -v`: Show detailed processing information

**Note**: You must specify either `--group-id` OR `--org-id`, but not both.

### Supported Regions

- `SNYK-US-01`: US East (default)
- `SNYK-US-02`: US West
- `SNYK-EU-01`: Europe
- `SNYK-AU-01`: Australia

## Output

The script provides:

1. **Console Summary**: Vulnerable lines count by organization and severity
2. **JSON Export**: Complete organization summary in JSON format

### Sample Output - Group Mode

```
🔧 Initializing Snyk API client (region: SNYK-US-01)...
🚀 Group mode: Fetching all organizations in group 12345678...
✅ Found 3 organizations in group

🔎 Processing 3 organization(s)...

[1/3] ==================================================
🔍 Processing organization: my-company-org (org-12345)
   📋 Found 150 code issues
   ✅ Processed 145 issues, skipped 5 issues

[2/3] ==================================================
🔍 Processing organization: dev-team-org (org-67890)
   📋 Found 45 code issues
   ✅ Processed 42 issues, skipped 3 issues

[3/3] ==================================================
🔍 Processing organization: qa-team-org (org-11111)
   📋 Found 20 code issues
   ✅ Processed 18 issues, skipped 2 issues

📊 Vulnerable Lines Summary by Organization:
===========================================

🏢 my-company-org (org-12345)
   🔴 High: 1,250 vulnerable lines
   🟡 Medium: 3,400 vulnerable lines
   🟢 Low: 890 vulnerable lines
   📊 Total: 5,540 vulnerable lines

🏢 dev-team-org (org-67890)
   🔴 High: 45 vulnerable lines
   🟡 Medium: 120 vulnerable lines
   🟢 Low: 30 vulnerable lines
   📊 Total: 195 vulnerable lines

🏢 qa-team-org (org-11111)
   🔴 High: 12 vulnerable lines
   🟡 Medium: 25 vulnerable lines
   🟢 Low: 8 vulnerable lines
   📊 Total: 45 vulnerable lines

📈 Grand Summary:
   Organizations: 3
   Total Vulnerable Lines: 5,780

✅ Successfully saved organization vulnerable lines summary to org_vulnerable_lines_group_20241201_143022.json

🎉 Organization vulnerable lines analysis completed successfully!
```

### Sample Output - Single Org Mode

```
🔧 Initializing Snyk API client (region: SNYK-US-01)...
🎯 Single org mode: Processing organization org-12345...

🔎 Processing 1 organization(s)...

[1/1] ==================================================
🔍 Processing organization: my-company-org (org-12345)
   📋 Found 150 code issues
   ✅ Processed 145 issues, skipped 5 issues

📊 Vulnerable Lines Summary by Organization:
===========================================

🏢 my-company-org (org-12345)
   🔴 High: 1,250 vulnerable lines
   🟡 Medium: 3,400 vulnerable lines
   🟢 Low: 890 vulnerable lines
   📊 Total: 5,540 vulnerable lines

📈 Grand Summary:
   Organizations: 1
   Total Vulnerable Lines: 5,540

✅ Successfully saved organization vulnerable lines summary to org_vulnerable_lines_org_20241201_143022.json

🎉 Organization vulnerable lines analysis completed successfully!
```

### JSON Output Format

```json
{
  "my-company-org (org-12345)": {
    "high": 1250,
    "medium": 3400,
    "low": 890,
    "total": 5540
  },
  "dev-team-org (org-67890)": {
    "high": 45,
    "medium": 120,
    "low": 30,
    "total": 195
  }
}
```

## How It Works

### Group Mode
1. **Fetches Organizations**: Gets all organizations within the specified group
2. **Processes Each Org**: For each org, fetches all code issues
3. **Gets Issue Details**: Retrieves detailed information for each issue including line ranges
4. **Counts Vulnerable Lines**: Calculates `(endLine - startLine + 1)` for each issue
5. **Categorizes by Severity**: Separates counts into high, medium, and low severity buckets
6. **Aggregates Results**: Combines all organization summaries into final report

### Single Org Mode
1. **Processes One Org**: Fetches all code issues for the specified organization
2. **Gets Issue Details**: Retrieves detailed information for each issue including line ranges
3. **Counts Vulnerable Lines**: Calculates `(endLine - startLine + 1)` for each issue
4. **Categorizes by Severity**: Separates counts into high, medium, and low severity buckets

### Debug Mode

For troubleshooting, use the verbose flag:
```bash
# Group mode debugging
python3 collect_snyk_issues.py --group-id YOUR_GROUP_ID --verbose

# Single org mode debugging
python3 collect_snyk_issues.py --org-id YOUR_ORG_ID --verbose
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2024 vuln-count-by-line contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. 