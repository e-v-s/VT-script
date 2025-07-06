# VirusTotal IP Lookup Script

A Python script that queries VirusTotal's API to get detailed information about IP addresses, including threat intelligence, WHOIS data, and network information.

## Quickstart Guide

### Prerequisites

- Python 3.7 or higher
- VirusTotal API key (free tier available)

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd VT-script
```

### 2. Set Up Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Get VirusTotal API Key

1. Go to [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Navigate to your profile settings
4. Copy your API key

### 5. Set Environment Variable

```bash
# On macOS/Linux:
export VT_API_Key="your-api-key-here"

# On Windows:
set VT_API_Key=your-api-key-here
```

**Alternative**: Create a `.env` file in the project root:
```
VT_API_Key=your-api-key-here
```

### 6. Run the Script

```bash
python virus-total-script.py
```

When prompted, enter the IP address you want to analyze.

## What Information You'll Get

The script retrieves and displays:

- **JARM Fingerprint**: SSL/TLS server fingerprint
- **AS Owner**: Autonomous System information
- **Country**: Geographic location
- **Last HTTPS Certificate Date**: SSL certificate information
- **Last Analysis Stats**: Threat detection statistics
- **Reputation**: Community reputation score
- **Total Votes**: Community voting data
- **WHOIS Data**: Filtered registration information including:
  - Registrar
  - Organization
  - Country
  - Creation/Update dates
  - Network range
  - Administrative contacts

## 🔧 Features

- **Asynchronous API calls** for better performance
- **Filtered WHOIS data** showing only relevant fields
- **Formatted timestamps** for better readability
- **Error handling** for API failures
- **Clean output formatting** with organized results

## Example Output

```
==================================================
Resultados da Consulta no VirusTotal
==================================================
IP consultado: 8.8.8.8
--------------------------------------------------

JARM:
  • jarm: 21d19d00021d21d21c21d19d21d21d8f1d21d21d21d21d21d21d21d21d21d

AS_OWNER:
  • as_owner: GOOGLE

COUNTRY:
  • country: US

LAST_HTTPS_CERTIFICATE_DATE: 2024-01-15 10:30:00

LAST_ANALYSIS_STATS:
  • harmless: 85
  • malicious: 0
  • suspicious: 0
  • undetected: 15

REPUTATION: 0

TOTAL_VOTES:
  • harmless: 0
  • malicious: 0

WHOIS:
  • organization: Google LLC
  • country: US
  • created: 1990-01-01
  • updated: 2023-12-01
  • netrange: 8.8.8.0/24

==================================================
Consulta finalizada
==================================================
```

## Important Notes

- **API Rate Limits**: Free VirusTotal API has rate limits (4 requests per minute)
- **API Key Security**: Never commit your API key to version control
- **Data Accuracy**: Results depend on VirusTotal's database and may not be real-time

## Troubleshooting

### Common Issues

1. **"VT_API_KEY not set in environment!"**
   - Make sure you've set the environment variable correctly
   - Check that the variable name is exactly `VT_API_Key`

2. **Import errors for aiohttp**
   - Ensure you've installed dependencies: `pip install -r requirements.txt`
   - Make sure you're using the virtual environment

3. **API rate limit exceeded**
   - Wait a minute before making another request
   - Consider upgrading to a paid VirusTotal plan for higher limits


## Future improvements

- Associate it with a script for scanning URLs:
  - Generate a hash from the URL given and search for its data on URLscan.io;
  - Integrate the scan above with Falcon Sandbox.
