import os
import asyncio
import aiohttp
import datetime
import time

# API key from virus total is needed to use the API
api_key = os.environ.get("VT_API_Key")

# If there is no API key on environment, raise an error
if not api_key:
  raise RuntimeError("VT_API_KEY não está configurada!")

print("""
        ฅ^•ﻌ•^ฅ
        Virus Total IP Lookup Script
        By Evs
""")

# Ask for the IP to be looked up
ip = input("IP para consulta: ")

# Async function to get the IP addr info from VirusTotal
async def getIP(ip, api_key):
  # API endpoint to get the IP addr info
  url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
  # HTTP headers to authenticate the request using the API key
  headers = {
    "accept": "application/json",
    "x-apikey": api_key
  }
  # Open async session using aiohttp
  async with aiohttp.ClientSession() as session:
    # Request the data from the API
    async with session.get(url, headers=headers) as response:
      # Raise an error if the request is not successful	
      response.raise_for_status()
      # Get the response data
      data = await response.json()
  
  # Return the data fetched from the API
  return data

# Filter the WHOIS data, with only the important fields
def filter_whois_data(whois_data):
  # If WHOIS is an integer, it's probably not the actual WHOIS data
  if isinstance(whois_data, int):
    return f"WHOIS ID/Timestamp: {whois_data} (dados completos não disponíveis)"
    
  # If there is no WHOIS data, return a message
  if not whois_data:
    return "Não existem dados de WHOIS"
    
  # Define the important fields to be extracted from the WHOIS data
  important_fields = [
    'registrar', 'organization', 'org', 'netname', 'descr',
    'country', 'admin-c', 'tech-c', 'mnt-by', 'created',
    'updated', 'status', 'inetnum', 'netrange'
  ]

  # Create a dict to store the data from important_fields
  filtered_data = {}
    
  # If whois_data is a string, parse it line by line
  if isinstance(whois_data, str):
    lines = whois_data.split('\n')
    for line in lines:
      line = line.strip()
      if ':' in line:
        key, value = line.split(':', 1)
        key = key.strip().lower()
        value = value.strip()
                
        # Check if this field is important, and if so, add it to the filtered_data dict
        for field in important_fields:
          if field in key:
            filtered_data[key] = value
            break
    
  # Else, if whois_data is already a dictionary, add the important fields to the filtered_data dict
  elif isinstance(whois_data, dict):
    for key, value in whois_data.items():
      key_lower = key.lower()
      for field in important_fields:
        if field in key_lower:
          filtered_data[key] = value
          break

  # If there is no important fields found, return a message
  return filtered_data if filtered_data else "Não existem campos importantes de WHOIS"

# Format the timestamp to a readable date format
def format_timestamp(timestamp):
  # If the timestamp is valid, format it to a readable date format
  try:
    if timestamp:
      # Convert the timestamp to a datetime object
      return datetime.datetime.fromtimestamp(timestamp, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S')
    else:
      return "N/A"
  except (ValueError, TypeError):
    return "Invalid timestamp"

# ----------------------------------------------------------------------

# Main function that runs the script
async def main():
  print("=" * 50)
  print("Resultados da Consulta no VirusTotal")
  print("=" * 50)
  print(f"IP consultado: {ip}")
  print("-" * 50)
  
  # Get basic IP information
  print("Buscando informações básicas do IP...")
  result = await getIP(ip, api_key)
  
  # Terms to be searched in result (including whois for main response)
  search_terms = [
    'jarm', 'as_owner', 'country', 'last_https_certificate_date', 'last_analysis_stats', 'reputation', 'total_votes', 'whois'
  ]

  # Function to search the terms of search_terms in result
  def search_fields(data, search_terms):
    # Dict to store the found fields
    found_fields = {}
    
    # Function to search the terms recursively in the result
    def search_recursive(obj, path=""):
      if isinstance(obj, dict):
        for key, value in obj.items():
          current_path = f"{path}.{key}" if path else key
                
          # Check if the key matches any search term
          for term in search_terms:
            if term.lower() in key.lower():
              found_fields[term] = value
              break
                
          # Continue searching recursively
          search_recursive(value, current_path)
      elif isinstance(obj, list):
        for i, item in enumerate(obj):
          current_path = f"{path}[{i}]"
          search_recursive(item, current_path)
    
    search_recursive(data)
    return found_fields

  # Get basic data including WHOIS from main response
  found_data = search_fields(result, search_terms)
  
  # Check if WHOIS is in the main response
  whois_from_main = found_data.get('whois')
  
  # Also check for other possible WHOIS-related fields
  whois_related_fields = [
    'whois_data', 'whois_info', 'whois_details', 'registration', 
    'whois_text', 'whois_raw', 'whois_content', 'whois_string',
    'registrar', 'organization', 'org', 'netname', 'descr',
    'country', 'admin-c', 'tech-c', 'mnt-by', 'created',
    'updated', 'status', 'inetnum', 'netrange'
  ]
  whois_alternative = None
  for field in whois_related_fields:
    if field in found_data:
      whois_alternative = found_data[field]
      break
  
  # Remove whois from search_terms for display
  display_terms = [term for term in search_terms if term != 'whois']

  # Display basic information first
  for term in display_terms:
    if term in found_data:
      value = found_data[term]
          
      # Special handling for timestamp fields
      if term == 'last_https_certificate_date':
        formatted_date = format_timestamp(value)
        print(f"{term.upper()}: {formatted_date}")
          
      # Format different types of data for other fields
      elif isinstance(value, dict):
        print(f"{term.upper()}:")
        for key, val in value.items():
          print(f"  • {key}: {val}")
      elif isinstance(value, list):
        print(f"{term.upper()}:")
        for item in value:
          print(f"  • {item}")
      else:
        print(f"{term.upper()}: {value}")
    else:
      print(f"{term.upper()}: Não encontrado")
      
    print()  # Add spacing between fields

  # Handle WHOIS data
  print("WHOIS:")
  whois_data = None
  
  # First try to get WHOIS from main response
  if whois_from_main:
    # Check if it's actual WHOIS data or just a timestamp/ID
    if isinstance(whois_from_main, (str, dict)) and whois_from_main:
      whois_data = whois_from_main
  
  # Try alternative WHOIS fields
  if not whois_data and whois_alternative:
    whois_data = whois_alternative
  
  # If no WHOIS data found, wait and try again (VirusTotal might need time to process)
  if not whois_data:
    print("  Aguardando processamento dos dados de WHOIS...")
    
    # Try multiple times with increasing delays
    for attempt in range(3):
      await asyncio.sleep(3)  # Wait 3 seconds between attempts
      
      try:
        fresh_result = await getIP(ip, api_key)
        fresh_data = search_fields(fresh_result, search_terms)
        
        # Check for WHOIS in fresh data
        fresh_whois = fresh_data.get('whois')
        if fresh_whois and isinstance(fresh_whois, (str, dict)) and fresh_whois:
          whois_data = fresh_whois
          break
        else:
          # Try alternative fields in fresh data
          for field in whois_related_fields:
            if field in fresh_data:
              whois_data = fresh_data[field]
              break
          if whois_data:
            break
      except Exception as e:
        print(f"  Erro na tentativa {attempt + 1}: {e}")
        continue
  
  # Display WHOIS data
  if whois_data:
    filtered_whois = filter_whois_data(whois_data)
    
    if isinstance(filtered_whois, dict):
      for key, val in filtered_whois.items():
        print(f"  • {key}: {val}")
    else:
      print(f"  {filtered_whois}")
  else:
    print("  Dados de WHOIS não disponíveis")
  
  print()
  print("=" * 50)
  print("Consulta finalizada")
  print("=" * 50)

asyncio.run(main())
