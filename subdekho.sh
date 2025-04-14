#!/bin/bash
# Usage: ./recon.sh example.com

domain=$1

echo "🔍 Starting subdomain enumeration for: $domain"

# Step 1: Amass
echo "[*] Running Amass (passive)..."
amass enum --passive -d "$domain" -o amass_$domain.txt
echo "[+] Amass done. Results saved in amass_$domain.txt"

# Step 2: Assetfinder
echo "[*] Running Assetfinder..."
assetfinder --subs-only "$domain" > assetfinder_$domain.txt
echo "[+] Assetfinder done. Results saved in assetfinder_$domain.txt"

# Step 3: Subfinder
echo "[*] Running Subfinder..."
subfinder -d "$domain" -o subfinder_$domain.txt
echo "[+] Subfinder done. Results saved in subfinder_$domain.txt"

# Step 4: Combine all results
echo "[*] Combining and de-duplicating all subdomains..."
cat amass_"$domain".txt assetfinder_"$domain".txt subfinder_"$domain".txt | sort -u > all_subs_"$domain".txt
echo "[+] Combined subdomains saved in all_subs_$domain.txt"

# Step 5: Filter resolvable subdomains
echo "[*] Filtering resolvable subdomains using dnsx..."
cat all_subs_"$domain".txt | dnsx -silent > resolved_"$domain".txt
echo "[+] Resolved subdomains saved in resolved_$domain.txt"

# Final Output
echo "✅ Recon complete. Found $(wc -l < resolved_"$domain".txt) live subdomains:"
cat resolved_"$domain".txt
