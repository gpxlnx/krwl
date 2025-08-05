#!/bin/bash

# Load configuration and API keys
if [ -f "./config.txt" ]; then
  source ./config.txt
else
  echo -e "\e[31m[!] config.txt not found. Exiting...\e[0m"
  exit 1
fi

BOLD='\e[1m'
UNDERLINE='\e[4m'
RED='\e[31m'
GREEN='\e[32m'
BLUE='\e[34m'
YELLOW='\e[33m'
CYAN='\e[36m'
MAGENTA='\e[35m'
NC='\e[0m' # No Color

# ReconX00 - Recon Script for Bug Bounty (by @3$H4N$H)
# Usage: ./reconx00.sh -d domain.com

while getopts ":d:" input; do
  case "$input" in
    d) domain=${OPTARG} ;;
  esac
done

if [ -z "$domain" ]; then
  echo "Usage: $0 -d domain.com"
  exit 1
fi

### Setup
mkdir -p "$domain"
cd "$domain" || exit
echo "Running recon for: $domain"

echo -e "${MAGENTA}[*] Creating tmp Directory ${NC}"
mkdir -p tmp

### Passive Subdomain Enumeration
echo -e "${CYAN}[*] Starting Passive Enumeration...${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using URLSCAN ${NC}"
curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain" | egrep "domain|$domain" | sort -u > tmp/urlscanio_raw
grep -oE "[a-zA-Z0-9.-]+\\.$domain" tmp/urlscanio_raw | anew tmp/urlscanio.txt
echo -e "${GREEN}[+] Subdomains found by urlscanio: $(wc -l < tmp/urlscanio.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using CERTSPOTTER ${NC}"
curl -s "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -o "[a-zA-Z0-9.-]*\.$domain" | sort -u > tmp/certspotter.txt
echo -e "${GREEN}[+] Subdomains found by certspotter: $(wc -l < tmp/certspotter.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using CERTSH ${NC}"
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.\?//g' | sort -u | grep "$domain" > tmp/cert.txt
echo -e "${GREEN}[+] Subdomains found by cert.sh: $(wc -l < tmp/cert.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using TREATCROWD ${NC}"
curl -s "http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | jq -r '.subdomains[]' | grep "$domain" > tmp/threatcrowd.txt
echo -e "${GREEN}[+] Subdomains found by threatcrowd: $(wc -l < tmp/threatcrowd.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using HACKTARGET ${NC}"
curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep "$domain" > tmp/hacktarget.txt
echo -e "${GREEN}[+] Subdomains found by hacktarget: $(wc -l < tmp/hacktarget.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using ALIENVAULT ${NC}"
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/url_list?limit=100&page=1" | grep -o '"hostname": *"[^"]*' | cut -d'"' -f4 > tmp/alienvault.txt
echo -e "${GREEN}[+] Subdomains found by alienvault: $(wc -l < tmp/alienvault.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using CERO ${NC}"
cero "$domain" | anew tmp/cero.txt
echo -e "${GREEN}[+] Subdomains found by cero: $(wc -l < tmp/cero.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using ASSETFINDER ${NC}"
assetfinder --subs-only "$domain" | anew tmp/assetfinder.txt
echo -e "${GREEN}[+] Subdomains found by assetfinder: $(wc -l < tmp/assetfinder.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using SUBFINDER ${NC}"
subfinder -d "$domain" -silent > tmp/subfinder.txt
echo -e "${GREEN}[+] Subdomains found by subfinder: $(wc -l < tmp/subfinder.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using SHOSUBGO ${NC}"
shosubgo -d "$domain" -s "$SHODAN_API_KEY" > tmp/shosubgo.txt
echo -e "${GREEN}[+] Subdomains found by shosubgo: $(wc -l < tmp/shosubgo.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using GITHUB-SUBDOMAIN ${NC}"
github-subdomains -d "$domain" -t "$GITHUB_TOKEN" -o tmp/github-subdomain.txt
echo -e "${GREEN}[+] Subdomains found by github: $(wc -l < tmp/github-subdomain.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using GITLAB-SUBDOMAIN ${NC}"
gitlab-subdomains -d "$domain" -t "$GITLAB_TOKEN" > tmp/gitlab-subdomain.txt
echo -e "${GREEN}[+] Subdomains found by gitlab: $(wc -l < tmp/gitlab-subdomain.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using CHAOS ${NC}"
chaos -d "$domain" -key "$CHAOS_API_KEY" > tmp/chaos.txt
echo -e "${GREEN}[+] Subdomains found by chaos: $(wc -l < tmp/chaos.txt)${NC}"

echo -e "${YELLOW}[*] Starting Passive Enumeration Using AMASS ${NC}"
amass enum -passive -d "$domain" -v | anew tmp/amass.txt
cat tmp/amass.txt | grep -oP '\S+(?= \(FQDN\))' | anew tmp/amass-fdqn.txt
echo -e "${GREEN}[+] Subdomains found by amass: $(wc -l < tmp/amass-fdqn.txt)${NC}"

echo -e "${MAGENTA}[*] Creating juicy Directory ${NC}"
mkdir -p juicy

cat tmp/urlscanio.txt tmp/certspotter.txt tmp/cert.txt tmp/threatcrowd.txt tmp/hacktarget.txt tmp/alienvault.txt tmp/cero.txt tmp/assetfinder.txt tmp/subfinder.txt tmp/shosubgo.txt tmp/github-subdomain.txt tmp/gitlab-subdomain.txt tmp/chaos.txt tmp/amass-fdqn.txt | grep "$domain" | anew juicy/subdomains.txt
echo -e "${BLUE}[✓] After Combining All Subdomains Found: $(wc -l < juicy/subdomains.txt)${NC}"

### Internet Archive Enumeration
echo -e "${CYAN}[*] Starting Internet Archive Scrapping ${NC}"

echo -e "${YELLOW}[*] Starting Archieving Wayback Data From WAYBACKURLS ${NC}"
waybackurls "$domain" | anew tmp/waybackurls_raw.txt
echo -e "${GREEN}[+] Waybackurls Found: $(wc -l < tmp/waybackurls_raw.txt)"

echo -e "${YELLOW}[*] Starting Archieving Wayback Data From GAU ${NC}"
gau "$domain" | anew tmp/gau_raw.txt
echo -e "${GREEN}[+] GAU Found: $(wc -l < tmp/gau_raw.txt)"

### HTTP Probing
echo -e "${CYAN}[*] Starting HTTP Probing ${NC}"

echo -e "${YELLOW}[*] Starting HTTP Probing For Collected Subdomains Using HTTPROBE ${NC}"
cat juicy/subdomains.txt | httprobe | grep "$domain" | anew juicy/probed-subdomains.txt
echo -e "${BLUE}[✓] After Probing Subdomains Found: $(wc -l < juicy/probed-subdomains.txt)${NC}"

### Crawling-Based Enumeration
echo -e "${CYAN}[*] Starting Crawling-Based Enumeration...${NC}"

echo -e "${YELLOW}[*] Starting Crawling Using Hakrawler...${NC}"
cat juicy/probed-subdomains.txt | hakrawler | grep "$domain" | anew tmp/hakrawler_raw.txt
echo -e "${GREEN}[+] Hakrawler Found: $(wc -l < tmp/hakrawler_raw.txt)"

echo -e "${YELLOW}[*] Starting Crawling Using Katana...${NC}"
cat juicy/probed-subdomains.txt | katana | grep "$domain" | anew tmp/katana_raw.txt
echo -e "${GREEN}[+] Katana Found: $(wc -l < tmp/katana_raw.txt)"

echo -e "${YELLOW}[*] Starting Crawling Using Gospider...${NC}"
gospider -S juicy/probed-subdomains.txt -d 10 -c 20 -t 50 -K 3 --no-redirect --js -a -w --blacklist ".(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt)" --include-subs -q -o gospider 2> /dev/null | anew -q tmp/gospider_raw.txt
echo -e "${GREEN}[+] Gospider Found: $(wc -l < tmp/gospider_raw.txt)"

echo -e "${YELLOW}[*] Starting Merging Crawled Passive Data ${NC}"
cat tmp/waybackurls_raw.txt tmp/gau_raw.txt tmp/hakrawler_raw.txt tmp/katana_raw.txt tmp/gospider_raw.txt | anew juicy/passive_raw.txt
echo -e "${BLUE}[✓] After Combining Passive Data Found: $(wc -l < juicy/passive_raw.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scrapping Subdomains From Crawled Data ${NC}"
cat juicy/passive_raw.txt | unfurl domains | sort | uniq | grep "$domain" | anew tmp/crawled_subdomains.txt
echo -e "${BLUE}[✓] From Crawling Subdomains Found: $(wc -l < tmp/crawled_subdomains.txt)${NC}"

echo -e "${YELLOW}[*] Starting Merging Crawled-Subdomains Data ${NC}"
cat juicy/subdomains.txt tmp/crawled_subdomains.txt | anew juicy/subdomains.txt

echo -e "${YELLOW}[*] Starting Scrapping for JavaScript Files Data ${NC}"
cat juicy/passive_raw.txt | grep '\.js$' | httpx -mc 200 -no-color | anew juicy/js.txt
echo -e "${BLUE}[✓] From Scrapping JavaScript Files Found: $(wc -l < juicy/js.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scrapping for JSON Files Data ${NC}"
cat juicy/passive_raw.txt | grep '\.json$' | httpx -mc 200 -no-color | anew juicy/json.txt
echo -e "${BLUE}[✓] From Scrapping JSON Files Found: $(wc -l < juicy/json.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scrapping for PDF Files Data ${NC}"
cat juicy/passive_raw.txt | grep '\.pdf$' | httpx -mc 200 -no-color | anew juicy/pdf.txt
echo -e "${BLUE}[✓] From Scrapping PDF Files Found: $(wc -l < juicy/pdf.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scrapping for Node_Modules Files Data ${NC}"
grep -E '/node_modules/.+\.js' passive_raw.txt | httpx -mc 200 -no-color | anew juicy/node_modules.txt
echo -e "${BLUE}[✓] From Scrapping Node_Modules Files Found: $(wc -l < juicy/node_modules.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scrapping for PDF Files Data ${NC}"
cat juicy/passive_raw.txt | grep 'robots.txt' | httpx -mc 200 -no-color | anew juicy/robots.txt
echo -e "${BLUE}[✓] From Scrapping PDF Files Found: $(wc -l < juicy/pdf.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scrapping for Useful Files Data ${NC}"
cat juicy/passive_raw.txt | grep -iaE "([^.]+)\.zip$|([^.]+)\.zip\.[0-9]+$|([^.]+)\.zip[0-9]+$|([^.]+)\.zip[a-z][A-Z][0-9]+$|([^.]+)\.zip\.[a-z][A-Z][0-9]+$|([^.]+)\.rar$|([^.]+)\.tar$|([^.]+)\.tar\.gz$|([^.]+)\.tgz$|([^.]+)\.sql$|([^.]+)\.db$|([^.]+)\.sqlite$|([^.]+)\.pgsql\.txt$|([^.]+)\.mysql\.txt$|([^.]+)\.gz$|([^.]+)\.config$|([^.]+)\.log$|([^.]+)\.bak$|([^.]+)\.backup$|([^.]+)\.bkp$|([^.]+)\.crt$|([^.]+)\.dat$|([^.]+)\.eml$|([^.]+)\.java$|([^.]+)\.lst$|([^.]+)\.key$|([^.]+)\.passwd$|([^.]+)\.pl$|([^.]+)\.pwd$|([^.]+)\.mysql-connect$|([^.]+)\.jar$|([^.]+)\.cfg$|([^.]+)\.dir$|([^.]+)\.orig$|([^.]+)\.bz2$|([^.]+)\.old$|([^.]+)\.vbs$|([^.]+)\.inf$|([^.]+)\.sh$|([^.]+)\.py$|([^.]+)\.vbproj$|([^.]+)\.mysql-pconnect$|([^.]+)\.war$|([^.]+)\.go$|([^.]+)\.psql$|([^.]+)\.sql\.gz$|([^.]+)\.vb$|([^.]+)\.webinfo$|([^.]+)\.jnlp$|([^.]+)\.cgi$|([^.]+)\.tmp$|([^.]+)\.ini$|([^.]+)\.webproj$|([^.]+)\.xsql$|([^.]+)\.raw$|([^.]+)\.inc$|([^.]+)\.lck$|([^.]+)\.nz$|([^.]+)\.rc$|([^.]+)\.html\.gz$|([^.]+)\.gz$|([^.]+)\.env$|([^.]+)\.git$|([^.]+)\.yml$|([^.]+)\.asp$|([^.]+)\.aspx$|([^.]+)\.jsp$|([^.]+)\.jspf$|([^.]+)\.jspa$|([^.]+)\.php$|([^.]+)\.php3$|([^.]+)\.php5$|([^.]+)\.phpbb$|([^.]+)\.phpt$|([^.]+)\.phps$|([^.]+)\.rb$|([^.]+)\.do$|([^.]+)\.dll$|([^.]+)\.mdb$|([^.]+)\.mdf$|([^.]+)\.xml$|([^.]+)\.ascx$|([^.]+)\.c$|([^.]+)\.cfm$|([^.]+)\.cpp$|([^.]+)\.swf$|([^.]+)\.tpl$|([^.]+)\.vb$|([^.]+)\.wsdl$|([^.]+)\.action$ |([^.]+)\.conf$|([^.]+)\.htaccess$ |([^.]+)\.properties$|([^.]+)\.ascx$|([^.]+)\.resx$|([^.]+)\.csproj$|([^.]+)\.pdb$|([^.]+)\.sln$|([^.]+)\.vbproj$ " | httpx -mc 200 -no-color | anew juicy/useful.txt
echo -e "${BLUE}[✓] From Scrapping Useful Files Found: $(wc -l < juicy/useful.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scrapping for URLFuzzing Files Data ${NC}"
cat juicy/passive_raw.txt | grep -Ev '\.js$|\.json$|\.pdf$|\.css$' | grep -E '\?.+=.+' | httpx -mc 200 -no-color | anew juicy/forURLfuzz.txt
echo -e "${BLUE}[✓] From Scrapping URLFuzzing Files Found: $(wc -l < juicy/forURLfuzz.txt)${NC}"

### Wordlist Creation From Passive Data

echo -e "${MAGENTA}[*] Creating Wordlist Directory ${NC}"
mkdir -p wordlists

echo -e "${CYAN}[*] Starting Wordlist Creation From Passive Data...${NC}"

echo -e "${YELLOW}[*] Starting Extracting Paths From Crawled Passive Data ${NC}"
cat juicy/passive_raw.txt | unfurl paths | sort -u > wordlists/paths.txt
echo -e "${GREEN}[+] Paths Found: $(wc -l < wordlists/paths.txt)${NC}"

echo -e "${YELLOW}[*] Starting Extracting Parameter Names From Crawled Passive Data ${NC}"
cat juicy/passive_raw.txt | unfurl keys | sort -u > wordlists/parameters.txt
echo -e "${GREEN}[+] Parameters Found: $(wc -l < wordlists/parameters.txt)${NC}"

echo -e "${YELLOW}[*] Starting Extracting Values From Crawled Passive Data ${NC}"
cat juicy/passive_raw.txt | unfurl values | sort -u > wordlists/values.txt
echo -e "${GREEN}[+] Values Found: $(wc -l < wordlists/values.txt)${NC}"

echo -e "${YELLOW}[*] Starting Extracting key=value Pairs From Crawled Passive Data ${NC}"
cat juicy/passive_raw.txt | unfurl keypairs | sort -u > wordlists/param-values.txt
echo -e "${GREEN}[+] Key=Value Found: $(wc -l < wordlists/param-values.txt)${NC}"

### HTTP Filtering
echo -e "${CYAN}[*] Starting HTTP Filtering Using HTTPx... ${NC}"

echo -e "${YELLOW}[*] Starting HTTP Filtering For 2xx Status Codes ${NC}"
cat juicy/subdomains.txt | httpx -mc 200,201,202,203,204,205,206,207,208,209 | anew juicy/2xx.txt
echo -e "${GREEN}[+] HTTPx Found Status Code 2xx: $(wc -l < juicy/2xx.txt)${NC}" 

echo -e "${YELLOW}[*] Starting HTTP Filtering For 3xx Status Codes ${NC}"
cat juicy/subdomains.txt | httpx -mc 300,301,302,303,304,305,306,307,308,309 | anew juicy/3xx.txt
echo -e "${GREEN}[+] HTTPx Found Status Code 3xx: $(wc -l < juicy/3xx.txt)${NC}"

echo -e "${YELLOW}[*] Starting HTTP Filtering For 400 Status Codes ${NC}"
cat juicy/subdomains.txt | httpx -mc 400 | anew juicy/400.txt
echo -e "${GREEN}[+] HTTPx Found Status Code 400: $(wc -l < juicy/400.txt)${NC}"

echo -e "${YELLOW}[*] Starting HTTP Filtering For 401 Status Codes ${NC}"
cat juicy/subdomains.txt | httpx -mc 401 | anew juicy/401.txt
echo -e "${GREEN}[+] HTTPx Found Status Code 401: $(wc -l < juicy/401.txt)${NC}"

echo -e "${YELLOW}[*] Starting HTTP Filtering For 403 Status Codes ${NC}"
cat juicy/subdomains.txt | httpx -mc 403 | anew juicy/403.txt
echo -e "${GREEN}[+] HTTPx Found Status Code 403: $(wc -l < juicy/403.txt)${NC}"

echo -e "${YELLOW}[*] Starting HTTP Filtering For 404 Status Codes ${NC}"
cat juicy/subdomains.txt | httpx -mc 404 | anew juicy/404.txt
echo -e "${GREEN}[+] HTTPx Found Status Code 404: $(wc -l < juicy/404.txt)${NC}"

echo -e "${YELLOW}[*] Starting HTTP Filtering For 429 Status Codes ${NC}"
cat juicy/subdomains.txt | httpx -mc 429 | anew juicy/429.txt
echo -e "${GREEN}[+] HTTPx Found Status Code 429: $(wc -l < juicy/429.txt)${NC}"

echo -e "${YELLOW}[*] Starting HTTP Filtering For IP Addresses ${NC}"
cat juicy/subdomains.txt | httpx -ip | anew tmp/ip_raw.txt
cat tmp/ip_raw.txt | grep -oE '\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]' | tr -d '[]' | anew juicy/ip.txt
echo -e "${GREEN}[+] HTTPx Found IPs from Subdomains: $(wc -l < juicy/ip.txt)${NC}"
cat tmp/amass.txt  | grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' | anew tmp/amass-ipv4.txt
echo -e "${GREEN}[+] Amass Found IPs : $(wc -l < tmp/amass-ipv4.txt)${NC}"
grep -oP '([a-fA-F0-9:]{2,39})(?= \(IPAddress\))' tmp/amass.txt | grep -P '([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}' | anew tmp/amass-ipv6.txt
echo -e "${GREEN}[+] Amass Found IPs : $(wc -l < tmp/amass-ipv6.txt)${NC}"
cat juicy/ip.txt tmp/amass-ipv4.txt tmp/amass-ipv6.txt | anew juicy/ip.txt
echo -e "${BLUE}[✓] After Combining Total IPs Found: $(wc -l < juicy/ip.txt)${NC}"

### Ports Scanning
echo -e "${CYAN}[*] Starting Mass Port Scanning... ${NC}"

echo -e "${YELLOW}[*] Starting Shodan Port Mapping Using SMAP ${NC}"
smap -iL juicy/ip.txt | tee juicy/smap.txt

#echo -e "${YELLOW}[*] Starting Naabu + Nmap Port Mapping Output in naabu_with_nmap.txt ${NC}"
#naabu -l juicy/ip.txt -p 0-65535 -o juicy/naabu_with_nmap.txt

### JS Leaks Finder
echo -e "${CYAN}[*] Starting Scrapping Secrets From JavaScript Files... ${NC}"

echo -e "${MAGENTA}[*] Creating secrets Directory ${NC}"
mkdir -p secrets

echo -e "${YELLOW}[*] Starting Scraping GitLeaks From JavaScripts Files ${NC}"
cat juicy/js.txt | jsleak  -t "./secrets-patterns-db/datasets/git-leaks.yml" -s | anew secrets/js-git-leaks.txt
echo -e "${GREEN}[+] GitLeaks Found From JavaScript: $(wc -l < secrets/js-git-leaks.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scraping MetaData From JavaScripts Files ${NC}"
cat juicy/js.txt | jsleak  -t "../secrets-patterns-db/datasets/high-confidence.yml" -s | anew secrets/js-metadata.txt
echo -e "${GREEN}[+] MetaData Found From JavaScript: $(wc -l < secrets/js-metadata.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scraping Leaks From JavaScripts Files ${NC}"
cat juicy/js.txt | jsleak  -t "../secrets-patterns-db/datasets/leakin-regexes.yml" -s | anew secrets/js-leaked.txt
echo -e "${GREEN}[+] Leaks Found From JavaScript: $(wc -l < secrets/js-leaked.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scraping Regexes From JavaScripts Files ${NC}"
cat juicy/js.txt | jsleak  -t "../secrets-patterns-db/datasets/nuclei-regexes.yml" -s | anew secrets/js-regexes.txt
echo -e "${GREEN}[+] Regexes Found From JavaScript: $(wc -l < secrets/js-leaked.txt)${NC}"

echo -e "${YELLOW}[*] Starting Scraping Trufflehog-Secrets From JavaScripts Files ${NC}"
cat juicy/js.txt | jsleak  -t "../secrets-patterns-db/datasets/trufflehog-v3.yml" -s | anew secrets/js-trufflehog.txt
echo -e "${GREEN}[+] Trufflehog-Secrets Found From JavaScript: $(wc -l < secrets/js-leaked.txt)${NC}"


echo "[✔] Recon Complete! Results of $domain"
