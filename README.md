# Tools
My personal one-liner and tools

## ForbiddenStrike
  - forbiddenstrike -d target.com 
  - This will find all subdomains on the target
  - Then it will use httpx and probe all the subdomains that give 403/401
  - Then will run the omni403 script to find any bypass
  - Cloudflare Bypass: forbiddenStrike -d roboform.com -fs 610,92 -t 5 -j 1.5
### Simple Flow yet very effective to find low-hanging fruit


## JwtPWN.py
  - python3 JwtPWN.py <jwt> -c <claim you want to edit(username, is_kyc_verfied, role, isadmin, etc.)> -v <desired value for that claim> -o intruder_ready_payloads.txt
  - It will check all the possible Jwt Vuln out there in the market
  - It will ask you to give your wordlist for cracking, your server URL where you have hosted the JSON given by the tool, if you find jwks.json on the target, then give the URL (All are optional)
  - It will generate a payload file which will have all the possible jwt variants. Paste them in Intruder and run your attack to find the flaws.

## OriginHunter
  - A tool that is a combination of all the various tools out there that use different methods for bypassing the WAF by finding the ORIGIN IP
  - It will give you a list of ips you can verify which is the origin ip from them.
  - Uses these methods: CT logs, SPF/MX, ASN/BGP, Shodan, Censys, ZoomEye, ViewDNS, OTX, RapidDNS, HackerTarget, Wayback, Favicon Hash, HTML Similarity, Neighbour
  - python3 originhunter.py -d example.com --shodan apikey --censys "apikey" --zoomeye "apikey" --viewdns "apikey"
 

## Omni403
  - A fast 403/401 bypass tool that supports headers as well as cookies
  - Click [here](https://github.com/abhishek26gupta/403-bypass) for more info.
  
