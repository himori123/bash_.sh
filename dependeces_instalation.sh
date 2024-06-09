#!/bin/bash

# Função para instalar dependências
install_dependencies() {
    sudo apt-get update
    sudo apt-get install -y curl jq nmap git python3-pip golang
    GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
    GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsx/cmd/dnsx
    GO111MODULE=on go get -u -v github.com/projectdiscovery/naabu/v2/cmd/naabu
    GO111MODULE=on go get -u -v github.com/projectdiscovery/httpx/cmd/httpx
    GO111MODULE=on go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
    GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns
    GO111MODULE=on go get -u -v github.com/lc/gau
    GO111MODULE=on go get -u -v github.com/hakluke/hakrawler
    GO111MODULE=on go get -u -v github.com/projectdiscovery/katana/cmd/katana
    GO111MODULE=on go get -u -v github.com/tomnomnom/waybackurls
    pip3 install git+https://github.com/tomnomnom/meg.git
    pip3 install -U requests
}

# Função para exibir o menu
show_menu() {
    echo "Escolha uma opção:"
    echo "0) Instalar dependências"
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

# Funções para cada operação (omitido por brevidade, mas inclua todas as funções mencionadas anteriormente aqui)

# Menu interativo
while true; do
    show_menu
    read -p "Escolha uma opção: " choice
    case $choice in
        0) install_dependencies ;;
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
