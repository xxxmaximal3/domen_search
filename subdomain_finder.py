import requests
import dns.resolver
import json
import sys
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import concurrent.futures
import re

def clean_domain(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return urlparse(url).netloc.replace('www.', '')

def get_subdomains_crtsh(domain):
    print(f"[*] Поиск в crt.sh для {domain}...")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lstrip('*.')
                    if domain in sub:
                        subdomains.add(sub)
    except Exception as e:
        print(f"  [!] crt.sh ошибка: {e}")
    print(f"  [+] Найдено через crt.sh: {len(subdomains)}")
    return subdomains

def get_subdomains_from_page(domain):
    print(f"[*] Анализ страницы {domain}...")
    subdomains = set()
    try:
        resp = requests.get(f"https://{domain}", timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        pattern = re.compile(r'([a-zA-Z0-9\-]+\.' + re.escape(domain) + r')')
        for match in pattern.findall(resp.text):
            subdomains.add(match)
    except Exception as e:
        print(f"  [!] Ошибка парсинга: {e}")
    print(f"  [+] Найдено на странице: {len(subdomains)}")
    return subdomains

def dns_bruteforce(domain):
    print(f"[*] DNS брутфорс для {domain}...")
    wordlist = [
        'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'sftp',
        'api', 'cdn', 'static', 'assets', 'img', 'images',
        'dev', 'staging', 'test', 'prod', 'beta', 'alpha',
        'app', 'mobile', 'web', 'portal', 'admin', 'panel',
        'auth', 'login', 'sso', 'oauth', 'accounts', 'account',
        'media', 'upload', 'downloads', 'files', 'docs', 'help',
        'support', 'status', 'monitor', 'metrics', 'analytics',
        'vpn', 'proxy', 'gateway', 'ns1', 'ns2', 'mx', 'mx1',
        'shop', 'store', 'checkout', 'payment', 'pay',
        'forum', 'blog', 'news', 'wiki', 'kb',
        'git', 'gitlab', 'github', 'jenkins', 'ci', 'jira',
        'video', 'stream', 'live', 'tv', 'radio',
        'm', 'wap', 'touch', 'i', 'ios', 'android',
    ]
    found = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    def check_subdomain(sub):
        full = f"{sub}.{domain}"
        try:
            resolver.resolve(full, 'A')
            return full
        except:
            try:
                resolver.resolve(full, 'CNAME')
                return full
            except:
                return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(check_subdomain, wordlist)
        for r in results:
            if r:
                found.add(r)

    print(f"  [+] Найдено через DNS: {len(found)}")
    return found

def resolve_ip(domain):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'A')
        return [str(r) for r in answers]
    except:
        return []

def main():
    print("=" * 60)
    print("   Поиск доменов и поддоменов для VPN Split Tunneling")
    print("=" * 60)

    target = input("\nВведите домен или URL сайта: ").strip()
    domain = clean_domain(target)
    print(f"\n[*] Целевой домен: {domain}\n")

    all_subdomains = set()
    all_subdomains.add(domain)
    all_subdomains.update(get_subdomains_crtsh(domain))
    all_subdomains.update(get_subdomains_from_page(domain))
    all_subdomains.update(dns_bruteforce(domain))

    print(f"\n[*] Резолвинг IP-адресов для {len(all_subdomains)} доменов...")
    results = []
    all_ips = set()

    for sub in sorted(all_subdomains):
        ips = resolve_ip(sub)
        if ips:
            results.append({'domain': sub, 'ips': ips})
            all_ips.update(ips)
            print(f"  {sub:<45} {', '.join(ips)}")

    print("\n" + "=" * 60)
    print(f"[+] Всего найдено доменов: {len(results)}")
    print(f"[+] Всего уникальных IP:   {len(all_ips)}")

    out_domains = f"{domain}_domains.txt"
    out_ips = f"{domain}_ips.txt"
    out_json = f"{domain}_full.json"

    with open(out_domains, 'w') as f:
        f.write('\n'.join(r['domain'] for r in results))

    with open(out_ips, 'w') as f:
        f.write('\n'.join(sorted(all_ips)))

    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\n[+] Сохранено:")
    print(f"    {out_domains}  — домены")
    print(f"    {out_ips}      — IP-адреса")
    print(f"    {out_json}     — полный результат (JSON)")
    print("\n[i] Файлы сохранены в папку рядом с программой.")
    input("\nНажми Enter для выхода...")

if __name__ == '__main__':
    main()
