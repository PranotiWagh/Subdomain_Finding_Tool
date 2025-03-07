import requests
import socket
import concurrent.futures
import dns.resolver
import time
from tabulate import tabulate

# Function to load wordlist from an array
def load_wordlist():
    return [
        "www", "mail", "ftp", "test", "admin", "web", "secure", "dev", "portal", "vpn", "api",
        "shop", "blog", "m", "mobile", "news", "status", "beta", "cdn", "edge", "download", "media",
        "img", "static", "chat", "support", "forum", "help", "docs", "dashboard", "my", "account",
        "billing", "login", "logout", "register", "signup", "auth", "oauth", "secure", "internal",
        "backup", "old", "new", "public", "private", "cloud", "store", "app", "gateway", "data",
        "graph", "analytics", "search", "api1", "api2", "api3", "content", "assets", "ads", "marketing",
        "services", "resources", "partners", "developers", "client", "user", "customers", "adminpanel",
        "manager", "connect", "test1", "test2", "dev1", "dev2", "staging", "preprod", "prod", "demo",
        "lab", "sandbox", "training", "events", "conference", "meet", "video", "stream", "upload",
        "download", "repository", "git", "svn", "wiki", "helpdesk", "issue", "jira", "zendesk", "sales",
        "finance", "hr", "payroll", "hrportal", "crm", "erp", "inventory", "warehouse", "order",
        "shipping", "logistics", "tracking", "barcode", "stock", "storefront", "ecommerce", "cart",
        "checkout", "shopsecure", "securecheckout", "payments", "invoice", "billingportal", "tax",
        "legal", "policy", "terms", "privacy", "compliance", "governance", "audit", "security",
        "monitoring", "logs", "firewall", "proxy", "dns", "vpnsecure", "vpnaccess", "adminvpn",
        "gatewaysecure", "webproxy", "dnsproxy", "proxyserver", "cache", "cdn1", "cdn2", "cdn3",
        "edgecache", "backupserver", "fileserver", "nas", "storage", "cloudstorage", "objectstore",
        "datastore", "database", "db1", "db2", "db3", "mongodb", "mysql", "postgres", "oracle",
        "sqlserver", "mariadb", "dynamodb", "elasticsearch", "kibana", "logstash", "splunk", "siem",
        "incident", "alerts", "monitor", "uptime", "statuspage", "maintenance", "scheduler",
        "taskmanager", "workflow", "automation", "api-gateway", "servicebus", "eventhub", "queue",
        "messaging", "broker", "iot", "sensor", "device", "telematics", "trackingservice", "geo",
        "maps", "location", "gps", "beacon", "advertising", "adsserver", "mediaserver", "videohost",
        "imagehost", "cdncache", "streaming", "radio", "live", "broadcast", "tv", "iptv", "gaming",
        "leaderboard", "community", "chatroom", "voice", "voip", "callcenter", "contact", "phone",
        "messenger", "email", "smtp", "imap", "pop3", "exchange", "webmail", "mailserver", "dnssec",
        "firewallrules", "ids", "ips", "honeypot", "forensics", "auditlog", "compliancecheck",
        "dataprotection", "gdpr", "privacyshield", "cookieconsent", "tos", "legalagreements",
        "intellectualproperty", "copyright", "trademark", "dmca", "whistleblower", "internalreport",
        "customerfeedback", "surveys", "nps", "reviews", "ratings", "press", "mediarelations",
        "publicrelations", "investors", "stakeholders", "board", "executives", "leadership", "ceo",
        "cfo", "cto", "ciso", "legalcounsel", "corporategovernance", "codeofconduct", "hrpolicies",
        "jobportal", "careers", "internships", "volunteer", "donate", "fundraising", "charity",
        "eventsponsor", "conferencepage", "trainingmaterials", "tutorials", "knowledgebase",
        "faq", "howto", "bestpractices", "guidelines", "standards", "iso", "certifications",
        "research", "whitepapers", "casestudies", "technicaldocs", "specs", "api-docs", "sdk",
        "opensource", "contributors", "collaborators", "partnerships", "alliances", "customersuccess",
        "consulting", "advisory", "professionalservices", "managedservices", "supportdesk"
    ][:500]  # Ensure it only contains 500 words

# Function to fetch subdomains from crt.sh (Certificate Transparency logs)
def fetch_crtsh(domain):
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return {entry['name_value'] for entry in response.json()}
    except Exception as e:
        print(f"[!] Error fetching from crt.sh: {e}")
    return set()

# Function to resolve subdomain to IP address using a specific DNS resolver
def resolve_subdomain(subdomain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]  # Using Google's public DNS
    try:
        answer = resolver.resolve(subdomain, "A")
        return subdomain, answer[0].to_text()
    except:
        return subdomain, "Not resolved"

# Brute-force subdomain enumeration with optimized threading
def brute_force_subdomains(domain):
    wordlist = load_wordlist()
    subdomains = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(resolve_subdomain, f"{sub}.{domain}"): sub for sub in wordlist}
        for future in concurrent.futures.as_completed(futures):
            subdomain, ip = future.result()
            if ip:
                subdomains.add((subdomain, ip))
    return subdomains

if __name__ == "__main__":
    while True:
        domain = input("Enter target domain (or type 'exit' to quit): ")
        if domain.lower() == 'exit':
            break

        print(f"[+] Running brute-force subdomain enumeration for {domain}...")

        start_time = time.time()  # Start timer

        brute_force_subdomains_list = brute_force_subdomains(domain)

        end_time = time.time()  # End timer
        total_time = end_time - start_time  # Calculate total time taken

        print(tabulate(brute_force_subdomains_list, headers=["Subdomain", "IP Address"], tablefmt="grid"))
        print(f"\n[+] Completed in {total_time:.2f} seconds")  # Print total time
