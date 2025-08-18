import requests, os, sys, hashlib
from colorama import Fore, Style, init
from PIL import Image
from PIL.ExifTags import TAGS
import whois, socket, dns.resolver

init(autoreset=True)

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.RED + """
 ██████╗  ██████╗  ██████╗  ██████╗ ███████╗██╗  ██╗    ████████╗ ██████╗  ██████╗ ██╗     
██╔════╝ ██╔═══██╗██╔═══██╗██╔═══██╗██╔════╝██║ ██╔╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
██║  ███╗██║   ██║██║   ██║██║   ██║█████╗  █████╔╝        ██║   ██║   ██║██║   ██║██║     
██║   ██║██║   ██║██║   ██║██║   ██║██╔══╝  ██╔═██╗        ██║   ██║   ██║██║   ██║██║     
╚██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝███████╗██║  ██╗       ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
""")
    print(Fore.YELLOW + "GhostX-ToolCybersecurity — Digital hitman. Precise. Silent.\n")

def alias_scan(username):
    print(Fore.CYAN + f"\n🔎 Scanning username: {username}")
    platforms = {
        "Instagram": f"https://www.instagram.com/ghostx_oblockops?igsh=djYyaWVyNWM2eWZt",
        "Guns LOL": f"https://guns.lol/xzsatoruyt55x666" ,
        "GitHub": f"https://github.com/XZSATORUYT55X",
        "TikTok": f"http://tiktok.com/@xzsatoruyt55x0}"
    }
    for name, url in platforms.items():
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print(Fore.GREEN + f"[+] {name}: Found → {url}")
            else:
                print(Fore.RED + f"[-] {name}: Not found")
        except:
            print(Fore.RED + f"[!] Error connecting to {name}")

def email_leak(email):
    print(Fore.CYAN + f"\n📧 Checking leaks for: {email}")
    try:
        r = requests.get(f"https://haveibeenpwned.com/unifiedsearch/{email}", headers={"User-Agent":"GhostX"})
        if r.status_code == 200 and "Domain" in r.text:
            print(Fore.GREEN + "[+] Email found in leaked databases.")
        else:
            print(Fore.YELLOW + "[-] No public leaks detected.")
    except:
        print(Fore.RED + "[!] Error checking email.")

def domain_info(domain):
    print(Fore.CYAN + f"\n🌐 Domain info: {domain}")
    try:
        w = whois.whois(domain)
        print(Fore.GREEN + f"[+] Whois:\n{w}")
        ip = socket.gethostbyname(domain)
        print(Fore.YELLOW + f"[+] IP: {ip}")
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            print(Fore.YELLOW + f"[+] DNS A Record: {rdata}")
    except:
        print(Fore.RED + "[!] Error retrieving domain info.")

def metadata_extract(path):
    print(Fore.CYAN + f"\n🧠 Extracting metadata from: {path}")
    try:
        image = Image.open(path)
        exifdata = image.getexif()
        for tag_id in exifdata:
            tag = TAGS.get(tag_id, tag_id)
            data = exifdata.get(tag_id)
            print(Fore.GREEN + f"{tag:25}: {data}")
    except:
        print(Fore.RED + "[!] Error extracting metadata.")

def sha256_encrypt(text):
    print(Fore.CYAN + f"\n🔐 Encrypting with SHA-256: {text}")
    hash_object = hashlib.sha256(text.encode())
    hex_dig = hash_object.hexdigest()
    print(Fore.GREEN + f"[+] Hash generated:\n{Fore.YELLOW}{hex_dig}")
    try:
        with open("GhostX_Hash.txt", "a") as f:
            f.write(f"{text} → {hex_dig}\n")
        print(Fore.BLUE + "[+] Hash saved to GhostX_Hash.txt")
    except:
        print(Fore.RED + "[!] Could not save hash.")

def menu():
    while True:
        banner()
        print(Fore.MAGENTA + """
[1] Scan username on social platforms
[2] Check email for leaks
[3] Get domain info
[4] Extract image metadata
[5] Encrypt text with SHA-256
[6] Exit
""")
        choice = input(Fore.YELLOW + "GhostX-ToolCybersecurity> ")
        if choice == "1":
            alias = input("Username> ")
            alias_scan(alias)
        elif choice == "2":
            email = input("Email> ")
            email_leak(email)
        elif choice == "3":
            domain = input("Domain> ")
            domain_info(domain)
        elif choice == "4":
            path = input("Image path> ")
            metadata_extract(path)
        elif choice == "5":
            texto = input("Text> ")
            sha256_encrypt(texto)
        elif choice == "6":
            print(Fore.RED + "\n👻 Shutting down GhostX-ToolCybersecurity... no trace left.")
            print(Fore.MAGENTA + "\n🔚 Powered by GhostX — Code with respect, style from the streets.")
            sys.exit()
        else:
            print(Fore.RED + "[!] Invalid option.")
        input(Fore.BLUE + "\nPress Enter to continue...")

menu()