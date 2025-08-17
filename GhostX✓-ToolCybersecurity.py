import requests, os, sys, hashlib, time
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
    print(Fore.YELLOW + "GhostX-ToolCybersecurity — Sicario digital. Preciso. Silencioso.\n")
    print(Fore.LIGHTBLACK_EX + "\"Nunca envíes una amenaza por internet solo para probar un punto\"")
    print(Fore.LIGHTBLACK_EX + "Ese dissing, no entres en eso, se lo dejamos a los informantes")
    print(Fore.LIGHTBLACK_EX + "No me informes sobre quién informa, esa es tu advertencia final")
    print(Fore.LIGHTBLACK_EX + "Las 7.62 pican como una abeja, él empieza a transformarse\n")

def alias_scan(username):
    print(Fore.CYAN + f"\n🔎 Escaneando alias: {username}")
    plataformas = {
        "Instagram": f"https://www.instagram.com/ghostx_oblockops?igsh=djYyaWVyNWM2eWZt",
        "GitHub": f"https://github.com/XZSATORUYT55X",
        "TikTok": f"tiktok.com/@xzsatoruyt55x666"
    
    for nombre, url in plataformas.items():
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print(Fore.GREEN + f"[+] {nombre}: Encontrado → {url}")
            else:
                print(Fore.RED + f"[-] {nombre}: No encontrado")
        except:
            print(Fore.RED + f"[!] Error al conectar con {nombre}")

def email_leak(email):
    print(Fore.CYAN + f"\n📧 Verificando filtraciones para: {email}")
    try:
        r = requests.get(f"https://haveibeenpwned.com/unifiedsearch/{email}", headers={"User-Agent":"GhostX"})
        if r.status_code == 200 and "Domain" in r.text:
            print(Fore.GREEN + "[+] Email filtrado en bases de datos.")
        else:
            print(Fore.YELLOW + "[-] No se encontraron filtraciones públicas.")
    except:
        print(Fore.RED + "[!] Error al verificar email.")

def domain_info(domain):
    print(Fore.CYAN + f"\n🌐 Información del dominio: {domain}")
    try:
        w = whois.whois(domain)
        print(Fore.GREEN + f"[+] Whois:\n{w}")
        ip = socket.gethostbyname(domain)
        print(Fore.YELLOW + f"[+] IP: {ip}")
        respuestas = dns.resolver.resolve(domain, 'A')
        for rdata in respuestas:
            print(Fore.YELLOW + f"[+] Registro DNS A: {rdata}")
    except:
        print(Fore.RED + "[!] Error al obtener información del dominio.")

def metadata_extract(path):
    print(Fore.CYAN + f"\n🧠 Extrayendo metadata de: {path}")
    try:
        imagen = Image.open(path)
        exifdata = imagen.getexif()
        for tag_id in exifdata:
            tag = TAGS.get(tag_id, tag_id)
            data = exifdata.get(tag_id)
            print(Fore.GREEN + f"{tag:25}: {data}")
    except:
        print(Fore.RED + "[!] Error al extraer metadata.")

def sha256_encrypt(text):
    print(Fore.CYAN + f"\n🔐 Encriptando con SHA-256: {text}")
    hash_object = hashlib.sha256(text.encode())
    hex_dig = hash_object.hexdigest()
    print(Fore.GREEN + f"[+] Hash generado:\n{Fore.YELLOW}{hex_dig}")
    try:
        with open("GhostX_Hash.txt", "a") as f:
            f.write(f"{text} → {hex_dig}\n")
        print(Fore.BLUE + "[+] Hash guardado en GhostX_Hash.txt")
    except:
        print(Fore.RED + "[!] No se pudo guardar el hash.")

def final_warning_mode():
    print(Fore.RED + "\n🔫 Final Warning Mode Activated...")
    time.sleep(1)
    print(Fore.YELLOW + "💣 Arming digital rounds...")
    time.sleep(1)
    print(Fore.YELLOW + "🧠 Locking targets silently...")
    time.sleep(1)
    print(Fore.YELLOW + "👻 No threats. No dissin'. Just precision.\n")
    time.sleep(1)
    print(Fore.LIGHTBLACK_EX + "\"Never send a threat on the internet just to prove a point\"")
    print(Fore.LIGHTBLACK_EX + "That dissin', don't get into that, we leavin' it to the informants")
    print(Fore.LIGHTBLACK_EX + "Don't inform me about who informing, that's yo' final warning")
    print(Fore.LIGHTBLACK_EX + "7.62's sting like a Bumblebee, he start transforming\n")
    print(fore.lightblack_ex + "These niggas keep dissin', I guess I'm the topic (Brr)
These bullets gon' knock the knowledge out of his noggin/")
    time.sleep(1)
    print(Fore.MAGENTA + "🔚 GhostX moves in silence. Respect the code.\n")

def menu():
    while True:
        banner()
        print(Fore.MAGENTA + """
[1] Escanear alias en redes sociales
[2] Verificar email filtrado
[3] Obtener información de dominio
[4] Extraer metadata de imagen
[5] Encriptar texto con SHA-256
[6] Salir
[7] Modo Final Warning
""")
        choice = input(Fore.YELLOW + "GhostX-ToolCybersecurity> ")
        if choice == "1":
            alias = input("Alias> ")
            alias_scan(alias)
        elif choice == "2":
            email = input("Email> ")
            email_leak(email)
        elif choice == "3":
            domain = input("Dominio> ")
            domain_info(domain)
        elif choice == "4":
            path = input("Ruta de imagen> ")
            metadata_extract(path)
        elif choice == "5":
            texto = input("Texto> ")
            sha256_encrypt(texto)
        elif choice == "6":
            print(Fore.RED + "\n👻 Cerrando GhostX-ToolCybersecurity... sin dejar huella.")
            print(Fore.MAGENTA + "\n🔚 Desarrollado por GhostX — Respeto al código, estilo callejero.")
            sys.exit()
        elif choice == "7":
            final_warning_mode()
        else:
            print(Fore.RED + "[!] Opción inválida.")
        input(Fore.BLUE + "\nPresiona Enter para continuar...")

menu()