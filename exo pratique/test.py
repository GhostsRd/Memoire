import base64
import math
import json
import urllib.request
import binascii

def parse_der_integer(data, offset):
    if data[offset] != 0x02:
        raise ValueError("Tag ASN.1 inattendu (attendu: INTEGER 0x02)")
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        num_bytes = length & 0x7f
        length = int.from_bytes(data[offset:offset+num_bytes], 'big')
        offset += num_bytes
    val = int.from_bytes(data[offset:offset+length], 'big')
    return val, offset + length

def extract_rsa_pem(filename):
    with open(filename, "r") as f:
        content = f.read()
    # Nettoyage des balises PEM
    b64_str = "".join([line.strip() for line in content.splitlines() if "PUBLIC KEY" not in line])
    der = base64.b64decode(b64_str)
    
    # Parcours minimaliste de la structure DER ASN.1
    idx = 0
    integers = []
    while idx < len(der) - 2:
        if der[idx] == 0x02:
            try:
                val, next_idx = parse_der_integer(der, idx)
                if val > 65537 or val in [65537, 3]:
                    integers.append(val)
                idx = next_idx
                continue
            except Exception:
                pass
        idx += 1
    if len(integers) < 2:
        raise ValueError("Impossible d'extraire les paramètres RSA du fichier.")
    # On retourne le plus grand comme modulo N, le plus petit comme exposant e
    return max(integers), min(integers)

def query_factordb(n):
    print(f"[*] Interrogation de Factordb pour le modulo ({n.bit_length()} bits)...")
    url = f"http://factordb.com/api?query={n}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "FF" or data.get("status") == "CF":
                factors = []
                for factor_info in data.get("factors", []):
                    val = int(factor_info[0])
                    power = factor_info[1]
                    for _ in range(power):
                        factors.append(val)
                if len(factors) >= 2:
                    return factors
            return None
    except Exception as e:
        print(f"[-] Erreur de connexion à Factordb : {e}")
        return None

# --- Exécution principale ---

try:
    print("[*] Extraction des clés PEM...")
    N_bob, e_bob = extract_rsa_pem("bob_public.pem")
    N_marie, e_marie = extract_rsa_pem("marie_public.pem")
    
    print(f"    -> Bob   : N = {N_bob} ({N_bob.bit_length()} bits), e = {e_bob}")
    print(f"    -> Marie : N = {N_marie} ({N_marie.bit_length()} bits), e = {e_marie}")
    
    # Étape 1 : Vérification de la faille de clé partagée (PGCD)
    gcd_val = math.gcd(N_bob, N_marie)
    if gcd_val > 1:
        print(f"\n[+] FAILLE TROUVÉE : Facteur commun identifié via PGCD !")
        p = gcd_val
        q_bob = N_bob // p
        q_marie = N_marie // p
        
        # Exemple de reconstruction de clé pour Marie
        phi_marie = (p - 1) * (q_marie - 1)
        d_marie = pow(e_marie, -1, phi_marie)
        print("[+] Clé privée de Marie reconstruite avec succès !")
    else:
        print("\n[*] Pas de facteur commun direct. Passage à l'étape 2 (Factordb)...")
        
        # Étape 2 : Recherche de facteurs connus pré-calculés en ligne
        factors = query_factordb(N_marie)
        if factors:
            p, q = factors[0], factors[1]
            print(f"[+] Succès ! Modulo de Marie résolu par Factordb :")
            print(f"    p = {p}")
            print(f"    q = {q}")
            phi_marie = (p - 1) * (q - 1)
            d_marie = pow(e_marie, -1, phi_marie)
            print("[+] Clé privée de Marie reconstruite avec succès !")
        else:
            print("[-] Le modulo n'est pas encore factorisé publiquement sur Factordb.")

except FileNotFoundError as e:
    print(f"[-] Erreur : Fichier manquant. Assurez-vous que 'bob_public.pem' et 'marie_public.pem' sont dans le même dossier.")
except Exception as e:
    print(f"[-] Une erreur est survenue : {e}")