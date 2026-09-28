import binascii

# Paramètres de Bob
N_bob = 1222260228653665370204510521871565621658927523188624234716406250327086007246410928245658558231490134091080868775307557825914890234266506268266580458423374171812441549894938975333354595906582898670532001474651995699915553534299686461807555867791031922255268238734432896120008810954164563490411604702077
e = 65537

# Le Message 20 (chiffré pour Bob)
cipher_20 = "1cf64adad2f782b84b923442fbe2841eb9c07d9f8ab9e44ef35c8e9126e5e663befc23ec1d6b0c14e4dfcd3c4958bce7b8b9b04075b4e0ef144528aef63d0b9238a900c66d214c28bf7a4bc3e7cadf3f92b5dfa6607052596df7537b5d4c4e10b10ea049f58c05cdf4b37ae8436553dcd9926c68fc867a514657e8796d"

# Le secret de Bob déchiffré à l'étape 1
secret_int = 1557422938456321829614468447894535711318684664379207196667063884174280351767432981431536828965055486276114619436202345696347624406776046150058732331602612797775248714388575800280260006576191539011974364668293758812824999284289003200951077465664915367831697633594656191039719825786656918279948544598709

print("[*] Recherche du facteur p de Bob à partir de la valeur du secret...")

# On teste si le secret ou une valeur très proche (jusqu'à 1 million d'écart) est le facteur de Bob
p_found = None
limit = 1000000

for offset in range(-limit, limit):
    candidate = secret_int + offset
    if candidate > 1 and N_bob % candidate == 0:
        p_found = candidate
        print(f"[+] Facteur trouvé avec un offset de {offset} !")
        break

if p_found:
    p = p_found
    q = N_bob // p
    
    # Calcul de la clé privée de Bob
    phi_bob = (p - 1) * (q - 1)
    d_bob = pow(e, -1, phi_bob)
    print(f"[+] Clé privée de Bob d = {d_bob}")
    
    # Déchiffrement du Message 20
    c = int(cipher_20, 16)
    m = pow(c, d_bob, N_bob)
    
    # Encodage en texte
    hex_str = hex(m)[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    decrypted_msg = binascii.unhexlify(hex_str).decode('utf-8', errors='ignore')
    
    print("\n================ MESSAGE 20 DÉCHIFFRÉ ================")
    print(decrypted_msg)
    print("======================================================")
else:
    print("[-] Le secret n'est pas un facteur proche direct. Vérifions d'autres pistes...")