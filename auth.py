import hashlib
import os
import json
import hmac
import getpass

# Pfad zur Datei in der die Nutzerdaten gepspeichert werden sollen
USER_DATA_FILE = "users.json"

# Iterationen und Hash-Algorithmus fuer PBKDF2
ITERATIONS = 250000
HASH_ALGORITHM = 'sha256'

def hash_password(password: str) -> tuple[str, str]:
    """
    Generiert den abgeleiteten Schluessel und den Salt. 
    Uebergeben wird das eingegbene Passwort.
    Zurueckgegeben wird das Tupel mit dem Salt und dem abgeleiteten Schuessel (beides im Hexadezimalformat).
    """
    # Kryptografisch sicheren Salt generieren mit Hilfe von Betriebssystem. Länge 16 Byte bzw. 128 Bit
    salt = os.urandom(16)
    
    # PBKDF2 anwenden mit Standard-Bibliothek Hashlib: hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None)
    # Das Passwort muss als Bytefolge kodiert sein.
    hashed_password = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )
    # Schluessel und Salt im Hexadezimalformat zurueckgeben
    return salt.hex(), hashed_password.hex()

def verify_password(provided_password: str, salt_hex: str, stored_hash_hex: str) -> bool:
    """
    Prueft, ob das angegebene Passwort korrekt ist.
    Uebergeben wird das angegebene Passwort und der gespeicherte Salt und abgeleitete Schluessel.
    Zurueckgegeben wird true, wenn das Passwort stimmt und false wenn nicht.
    """
    # Heaxdezimal in Bytes umwandeln
    salt = bytes.fromhex(salt_hex)
    stored_hash = bytes.fromhex(stored_hash_hex)
    
    # PBKDF2 mit gleichen Parametern
    provided_hash = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        provided_password.encode('utf-8'),
        salt,
        ITERATIONS
    )
    
    # abgeleitete Schuessel werden verglichen
    # compare_digest() der Standard-Bibliothek hmac wird verwendet, um Timing-Angriffe zu verhindern
    return hmac.compare_digest(stored_hash, provided_hash)

def load_users() -> dict:
    """
    Laedt die Nutzerdaten aus der JSON-Datei
    Gibt die Daten als dictionary zurueck
    """
    try:
        with open(USER_DATA_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Leeres dictionary, falls Datei nicht gelesen werden kann
        return {}

def save_users(users: dict):
    """
    Speichert die Nutzerdaten in der JSON-Datei
    """
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def register_user():
    """
    Registriert neuen Nutzer
    """
    print("\n--- Neuen Nutzer registrieren ---")
    users = load_users()
    
    username = input("Nutzername: ").lower()
    
    if username in users:
        print("Dieser Nutzer existiert bereits. Bitte wähle einen anderen Namen.")
        return

    # getpass damit das Passwort nicht angezeigt wird
    password = getpass.getpass("Passwort: ")
    password_confirm = getpass.getpass("Passwort bestätigen: ")
    
    if password != password_confirm:
        print("Die Passwörter stimmen nicht überein. Bitte versuche es noch einmal.")
        return
        
    if not password:
        print("Das Passwort muss ein Zeichen enthalten.")
        return

    # Salt und abgeleiteten Schluessel generieren
    salt_hex, hashed_password_hex = hash_password(password)
    
    # Nutzerdaten speichern
    users[username] = {
        "salt": salt_hex,
        "hash": hashed_password_hex
    }
    
    save_users(users)
    print(f"\nNutzer '{username}' wurde erfolgreich registriert!")

def login_user():
    """
    Meldet Nutzer an
    """
    print("\n--- Anmelden ---")
    users = load_users()
    
    username = input("Nutzername: ").lower()
    password = getpass.getpass("Passwort: ")
    
    # Nutzernamen suchen
    user_data = users.get(username)
    
    if not user_data:
        # Fehlermeldung falls Nutzername nicht gefunden wurde
        # absichtlich generisch gehalten
        print("\nNutzername oder Passwort ist nicht korrekt.")
        return
        
    # Passwort pruefen
    is_correct = verify_password(
        provided_password=password,
        salt_hex=user_data["salt"],
        stored_hash_hex=user_data["hash"]
    )
    
    if is_correct:
        print(f"\nAnmeldung erfolgreich. Willkomen, {username}! ")
    else:
        print("\nNutzername oder Passwort ist nicht korrekt.")


def main():
    #Terminal leeren und Titel anzeigen
    os.system('cls' if os.name == 'nt' else 'clear')
    print(" _____                           ______ _    ____  ___")
    print("/  ___|                          | ___ \ |  | |  \/  |")
    print("\ `--.  ___  ___ _   _ _ __ ___  | |_/ / |  | | .  . |")
    print(" `--. \/ _ \/ __| | | | '__/ _ \ |  __/| |/\| | |\/| |")
    print("/\__/ /  __/ (__| |_| | | |  __/ | |   \  /\  / |  | |")
    print("\____/ \___|\___|\__,_|_|  \___| \_|    \/  \/\_|  |_/")
    print("\n")
    #Eingabefenster in der Konsole
    while True:                                           
        print("Wähle eine Option:")
        print("1. Registrieren")
        print("2. Anmelden")
        print("3. Verlassen")
        choice = input("Deine Option: ")
        
        if choice == '1':
            register_user()
        elif choice == '2':
            login_user()
        elif choice == '3':
            print("Bis zum nächsten Mal!")
            break
        else:
            print("\nUngültige Eingabe, bitte erneut versuchen.")

if __name__ == "__main__":

    main()

