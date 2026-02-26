# Instrukcja instalacji ReconSpider

## Szybka instalacja linux

```bash
# 1. Sklonuj repozytorium
git clone https://github.com/Maciej207/osint-ReconSpider-v3.0.git
cd reconspider

# 2. (Opcjonalnie) Utwórz wirtualne środowisko
python3 -m venv venv
source venv/bin/activate

# 3. Zainstaluj zależności
pip install -r requirements.txt

# 4. (Opcjonalnie) Zainstaluj wszystkie moduły
pip install -r requirements-full.txt

# 5. Uruchom
python reconspider_pro1.py example.com
