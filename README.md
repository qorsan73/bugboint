# bugboint
# RUN : 

```
pip install requests beautifulsoup4 colorama dnspython urllib3
```
# Basic scan

```
python3 kolagen.py -u https://example.com
```
# Deep scan with more threads

```
python3 kolagen.py -u https://example.com -d 5 -t 50
```
# Scan with custom timeout

```
python3 kolagen.py -u https://example.com --timeout 60
```
# Save output to specific file

```
python3 kolagen.py -u https://example.com -o scan_results.json
```
