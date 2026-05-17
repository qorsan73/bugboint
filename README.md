# bugboint
# RUN : 

```
pip install requests beautifulsoup4 colorama dnspython urllib3
```
# Basic scan

```
python3 advanced_scanner.py https://example.com
```
# Deep scan with more threads

```
python3 advanced_scanner.py https://example.com -d 5 -t 50
```
# Scan with custom timeout

```
python3 advanced_scanner.py https://example.com --timeout 60
```
# Save output to specific file

```
python3 advanced_scanner.py https://example.com -o scan_results.json
```
