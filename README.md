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

<img width="1920" height="1080" alt="Screenshot_2026-05-17_21_26_12" src="https://github.com/user-attachments/assets/708528b8-4471-40b9-905e-dcb8fa8b55f0" />


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

<img width="1920" height="1080" alt="Screenshot_2026-05-17_21_26_38" src="https://github.com/user-attachments/assets/0c9e1131-84b5-4683-aff4-96c1103cf539" />
