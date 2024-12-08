# **NHL-Scanner**  
*A high-performance web vulnerability scanner with support for custom signatures and detailed reporting.*

![NHL-Scanner Logo](/static/nhl-scanner-cover-image.png)

<p align="center">
  <a href="#get-started">Get Started</a> •
  <a href="#features">Features</a> •
  <a href="#documentation">Documentation</a> •
</p>

<p align="center">

<img src="https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white">
&nbsp;&nbsp;
<a href="#documentation"><img src="https://img.shields.io/badge/documentation-%23000000.svg?style=for-the-badge&logo=read-the-docs&logoColor=white"></a>

</p>

---

## **Overview**

NHL-Scanner is a robust and lightweight vulnerability scanner designed for flexibility and precision. Whether you're scanning a single target, multiple targets, or crafting custom vulnerability templates, NHL-Scanner ensures efficient detection and reporting of vulnerabilities.

### **Why NHL-Scanner?**
- **Custom Signatures**: Write your own signatures with `status code` or `keyword` matchers.
- **Scalable Scanning**: Handle single or multiple target scans seamlessly.
- **Detailed Reporting**: Generate HTML reports filtered by scan ID or target.
- **User-Friendly**: Interactive CLI for creating custom signatures and managing scans.

---

## **Table of Contents**

- [Get Started](#get-started)
- [Features](#features)
  - [Single Target Scan](#single-target-scan)
  - [Scan Multiple Targets](#scan-multiple-targets)
  - [Generate Reports](#generate-reports)
  - [Create Custom Signatures](#create-custom-signatures)
- [Documentation](#documentation)

---

## **Get Started**

### **1. Installation**

Install Python 3.9+ and clone the repository:

```bash
git clone https://github.com/HD-F0rensics/nhl-scanner.git
cd nhl-scanner
pip install -r requirements.txt
```

### **2. Running NHL-Scanner**

Run the tool with the `-h` flag to explore the available options:

```bash
python nhl-scanner.py --help
```

---

## **Features**

### **Single Target Scan**

Perform a quick scan against a single target using a specific signature:

```bash
python nhl-scanner.py -t https://example.com -s CUSTOM_signature.json
```

### **Scan Multiple Targets**

Scan multiple targets by providing a file containing target URLs:

```bash
python nhl-scanner.py -T targets.txt -S
```

### **Generate Reports**

Export a detailed HTML report for a specific scan ID:

```bash
python nhl-scanner.py --export-report scan-id:<your-scan-id>
```

Or generate a report for a specific target:

```bash
python nhl-scanner.py --export-report target:https://example.com
```

Reports are saved in the `reports/` folder.

### **Create Custom Signatures**

Easily create new signatures through an interactive CLI:

```bash
python nhl-scanner.py --create-sig
```

### **Lite Mode**

Print only the matches during scans for cleaner output:

```bash
python nhl-scanner.py -t https://example.com -L
```

---

## **Documentation**

### **Command-Line Options**

Explore the full list of available options:

```bash
python nhl-scanner.py --help
```

<details>
  <summary>Expand command-line options</summary>

```plaintext
-t, --target               Specify a single target URL
-T, --targets              File containing multiple target URLs
-S, --all_signatures       Use all signatures in the 'signatures' folder
-s, --signature            Use a specific signature file
-L, --lite                 Lite mode: print only matches
--export-report            Export a report by scan-id or target (e.g., scan-id:<id> or target:<url>)
--create-sig               Create a custom signature interactively
```

</details>

### **Example Scenarios**

1. **Scanning with All Signatures**:
    ```bash
    python nhl-scanner.py -t https://example.com -S
    ```

2. **Exporting a Report**:
    ```bash
    python nhl-scanner.py --export-report scan-id:<your-scan-id>
    ```

3. **Creating a Custom Signature**:
    ```bash
    python nhl-scanner.py --create-sig
    ```

4. **Lite Mode Scanning**:
    ```bash
    python nhl-scanner.py -t https://example.com -L
    ```


