## Regex Data Extraction

This project reads a raw text file containing unstructured and messy data, then extracts useful information using Regex.
It also includes Validation and security checks to make sure all input data is safe and correctly formatted.
The final output is saved as a clean JSON file.

 **What This Project Does**

The program scans a text file and extracts:
- Email addresses (including ALU-specific emails)
- Phone numbers
- Credit card numbers (validated and masked)
- URLs
- HTML tags
- Hashtags
- Currency values
- Time values



**Security Features**

- Scans input for **malicious patterns first** 
- Detects:
  - XSS attacks (e.g., <script>, onerror)
  - SQL injection patterns
- Credit cards are:
  - Validated using the Luhn algorithm
  - Checked against known test numbers
  - Always masked (only first 3 and last 3 digits shown)
- Duplicate values are automatically removed
- Invalid inputs return clear error messages
  
**project structure**

project/
│
├── input/
│ └── raw-text.txt  -the raw data
│
├── output/
│ └── sample-output.json - stores the sorted data
│
└── src/
└── main.py - has the main program

**How to run the program**

Run python3 src/main.py

After the program runs:
The results are recorded in the JSON sample output file, which includes dictionaries and lists containing phone numbers, card numbers, and emails.

**How It Works** 

The program reads raw text from a file

It first checks for unsafe or malicious content

It uses regex patterns to find different types of data

**Regex patterns used**

1. Email
r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
Matches letters/digits/symbols before @, then a domain name, then a dot and TLD of at least 2 letters. Word boundaries on both ends prevent partial matches.

**ALU Emails**
r'^[A-Za-z0-9._%+\-]+@alueducation\.com$'
r'^[A-Za-z0-9._%+\-]+@alumni\.alueducation\.com$'
r'^[A-Za-z0-9._%+\-]+@si\.alueducation\.com$'
 ^ and $ anchors force a full-string match to prevent spoofed domains like @alueducation.com.phishing.io from passing. 

 **Phone Numbers**
r'(?:\+\d{1,3}[\s\-.]?)?(?:\(0?\d{1,4}\)[\s\-.]?)?\d{3,5}[\s\-.]\d{3,4}(?:[\s\-.]?\d{3,4})?'
Country code,   area code, then two required digit blocks separated by a space, hyphen, or dot. The  separator prevents card numbers from being matched.

 **Credit Cards**
   
r'\b\d{4}[\s\-]\d{4,6}[\s\-]\d{4,6}(?:[\s\-]\d{1,4})?\b'
** Strict Amex (15 digits)**
r'^\d{4}[\s\-]\d{6}[\s\-]\d{5}$'
** Strict Visa (16 digits)**
r'^\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}$'
The broad pattern catches anything that looks like a card. Strict patterns then confirm exact digit groupings. Every match is also checked against a test-card blocklist and the Luhn algorithm.

 **URLs**
r'https?://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
Matches http://or https://followed by any valid URL characters. 

 **HTML Tags**
r'</?[A-Za-z][A-Za-z0-9]*(?:\s+[^>]*)?\s*/?>'
Matches opening, closing, and self-closing tags. Tag name must start with a letter. 

 **Hashtags**
   r'#[A-Za-z]\w+'
Hash symbol followed by a mandatory letter, then any word characters. The letter-first rule prevents ticket numbers, years, and IDs like #2026 from being matched.

** Currency**
r'(?:KES|USD|EUR|GBP)\s*[+\-]?[$€£]?\s*\d{1,3}(?:,\d{3})*\.\d{2}|[+\-]?[$€£]\s*\d{1,3}(?:,\d{3})*\.\d{2}'
 Currency code first (KES 4,500.00) or symbol first ($89.99). Exactly two decimal places are required

 **Time**
r'\b(?:(?:1[0-2]|0?[1-9]):[0-5]\d\s?[AP]M|(?:[01]\d|2[0-3]):[0-5]\d)\b'
 12-hour (2:30 PM, hours 1–12) and 24-hour (14:45, hours 00–23). Minutes restricted to 00–59. 

 **Unsafe Content**
r'<script[\s\S]*?>[\s\S]*?</script>'   
r'\bon\w+\s*='                          
r'javascript\s*:'                       
r"'\s*OR\s+\d+=\d+."                    
r'\bDROP\s+TABLE\b'                    
r';\s*--'                              
Unsafe content is scanned before extraction. Detects XSS and SQL injection patterns. If any match, the input is flagged.


