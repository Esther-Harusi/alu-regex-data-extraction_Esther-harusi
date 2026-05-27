## Regex Data Extraction

This project reads a raw text file containing unstructured and messy data, then extracts useful information using **Python regular expressions (regex)**.

It also includes **validation and security checks** to make sure all input data is safe and correctly formatted.

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

- Scans input for **malicious patterns first** (before extraction)
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
The results are recorded in the JSON sample output file, which will include the dictionaries and lists containing the phone numbers, card numbers, and emails.

**How It Works** 

The program reads raw text from a file

It first checks for unsafe or malicious content

It uses regex patterns to find different types of data

Each item is validated based on format  rules

Invalid or duplicate data is rejected with clear reasons

Safe results are grouped and saved as JSON.
