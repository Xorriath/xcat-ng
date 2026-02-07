# XCat-NG

A modernized fork of [XCat](https://github.com/orf/xcat) — a command line tool to exploit and investigate blind XPath injection vulnerabilities.

## What's New in XCat-NG

### Modernized Codebase
- Updated to **Python 3.10+** with modern syntax (type unions, f-strings, etc.)
- Updated all dependencies to current versions
- Cleaned up deprecated patterns throughout

### In-Band Extraction (`--inband`)
Extract data directly from HTTP response bodies instead of character-by-character blind extraction. When the target application reflects XPath results in its responses:
- **Response diffing** compares true/false responses to extract data in as few as 2-3 requests
- **DFS tree traversal** handles row-limited applications by walking the XML tree node-by-node via union injection
- Falls back to standard blind extraction automatically if in-band isn't possible

### Time-Based Blind Injection (`--time N`)
For applications that return identical responses regardless of true/false conditions, where content-based detection is impossible:
- Uses nested `count()` expressions to create computational delay via XPath short-circuit evaluation
- `N` specifies the nesting level (user determines the right value by testing)
- Auto-detects injection type and calibrates timing threshold
- Linear search optimization — minimizes expensive true (slow) checks

### Other Improvements
- Expanded character search space to all 95 printable ASCII characters
- Improved robustness across different application behaviors

## Features

- Auto-selects injections (run `xcat injections` for a list)
- Detects the version and capabilities of the XPath parser and selects the fastest retrieval method
- Built-in out-of-band HTTP server
    - Automates XXE attacks
    - Can use OOB HTTP requests to drastically speed up retrieval
- Custom request headers and body
- Built-in REPL shell supporting:
    - Reading arbitrary files
    - Reading environment variables
    - Listing directories
- Optimized retrieval
    - Binary search over unicode codepoints if available
    - Common character frequency tracking
    - Unicode normalization to reduce search space

## Install

```
pip install poetry
git clone https://github.com/Xorriath/xcat-ng.git
cd xcat-ng
poetry install
```

## Usage

### Boolean-Based Blind Extraction
```bash
# GET request with content-based detection
xcat run http://target/page.php q q=value --true-string='Success'

# POST form with negated match
xcat run http://target/page.php username username=admin msg=test \
  -m POST --encode FORM --true-string='!Error'
```

### In-Band Extraction
```bash
# Extract data directly from response bodies (much faster)
xcat run http://target/page.php q q=value f=field \
  --true-string='Result' --inband
```

### Time-Based Blind Extraction
```bash
# When responses are identical — use timing as the oracle
xcat run http://target/page.php username username=admin msg=test \
  -m POST --encode FORM --time 6
```

### Detection & Shell
```bash
# Detect injection types and XPath features
xcat detect http://target/page.php q q=value --true-string='Success'

# Interactive shell for manual exploration
xcat shell http://target/page.php q q=value --true-string='Success'
```

## Credits

Original XCat by [Tom Forbes](https://github.com/orf/xcat).
