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

### Robust Detection on Real-World Predicates
Boolean detection now works when the injection point is **not** the last term in the XPath predicate — the common authentication-bypass shape `…[username='?' and password='…']`, where a trailing `and password=…` clause used to neutralise every payload and produce a silent "No injections detected":
- **Double-or injectors** (`DUMMY' or … or '`) isolate any trailing clause into a dead `or` branch, and use a non-matching dummy so a valid working value can't pin the predicate true
- **Redirect-aware oracle** — `--true-location` matches the 302 `Location`/final URL and `--no-follow-redirects` evaluates the raw redirect, for login flows whose only true/false signal is *where* they redirect
- **Regex oracle** — `--true-regex` for body matches a fixed substring can't express
- **Oracle calibration** — a misconfigured oracle is reported distinctly ("matched every / no probe") instead of an opaque error, and extraction aborts loudly if the oracle stops differentiating rather than emitting a fabricated document

### Other Improvements
- Expanded character search space to all 95 printable ASCII characters
- Improved robustness across different application behaviors

## Features

- Auto-selects injections (run `xcat-ng injections` for a list)
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

```bash
pipx install git+https://github.com/Xorriath/xcat-ng.git
```

Or from source:
```bash
git clone https://github.com/Xorriath/xcat-ng.git
cd xcat-ng
pip install poetry
poetry install
```

## Usage

### Boolean-Based Blind Extraction
```bash
# GET request with content-based detection
xcat-ng run http://target/page.php q q=value --true-string='Success'

# POST form with negated match
xcat-ng run http://target/page.php username username=admin msg=test \
  -m POST --encode FORM --true-string='!Error'
```

### Authentication Bypass (redirect-signalled)
```bash
# username AND password predicate; success vs failure differ only by redirect target.
# The double-or injector handles the trailing `and password=...`; match on the Location.
xcat-ng run http://target/login.php username username=admin pass=test -m POST --encode FORM --no-follow-redirects --true-location=user.php
```

### In-Band Extraction
```bash
# Extract data directly from response bodies (much faster)
xcat-ng run http://target/page.php q q=value f=field \
  --true-string='Result' --inband
```

### Time-Based Blind Extraction
```bash
# When responses are identical — use timing as the oracle
xcat-ng run http://target/page.php username username=admin msg=test \
  -m POST --encode FORM --time 6
```

### Detection & Shell
```bash
# Detect injection types and XPath features
xcat-ng detect http://target/page.php q q=value --true-string='Success'

# Interactive shell for manual exploration
xcat-ng shell http://target/page.php q q=value --true-string='Success'
```

## Credits

Original XCat by [Tom Forbes](https://github.com/orf/xcat).
