Follow along at: __[https://github.com/ptudor/betterhttpd](https://github.com/ptudor/betterhttpd)__

My name is Patrick Tudor and this is Better Websites with Apache HTTP Server.

ptudor@[ptudor.net](https://www.ptudor.net)

For many today, their experience with the Internet is through web browsers and applications that rely on API calls over HTTPS. I am glad you are taking your time to trust my opinions might hold some little bit of information you can take home and make your piece of the Internet a better place.

I've been using Apache httpd for various things basically since the fork from UIUC's NCSA httpd when I was a teenager. Fortunately innovation didn't end with Mosaic but also now we have CSPs, HSTS, TLS, et cetera and a world of new computer languages.

There are alternatives: IIS, nginx, and everything else on the [Wikipedia comparison](https://en.wikipedia.org/wiki/Comparison_of_web_server_software) and [Wikipedia category](https://en.wikipedia.org/wiki/Category:Web_server_software). You also may be using haproxy, varnish, or something else from the [Reverse Proxy category](https://en.wikipedia.org/wiki/Category:Reverse_proxy). And above that the world of hardware load balancers, nevermind Kubernetes Services and OpenShift Routes in the mix now too. Use what's best for the task at hand.

Modern webservers are incredibly fast. Run your own benchmarks and tune your application servers. I can create a slow website by using mod_php, make it better with `opcache.validate_timestamps=0`, and make it fast with php-fpm. Response time for humans is more important than bragging about raw hits served to bots.

# Index 

- Shortcuts
- Read The Documentation
- Web Browsers and Inspectors
- Core Modules
- Macros
- Client Conversation
- Errors
- Common Files
- HSTS, CSP, CORS
- Caching
- ProxyPass and Balancer
- Status Pages
- Logs

## Shortcut to a fast website

```
<Location "/">
  Header setifempty Cache-Control "public, immutable, s-maxage=7200, max-age=172800"
  CacheEnable disk "/"
  AllowMethods GET
</Location>
Header always set Server "Apache"
```

Turn on the client cache, turn on the server cache, drop unused methods, and benefit.

## Shortcut to a slow website

Allow unused methods, disable the server cache, and demand clients never locally store the content we send.

```
<Location "/">
  SetEnv no-cache
  Header always set Cache-Control "no-store"
</Location>
```

When multiple [Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control) values are listed, "the most restrictive directive should be honored."

## Read the documentation.

The documentation is great and filled with many examples. Start with core, and the list of modules. Keep coming back; the Apache documentation team does a great job and I've seen many great edits in the last few years.

I want to point out these four items in particular:

### Reverse Proxy guide

There is a [Reverse Proxy guide](https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html). A complementary feature is [mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html) for an `X-Forwarded-For` handler. Support for `RemoteIPProxyProtocol` exists, really useful for client-cert auth behind an intermediate device.

### Expressions

When you see an Apache 2.2 configuration using RewriteRules, you can probably make a better config in Apache 2.4 with expressions.

Documentation on [Expressions in Apache HTTP Server](https://httpd.apache.org/docs/current/expr.html).

Log only specific errors:

```
CustomLog logs/access-errors-405-410.log common "expr=%{REQUEST_STATUS} -in {'405','410'}"
```

Use `If` for string or integer comparison against variables.

```
<If "%{HTTPS} == 'off'">
    Header set X-Cleartext true
</If>
```

An aside, [FallBackResource](https://httpd.apache.org/docs/trunk/mod/mod_dir.html#fallbackresource) can also replace RewriteEngine things. I like 404s but if you want a 200 everywhere...

```
FallBackResource /index.html
```

Or maybe you don't want a 200 or 404. You could make a 503 by combining a `RedirectMatch 503 (.*)` and `ErrorDocument 503`. Many RewriteRules from old examples have better options in 2.4.

**L,R?** _Why?_

```
RewriteRule ^/podcasts/(.*)$ http://podcasts.toomuchrock.com/$1 [L,R]
```

**Redirect?** _Nice:_

```
RedirectMatch 307 ^/podcasts/(.*)$ http://podcasts.toomuchrock.com/$1
```

### Avoid htaccess files

For the sake of disk IO, you want htaccess support disabled. A request for /a/b/c/d/index.html isn't opening just one file, it's trying to open .htaccess in /, /a, /a/b, /a/b/c, and finally /a/b/c/d. On every single hit.

```
<Directory "/">
    AllowOverride None
    AllowOverrideList None
</Directory>
```

### Avoid old access control

When I see `Order allow,deny` in a configuration I am immediately concerned. "[You should avoid using them, and avoid outdated tutorials recommending their use.](https://httpd.apache.org/docs/2.4/howto/access.html)" This must be updated to `Require` syntax, like `Require all granted` or `Require all denied` instead.

## Web browsers

KDE's Konqueror had a big influence two decades ago. Briefly, it was forked by Apple into Webkit for Safari and then forked by Google into Blink for Chrome. Check out Wikipedia's [Comparison of Browser Engines](https://en.wikipedia.org/wiki/Comparison_of_browser_engines) for details.

I suggest running the development versions of browsers for fun. Safari Technology Preview, Chrome Canary, and Firefox Developer Edition are all on my Dock.

### Web inspector

Every browser has a web inspector, Command-Option-I for me, you may have to enable the Develop menu in Safari to expose it.

Reload a page and explore the request. I spend most of my time in the inspector directly reading headers or looking at the Network tab for timing and sizes, sometimes the Security tab. This is the place to inspect and edit or delete cookies and local storage. The console is probably telling you why a resource was rejected.

Something Firefox in particular does well formatting raw JSON files.

Chrome has a convenient "Copy url as curl command" menu item. 

Also check out "Server-Timing" headers to expose application metrics to the web inspector, with a great overview at [this Fastly blog post](https://www.fastly.com/blog/supercharging-server-timing-http-trailers). 

### wget and curl

I have `wget -S` and `curl -v` memorized. More complex examples I don't have memorized but I do commonly request a file be saved with the remote timestamp, particularly in scripts, so on subsequent requests clients can send an `If-Modified-Since` request and servers can respond with a `304 Not Modified` response so the request is faster for the client and cheaper for the server.

```
while true; do
  wget -S -N -o /dev/null --compression=auto \
    --user-agent=ptudornet-wget --header="Cookie: a=1" \
    --prefer-family=IPv6 --method=GET http://localhost
  sleep 2
  curl --verbose --location --remote-time \
    --output /dev/null --cookie "b=2" --compressed \
    --user-agent=ptudornet-curl http://localhost
  sleep 2
  curl -v -L -R -o /dev/null -b /tmp/cookiejar -c /tmp/cookiejar \
    -A ptudornet-curl -X GET http://localhost
  sleep 2
done
```

This is an elementary loop but only use your troubleshooting skills for good. We are at a conference in a country where the [Computer Fraud and Abuse Act](https://en.wikipedia.org/wiki/Computer_Fraud_and_Abuse_Act) applies to your decisions. Read [the complaint in USA v Gad](https://www.documentcloud.org/documents/6782920-USA-v-Dam.html) to see how the FBI investigated a website outage in 2020.

## Headers, in and out

Notice "br" for [Brotli](): `Accept-Encoding: gzip, deflate, br`. We will [enable support for mod_brotli](https://gist.github.com/ptudor/90b44c72997580af9baada6e1554a871) later.

When a browser tells us the language of the user, we can try to accomodate them: `Accept-Language: en-US,en;q=0.9`. Later, we will import localized error messages maintained by Apache.

Response from Wikipedia:

```
Age: 0
Cache-Control: private, s-maxage=0, max-age=0, must-revalidate
Content-Encoding: gzip
Content-Language: en
Content-Type: text/html; charset=UTF-8
Date: Fri, 01 Dec 2022 02:28:30 GMT
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Strict-Transport-Security: max-age=106384710; includeSubDomains; preload
Vary: Accept-Encoding,Cookie,Authorization
```

Response from IANA:

```
HTTP/1.1 200 OK
Age: 1523
Cache-Control: public, max-age=3600
Connection: Keep-Alive
Content-Encoding: br
Content-Length: 1180
Content-Security-Policy: upgrade-insecure-requests; default-src 'self' ...
Content-Type: text/html; charset=UTF-8
Date: Fri, 01 Dec 2022 03:35:15 GMT
Expires: Fri, 01 Dec 2022 04:09:55 GMT
Keep-Alive: timeout=2, max=358
Last-Modified: Tue, 05 Oct 2021 16:31:06 GMT
Referrer-Policy: same-origin
Server: Apache
Strict-Transport-Security: max-age=48211200; preload
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

Response from maintenance.icann.org:

```
HTTP/1.1 503 Service Unavailable
Accept-Ranges: bytes
Connection: close
Content-Encoding: br
Content-Language: en, ar, fr, es, ru, zh
Content-Length: 1178
Content-Type: text/html; charset=UTF-8
Date: Fri, 01 Dec 2022 04:58:50 GMT
ETag: "ac7-5117f2375e140-br"
Last-Modified: Tue, 17 Mar 2015 17:17:17 GMT
Referrer-Policy: origin-when-cross-origin
Retry-After: 30
Server: Apache
Vary: Accept-Encoding
X-Frame-Options: SAMEORIGIN
```

# Apache Core and Modules

[Apache Module Index](https://httpd.apache.org/docs/2.4/mod/)

Double check you are using the [Event MPM](https://httpd.apache.org/docs/2.4/mod/event.html). Historically, default configurations from vendors tended to prefer working out-of-the-box with mod_php and [prefork](https://httpd.apache.org/docs/2.4/mod/prefork.html) instead of requiring php-fpm so doublecheck for event. Another historical consideration is bumping your nprocs ulimit value by ten-fold or as needed. (In `top` a capital-H switches between tasks and threads.)

Start with the [common worker configurations](https://httpd.apache.org/docs/2.4/mod/mpm_common.html). You probably will never need to adjust your `ServerLimit` but here is where you will find it.

New since 2.4.17, `ListenCoresBucketsRatio` is disabled by default but looks interesting for bare-metal. The [documentation](https://httpd.apache.org/docs/2.4/mod/mpm_common.html#listencoresbucketsratio) states: "On systems with a large number of CPU cores, enabling this feature has been tested to show significant performances improvement and shorter responses time."

For a happy user experience, you want graceful shutdowns of the Apache process when exiting. In your Kubernetes deployment this means a preStop hook on the container process to killall -WINCH httpd instead of the default SIGTERM. With the WINCH signal the process will continue to serve existing connections like someone downloading a PDF instead of your customer's web browsers redirecting to a local error that says "the remote server went away mid transaction, computers are hard, try later."

```
GracefulShutdownTimeout 600
```

```
lifecycle:
  preStop:
    exec:
      command: ["/bin/kill","-WINCH","1"]
```

For more detail about signals, refer to [stopping httpd](https://httpd.apache.org/docs/2.4/stopping.html)

## Core:

All the main config options are part of [core](https://httpd.apache.org/docs/2.4/mod/core.html) so let's highlight a couple.

### Define

You may notice with `ps` your httpd process has flags after a -D like FOREGROUND. You can add run-time defines when executing the process, like a flag for testing new features, and then later use `Define` to put that default state in your config files. (Besides `IfDefine` see also `IfFile`, and `Include` and `IncludeOptional`). Try to make sure your equation adds up: You may want to create a default and then later `UnDefine` that default if other flags are present.

```
Define PRIMARY
<IfDefine SECONDARY>
  DocumentRoot /var/www/html/secondary
  UnDefine PRIMARY
</IfDefine>
<IfDefine PRIMARY>
  DocumentRoot /var/www/html/primary
</IfDefine>
```

### Directory and Location

Let's review the relationship between Directory, File, and Location. More details at [Filesystem, Webspace, and Boolean Expressions](https://httpd.apache.org/docs/2.4/sections.html#file-and-web).

`Directory` operates on the process file system like /var/www/html/a/b that is outside the `DocumentRoot` and `ServerRoot` boundaries.

`File` is a file served directly from a local disk like index.html

`Location` refers to the URL path like /a/b. Because it's operating on the URL instead of a filesystem directory it is useful with proxied paths.

`Alias` lets us redefine those slightly as with my UUIDs you will real soon grow tired of seeing.

Quoting from that webpage, "When applying directives to objects that reside in the filesystem always use `<Directory>` or `<Files>`. When applying directives to objects that do not reside in the filesystem (such as a webpage generated from a database), use `<Location>`."

```
<Directory "/var/www">
  Require all denied
  #Options +Indexes +FollowSymLinks
  Options None
  AllowOverride None
</Directory>
```

```
<Files ".env">
  Require all denied
</Files>
```

A regex is supported here (and many other directives) with a discouraged `~` or the preferred "Match" suffix:

```
<FilesMatch "^(phpinfo.php|test.php)$">
  Require env acl_rfc1918
</FilesMatch>
```

The order of [merging](https://httpd.apache.org/docs/2.4/sections.html#merging) and matching can influence your results. In short, `Directory` and `File` precedes `Location` and `If` follows those. The `Location` is a last-match item, in contrast to `Alias` and `ProxyPass` where first-match demands your more-specific paths be first.

```
<Location "/">
  Require all granted
  Header unset X-Request-Id
</Location>
<Location "/private">
  Require env acl_rfc1918
</Location>
<Location "/private/forbidden">
  Require all denied
</Location>
```

There are times you want to turn off authentication on a sub-directory, like when an password protected website needs to display an error message. Explore an [authentication overview](https://httpd.apache.org/docs/2.4/howto/auth.html).

```
<Location "/">
  Require valid-user
  Header unset X-Powered-By
</Location>
<Location "/error">
  Require all granted
</Location>
```

A similar example with HTTP methods. You might turn off POST on your website to return a 405 status instead, but maybe there is a single form. Have a more specific location with a different config.

```
<Location "/">
  AllowMethods GET
</Location>
<Location "/contact/submit">
  AllowMethods GET POST
</Location>
```

Using an `Alias` is convenient to map common files.

```
Alias "/fake.html" "/real.html"
Alias "/robots.txt" "/var/www/common/well-known/robots.txt"
```

### Limits

You might want to know there are reasonable limits on inbound requests before the client is dropped. Particularly because in 2.4.53 and earlier, `LimitRequestBody` was unlimited. It now has a default of one gigabyte.

```
LimitRequestBody 102400       # default 1073741824 bytes
LimitRequestFields 24         # default 100
LimitRequestFieldSize 8186    # default 8190
MaxKeepAliveRequests 500      # default 100
```

### Protocols

I like strict protocol options. The most obvious benefit is it requires RFC-compliant CRLF termination for newlines. No big deal, add a `--crlf` flag to s_client or netcat or whatever. When using HTTP/2, be mindful of [connection coalescing](https://daniel.haxx.se/blog/2016/08/18/http2-connection-coalescing/).

```
HttpProtocolOptions Strict LenientMethods Require1.0
Protocols h2 http/1.1
ServerAdmin error@example.com
ServerSignature Off
ServerTokens Prod
TimeOut 19
```

Without the `ServerTokens` option, default error pages and the Server header include the version and OS and some module versions.

### Listen Ports

The IANA assigned port numbers for the http and https services, 80 and 443, are below 1024 so out of the box the process must launch as root. There's a bunch of scenarios that require running on different ports or as different users so here's a quick hint to pick another port of the 65k.

```
sed -i -e "s/^Listen 80$/#see: 10-listen.conf Listen 8080/g" /etc/httpd/conf/httpd.conf
echo "Listen 8080" >> /etc/httpd/conf.d/10-listen.conf
echo "Listen 8443 https" >> /etc/httpd/conf.d/10-listen.conf
```

Let's say OpenShift is assigning a userid so we're touching the user and group here. Be mindful wherever you run your webserver that the daemon is a different userid than the read-write owner of the files it serves.

```
sed -i -e "s/^User apache$/#openshift User apache/g" /etc/httpd/conf/httpd.conf && \
sed -i -e "s/^Group apache$/Group root/g" /etc/httpd/conf/httpd.conf
```

### Coming up...

Later we'll come back to `ErrorLogFormat` and add a request uniqueid and then when we enable the status and info handlers `ExtendedStatus On` will matter.

## Macros

These are templates expanded at run-time. The first example lets a website share a config between cleartext and TLS listeners.

```
<Macro virtualhostBaatriikDotShabaka>
  ServerName xn--mgbbh2a9fub.xn--ngbc5azd
  ServerAlias xn--h28h.gemmagps.com
  # .....
</Macro>

# if we see a Host header that doesn't match a ServerName, redirect to the Most Correct hostname.
<VirtualHost _default_:8080>
  ServerName default-redirect-0661140e-17ce-4b8b-b320-5ddcb998113c
  Redirect / https://xn--mgbbh2a9fub.xn--ngbc5azd/
</VirtualHost>

<VirtualHost *:8080>
  Use virtualhostBaatriikDotShabaka
</VirtualHost>

<VirtualHost *:8443>
  Use virtualhostBaatriikDotShabaka
  Include conf.d/include/tls.conf
</VirtualHost>
```

You might have a list of certain paths that are proxied to various places, consider sending them as parameters.

```
<Macro ProxyTwoOptions ${path} ${timeout}>
  ProxyPass /{$path}/ http://localhost/${path}/ timeout=${timeout}
</Macro>

Use ProxyTwoOptions fast 2
Use ProxyTwoOptions slow 12

UndefMacro ProxyTwoOptions
```

Result:

```
ProxyPass /fast/ http://localhost/fast/ timeout=2
ProxyPass /slow/ http://localhost/slow/ timeout=12
```

I use Macros for VirtualHosts and ProxyPass lines and that's about it. Be careful to use `UndefMacro` when nesting macros.

## Variables from Client Info

A web browser tells us all sorts of cool things. We can find out the name of the application, the source address, cookies, the preferred language, and so on.

(We'll add and remove headers below using [mod_headers](https://httpd.apache.org/docs/2.4/mod/mod_headers.html).)

### User-Agent

Easily spoofed but frequently accurate, we get the User-Agent with details on the application name and OS, say, Chrome on Android or Safari on an iPhone. 

```
BrowserMatch ^$ acl_useragent_null
BrowserMatch "^htpdate/" acl_useragent_htpdate
```

A surprising number of requests do not include a user agent.

```
<If "env('acl_useragent_null') == 1 " >
  Redirect permanent / http://localhost/
</If>
```

Here are two contrived examples of using that variable to strip an inbound header:

```  
# Use an If for more complex situations, or,
# use the env tag, both these statements do the same thing:
<If "env('acl_useragent_htpdate') == 1 " >
  RequestHeader unset Cache-Control
</If>
RequestHeader unset Cache-Control env=acl_useragent_htpdate
```

Never depend on the client-provided User-Agent header for reliable information:

```
export useragent=$(date +%s.%N) && echo gdate: ${useragent} && echo bash5: ${EPOCHREALTIME}
```

### Client Source Address

Working with a web server you juggle three IP addresses: the Client, the Peer, and the Local IP addresses. Client is the most remote address, as reported by X-Forwarded-For and mod_remoteip, the Peer is the intermediate proxy that actually handshaked with us, and the Local address is where the daemon is listening and accepted the connection.

That information can be used to tag abuse or limit paths by network.

```
SetEnvIfExpr "-R '100.64.0.0/10'" acl_addr_cgn
SetEnvIfExpr "-R '10.0.0.0/8' || -R '172.16.0.0/12' || -R '192.168.0.0/16'" acl_addr_rfc1918
SetEnvIfExpr "-R '192.0.2.0/24' || -R '2001:db8::/32'" acl_addr_documentation  
SetEnvIfExpr "-R '10.146.29.71/32'" acl_deny_with_200
SetEnvIfExpr "-R '10.82.201.4/32'" acl_deny_with_503

<Location "/">
  <If "env('acl_deny_with_503') == 1 " >
    #RedirectMatch 503 ^/(?!error/)(.*)$
    Redirect 503 /
    ErrorDocument 503 "Server error. Possibly catastrophic and permanent."
  </If>
  <If "env('acl_useragent_abuse') == 1 " >
    DirectoryIndex contact-us-about-your-abuse.html
  </If>
</Location>
  
<Location "/acl">
  # RequireAny is implied, only RequireAll needs a specific clause
  Require env acl_addr_cgn
  Require env acl_addr_rfc1918
</Location>
```

### Test with ACL-dependent headers

In this example where we look for the presence of a cookie sent by the client, the response header is only sent to the client when the ACL matches.

```
<Location /cookie>
  Session On
  SessionCookieName httpd_session \
    path=/private;domain=example.com;httponly;secure;SameSite=Lax;version=1
  # add the "expiry" key thus:
  SessionMaxAge 7776000 # 86400 * 90
  # "Multiple keys can be specified in order to support key rotation."
  # "The first key listed will be used for encryption"
  SessionCryptoPassphrase aQYEUZzKggZiQjQ6TpgQ DKBFdmxvTXKK9ossbjKZQ

  <If "%{HTTP_COOKIE} =~ /httpd_session/">
    Header set X-Matched-Cookie "httpd_session" env=acl_rfc1918
  </If>
  <Else>
    Header set X-Matched-Cookie "none" env=acl_rfc1918
  </Else>
</Location>
```

This is an incomplete session example but we're just using it to create a cookie for the expression.

### Inspect Accept-Language header

A browser sends a header to the server listing the languages it is configured to prefer. A couple years ago someone emailed me to say they'd recently started a business by the same name as a dotcom I own. So I added a clause to that config looking for Hungarian web browsers on the root document, as if someone typing a URL by hand, and redirected from my dotcom to the ccTLD domain of the same name.

```
<LocationMatch "^/$">
  <If "%{HTTP:Accept-Language} =~ /hu-HU/">
    Header set X-Courtesy-Redirect ptudor
    RedirectMatch 307 https://www.example.com/
  </If>
</LocationMatch>
```

Accept-Language is a great header to chart from your logs. Instead of guessing what language your customer wants based on geolocation or making them pick a flag in a webapp, you can explore exactly what the web browser prefers.

## Make errors more pleasant

All sorts of conditions lead to error messages. Maybe someone hand-typed a URL and got a 404, or tried to authenticate to an htpasswd site where the error messages also require credentials. I type in /404/404 as a URL any time I need a quick check. Our overall goal with Apache is to avoid a message like this: "Additionally, a 404 Not Found error was encountered while trying to use an ErrorDocument to handle the request."

### Create your own

Not all errors are bad. Consider the intentional 503 to a specific IP address earlier or this 410 for a particular file extension that we decided should be neither a 404 nor a 200.

```
Redirect 308 "/wp-login.php" http://localhost/wp-login.php
Redirect 404 "/.env"
Redirect 404 "/Dockerfile"
Redirect 403 "/struts/webconsole.html"
RedirectMatch 403 "/\.git"
RedirectMatch 403 "/\.svn"
RedirectMatch 410 "^(.*)\.asp$"
```

This more complex version demonstrates flexibility. You might see something similar with `ProxyPass` statements where inside or outside a Location block are both valid, with slightly different syntax because the path is known from the Location.

```
<LocationMatch "^/wp-login.php$">
  Redirect 308 http://localhost/wp-login.php
</LocationMatch>
```

Be extra cautious about your trailing slashes on redirects. Test things.

```
Redirect 307 / https://www.example.com/
```

A request for /alpha/bravo transforms to alpha/bravo when it is appended because of the left slash, so the right element must have a matching slash to avoid inventing a TLD (top level domain) of comalpha.

### Translated Error Messages

You shouldn’t need to be literate in English and limited to ASCII to use the Internet. Use the language and script you learned in school, that you use in commerce and government. If a letter in your name has an accent or tilde or umlaut, and your keyboard has that character, it should work on the Internet. I learned Arabic script in college so to help me explore Internationalized Domain Names (IDN) I have the domain [باتريك.شبكة](https://باتريك.شبكة). Creating DNS records in other scripts and testing for rendering errors in software connects to the existing content outside ASCII already on websites. But what happens when there's a 404 or 502?

Part of making the Internet friendlier that is important for me is serving translated error messages that soften the insult of a computer telling a human it failed. Or at least something more useful than "Guru mediation failed" as another powerful webserver does.

- [Documentation Guide](https://httpd.apache.org/docs/2.4/custom-error.html)
- [README](https://svn.apache.org/viewvc/httpd/httpd/trunk/docs/error/README?view=co)
- [conf](https://svn.apache.org/viewvc/httpd/httpd/trunk/docs/conf/extra/httpd-multilang-errordoc.conf.in?view=markup)
- [src](https://svn.apache.org/viewvc/httpd/httpd/trunk/docs/error/)

Check out the list of translated languages and contributors in the README, maybe you know a language that isn't listed. I think it's so cool I know the guy who did the Russian translations because the work he did on his keyboard may be on your computer already.

I find it is easiest to test dynamic languages with FireFox. Picking, choosing, re-ordering languages, all easiest with FireFox.

So let's enable multilang-errordoc.conf but change the default /error path for fun.

```
cp /usr/share/doc/httpd/httpd-multilang-errordoc.conf /etc/httpd/conf.d/10-multilang-errordoc.conf
echo 'Alias /error/include/ "/var/www/common/error/include"' >> /etc/httpd/conf.d/10-multilang-errordoc.conf
sed -i -e "s% /error/% /1234abcd-1234-abcd-8033-e46cf419856e/e7a5e4de-3086-452e-8949-c801f0d04310/%g" /etc/httpd/conf.d/10-multilang-errordoc.conf
```

Create the local HTML somehow. We'll get to the CSS in one moment.

```
install -d -m 0755 -o 0 -g 0 /var/www/common/error/include
install -m 644 -o 0 -g 0 /dev/null /var/www/common/error/include/top.html
install -m 644 -o 0 -g 0 /dev/null /var/www/common/error/include/bottom.html
install -m 644 -o 0 -g 0 /dev/null /var/www/common/error/include/error.css
```

Some folks dislike echoing back the "Referer" header contents in styled 404s so here's a quick edit:

```
sed -i -e "/if expr/,/else/d" /usr/share/httpd/error/HTTP_NOT_FOUND.html.var && \
sed -i -e "/endif/d" /usr/share/httpd/error/HTTP_NOT_FOUND.html.var
```

### Automatic Directory Index

If you have a list of files in a directory you want to expose as download links, use [mod_autoindex](https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html) which has a bunch of options.

```
Alias /1234abcd-1234-abcd-8033-e46cf419856e/05d7c2aa-4cc9-4cba-b409-131daa8e0906 /var/www/common/autoindex
<Directory "/var/www/common/autoindex">
  Require all granted
</Directory>
<Directory "/var/www/html/mirror">
  # see also IndexStyleSheet
  HeaderName /1234abcd-1234-abcd-8033-e46cf419856e/05d7c2aa-4cc9-4cba-b409-131daa8e0906/HEADER.html
  ReadmeName /1234abcd-1234-abcd-8033-e46cf419856e/05d7c2aa-4cc9-4cba-b409-131daa8e0906/README.html
  Options Indexes FollowSymLinks # enable MultiViews for translated content
  IndexOptions +HTMLTAble +FancyIndexing +FoldersFirst +IgnoreCase +SuppressDescription +SuppressIcon +NameWidth=* +Charset=UTF-8
  # other options of note: TrackModified, VersionSort, SuppressHTMLPreamble 
  IndexOrderDefault Ascending Name
</Directory>
```

I disable icons because some fingerprinting scanners complain and it's true, search for "originally made for Mosaic for X" and there are plenty of results. If you like using icons, check out `AddAlt` to create text for screen readers and spend a moment to find some fresher replacement icons you can extract in place. Stepping away from RPMs for a moment, here's an Ubuntu manpage for [apache-icons](https://manpages.ubuntu.com/manpages/jammy/en/man7/apache-icons.7.html) which includes Tango and FontAwesome images in its [repo](https://git.open-infrastructure.net/software/service-tools/tree/apache) and [config](https://git.open-infrastructure.net/software/service-tools/tree/apache/share/apache/mods/000-apache-icons.conf).

```
sed -i -e "s%Alias /icons/%Alias /dyzeBSyvGUsUqa/%g" /etc/httpd/conf.d/autoindex.conf
```

Make the HTML files:

```
install -d -m 0755 -o 0 -g 0 /var/www/common/autoindex
install -m 644 -o 0 -g 0 /dev/null /var/www/common/autoindex/HEADER.html
install -m 644 -o 0 -g 0 /dev/null /var/www/common/autoindex/README.html
install -m 644 -o 0 -g 0 /dev/null /var/www/common/autoindex/autoindex.css
```

An aside about /index.html: I want every website to have an index.html, the `DirectoryIndex` default, telling me the name of the site I've connected to, not a blank white screen. Be aware there is a default rule, welcome.conf, that confuses folks when their browser gets styled content but the status code is a 403 failing healthchecks because no index.html exists.

### CSS

As you saw hints of just above, your Apache config wants CSS in two places. First, mod_autoindex, and second, for the error messages. In a moment we'll add a stylesheet for fonts but first, remember we're adding CSS as a file instead of in-line for the benefit of our content security policy header. This is plain HTML but you can do anything you want to make the content look prettier.

HTML:

```
<link rel="stylesheet" href="/1234abcd-1234-abcd-8033-e46cf419856e/e7a5e4de-3086-452e-8949-c801f0d04310/error.css">
```

```
<link rel="stylesheet" href="/1234abcd-1234-abcd-8033-e46cf419856e/05d7c2aa-4cc9-4cba-b409-131daa8e0906/autoindex.css">
```

Public examples: [InterNIC](https://www.internic.net/domain/); [IANA](https://data.iana.org/ksk-ceremony/).

### WOFF

When you have a third party host your web fonts, your access logs are also their access logs.

You can make your own web fonts, converting TrueType to WOFF2 with [woff2_compress](https://github.com/google/woff2).

```
dnf -y install woff2-tools overpass-fonts liberation-fonts \
google-noto-sans-fonts dejavu-sans-fonts dejavu-serif-fonts \
bitstream-vera-sans-fonts bitstream-vera-sans-mono-fonts bitstream-vera-serif-fonts
install -d -m 0755 -o 0 -g 0 /var/www/typeface
cp -a /usr/share/fonts/google-noto /var/www/typeface/google-noto
for ii in $(ls /var/www/typeface/google-noto)
  do time woff2_compress /var/www/typeface/google-noto/${ii}
done
```

Or, generate CSS and multiple formats with the [mkwebfont script from font-tools](https://copr.fedorainfracloud.org/coprs/mbignami/font-tools/).

```
dnf copr enable mbignami/font-tools ; dnf -y install font-tools
dnf search fonts ; ls /usr/share/fonts
install -d -m 0755 -o 0 -g 0 /var/www/webfont
install -d -m 0755 -o 0 -g 0 /var/www/webfont/google-noto
install -d -m 0755 -o 0 -g 0 /var/www/webfont/overpass
mkwebfont -d /var/www/webfont/google-noto -f google-noto /usr/share/fonts/google-noto/*.ttf
mkwebfont -d /var/www/webfont/overpass -f overpass /usr/share/fonts/overpass/*.otf
```

Now expose your files. In a few sections we'll take care of the Allow Origin header for fonts.

```
Alias /1234abcd-1234-abcd-8033-e46cf419856e/95a2e095-9767-4808-bc5c-a90017688a7c/ /var/www/webfont/
Alias /1234abcd-1234-abcd-8033-e46cf419856e/ac68c38e-c3e4-46dc-af31-cb085d425ff1/ /var/www/typeface/
<Directory "/var/www/webfont">
  ExpiresActive on
  ExpiresDefault "access plus 1 year"
</Directory>
# alternative
<Location "/1234abcd-1234-abcd-8033-e46cf419856e/95a2e095-9767-4808-bc5c-a90017688a7c/">
  ExpiresActive on
  ExpiresDefault "access plus 1 year 1 month 1 week 1 day 1 hour 1 minute 30 seconds"
</Location>
```

HTML:

```
<link rel="stylesheet" href="/1234abcd-1234-abcd-8033-e46cf419856e/95a2e095-9767-4808-bc5c-a90017688a7c/google-noto/google-noto.css">
<link rel="stylesheet" href="/1234abcd-1234-abcd-8033-e46cf419856e/95a2e095-9767-4808-bc5c-a90017688a7c/overpass/overpass.css">
```

### Bonus

Better nginx error messages because all servers should be nicer to web browsers:

```
error_page   500 502 503 504  /50x-nginx.html;
  location = /50x-nginx.html {
    root   /usr/local/www/nginx/common/error;
    internal;
  }
```

## Shared Files

For consistent branding across sites, you can have Apache serve a common file like favicon.ico or [security.txt](https://en.wikipedia.org/wiki/Security.txt).

```
Alias "/.well-known/security.txt" "/var/www/common/well-known/security.txt"

Alias /favicon.ico /var/www/common/images/favicon.png
Alias /wp-content/themes/default/assets/images/favicon.png /var/www/common/images/favicon.png
Alias /apple-touch-icon.png /var/www/common/images/apple-touch-icon.png

<FilesMatch "^(favicon.ico|favicon.png|apple-touch-icon.png)$">
  # 60 * 60 * 24 * 52
  Header set Cache-Control "max-age=4492800, public, immutable"
  # consider ExpiresByType for similar results
</FilesMatch>
```

You'll possibly need to exclude these paths from your proxy with the trailing exclamation mark:

```
ProxyPassMatch "^/(favicon.ico|favicon.png|apple-touch-icon.png)$" !
```

## Security with HSTS, CSP, and CORS

### HSTS

TLS is a basic element of the modern web and setting aside the encryption benefits, it is useful for establishing the authenticity of the web server your computer handshaked with. If you have old websites still serving traffic on port 80, you can shift browsers toward port 443 with a CSP that converts 'http' links into 'https' on the client side and then after a secure channel is established, the Strict Transport Security header will be trusted and future communication will avoid port 80.

```
Header setifempty Content-Security-Policy "upgrade-insecure-requests"
Header setifempty Referrer-Policy "strict-origin-when-cross-origin"
Header set Strict-Transport-Security "max-age=63158400; preload"
```

HSTS prevents intercepted communications from being forcefully downgraded. In short, an intermediate proxy could notice a port 80 redirect from http to https, not return that to the client instead respond with any html over the http channel stripped of references to https; check out sslstrip. Nonetheless, where you listen on port 80, add a redirect to 443 unless you're serving a CRL or some edge case.

If you use mod_md, with `MDRequireHttps permanent` it can send both the redirect and the HSTS header for you.

Notice in all the header examples the use of "set" or "setifempty" as the verb because "add" appends instead of replacing. Oops:

```
X-Content-Type-Options: nosniff, nosniff
X-Frame-Options: SAMEORIGIN, SAMEORIGIN
```

A quick aside, here's an example of using Apache to change strings in HTML after the content has been fetched.

```
AddOutputFilterByType SUBSTITUTE text/html
Substitute "s|galmon.eu|gpsmon.us|nq"
Substitute "s|</body>|<!-- <p align=\"center\">html string substitution in apache</p> --></body>|i"
```

You might need to inflate if you're trying to sed on a proxy.

```
AddOutputFilterByType INFLATE;SUBSTITUTE;DEFLATE text/html
```

### CSP

A [content security policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (CSP) defines a list of remote hosts the web page is allowed to load resources from. Adding a CSP is generally a matter of looking in the Inspector and making the list of external URLs; exceptions for inline CSS and JS will quickly start to annoy you.

```
Header set Content-Security-Policy "upgrade-insecure-requests; default-src 'self' https://wgshell.com; \
script-src 'self'; style-src 'self'; child-src 'self' https://ota.bike; img-src 'self' https://ota.bike;"
```
Whitespace is interpreted literally by `Header` but backslashes are okay for line continuations.

A sometimes-seen element of CSPs are [nonces](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/nonce) for providing some level of authenticating resources; the linked document suggests, "Always try to take full advantage of CSP protections and avoid nonces or unsafe inline scripts whenever possible."

### CORS

Be careful with [Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin) when you are doing [Cross-Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) (CORS) things. Cross-Origin Resource means files downloaded from a different website like fonts or JSON data. Don't copy-and-paste an asterisk if a hostname works better.

```
Header set Access-Control-Allow-Origin "*" env=acl_rfc1918
```

Look at this great [StackOverflow example](https://stackoverflow.com/questions/33197751/fonts-are-blocked-in-web-client-cors) that reflects the origin back conditionally although it has a typo on that page corrected here:

```
SetEnvIf Origin "https://((www|sub1|sub2|sub3)\.example\.com)$" ACAO=$0
Header set Access-Control-Allow-Origin "%{ACAO}e" env=ACAO
Header set Access-Control-Allow-Methods "GET"
```

Test it:

```
wget -S --header="Origin: https://www.ptudor.net" https://www.ptudor.net/fonts/olf/source-sans-pro/SourceSansPro-Bold.woff2
curl -v --header "Origin: https://www.ptudor.net" https://www.ptudor.net/fonts/olf/source-sans-pro/SourceSansPro-Bold.woff2
```

## Caching

### Expires header

mod_expires will prepare the Etag and Cache-Control headers for locally-served files. Look for a mime.types file if you want a list.

```
ExpiresActive on
ExpiresDefault "access plus 1 hour"
ExpiresByType application/x-debian-package "access plus 1 year"
ExpiresByType application/x-javascript "access plus 15 days"
ExpiresByType font/woff2 "access plus 1 year"
ExpiresByType image/png "access plus 45 days"
ExpiresByType text/html "access plus 1 week"
ExpiresByType video/mp4 "access plus 180 days"
```

Speaking of mime, this influences how a browser displays or saves files based on extension. Somewhat related to `AddCharset` and `AddEncoding` from [mod_mime](https://httpd.apache.org/docs/2.4/mod/mod_mime.html).

```
AddType text/plain sh
AddType text/plain .sha256
AddType image/svg+xml svg
```

### Cache-Control

For proxied content, a Cache-Control header can be enforced on a path.

```
<LocationMatch "^(favicon.ico|favicon.png|apple-touch-icon.png)$">
  Header set Cache-Control "max-age=4492800, public, immutable"
</LocationMatch>
```

Sometimes you want to force a proxied document into the cache, but it is missing headers and you don't want to cache abnormal response codes. Here's a conditional Cache-Control header:

```
<Location "/download/">
  Header set Cache-Control "public, s-maxage=86399, max-age=259197" "expr=%{REQUEST_STATUS} -in {'200','206','301','302','304','307','308','404','410'}"
</Location>
```

### mod_cache

mod_cache has some options I always touch: First, turn off the QuickHandler because it can bypass other checks. Then adjust the floor to include zero byte redirects and then adjust the ceiling beyond the one megabyte default. I might not want to cache an ISO but a 1.1MB image is no big deal.

```
CacheQuickHandler off
CacheMinFileSize 0
CacheMaxFileSize 2000000
```

If you want some extra status headers to show up in your web inspector, you can, but I just rely on logs and the "Age" header generally.

```
<If "env('acl_addr_rfc1918') == 1">
  CacheHeader on
  CacheDetailHeader on
</If>
<Else>
  CacheHeader off
  CacheDetailHeader off
</Else>
```

I do not like the option `CacheIgnoreQueryString` because a better choice when you are in that tough position is `CacheIgnoreURLSessionIdentifiers` like so:

```
# example: GET /static/fonts/sans-serif.woff2?version=1.0.0
CacheIgnoreURLSessionIdentifiers version
# example: GET /static/images/photograph.jpeg?timestamp=1669592938
CacheIgnoreURLSessionIdentifiers timestamp
```

If you have a cache on the root, you can exclude some paths.

```
<Location "/">
  AllowMethods GET
  CacheEnable disk
</Location>
<Location "/login">
  AllowMethods GET PUT POST PATCH OPTIONS
  SetEnv no-cache
</Location>
```

Consider storing your cache on a ram disk:

```
volumes:
- name: varcachehttpdproxy
  emptyDir:
    medium: Memory
volumeMounts:
- name: varcachehttpdproxy
  mountPath: /var/cache/httpd/proxy
  readOnly: false
```          

You need to clean the cache yourself with the `htcacheclean` script. It deletes stale files from the disk. I wish it had a daemon mode, but there's many ways to run a command on a timer or in a loop with sleep.

## Proxy, Balancer, Standby

I'll give some quick examples, but you need to [read](http://events17.linuxfoundation.org/sites/events/files/slides/mod_proxy%20Cookbook.pdf) and [watch](https://www.youtube.com/watch?v=fO9-2tY4N2Q) Daniel Ruggeri's mod_proxy Cookbook.

Avoid a default proxy on the root path if you can. Apache can serve a 404 ten times faster than your application server and your list of paths to exclude from the proxy will be shorter.

Double-check you do not have an asterisk here.

```
<Proxy />
  Require all granted
</Proxy>
```

Quickly repeating an earlier example, here is a typical ProxyPass statement:

```
<Macro ProxyTwoOptions ${path} ${timeout}>
  ProxyPass /{$path}/ http://localhost/${path}/ timeout=${timeout}
</Macro>

Use ProxyTwoOptions static 1
Use ProxyTwoOptions dynamic 3
Use ProxyTwoOptions reports 18

UndefMacro ProxyTwoOptions
```

It's likely you want to exclude some files if you have a proxy on the root, use a bang, an exclamation mark, to deny that path from the proxy handler and keep it local.

```
ProxyPass /google822c1b63853ed2.html !
ProxyPass /BingSiteAuth.xml !
ProxyPass /1234abcd-1234-abcd-8033-e46cf419856e !
ProxyPass /.well-known/security.txt !
```

Try to move toward Balancers instead so you can benefit from hot spares. Here, a downstream status of 500, 502, or 503 or a next-hop timeout will activate a secondary member to return a common error page. If you do have sorry servers that collect errors, make sure they accept any host header they might see.

```
ProxyPreserveHost on # pros and cons
<Proxy balancer://django>
  ProxySet failonstatus=500,502,503 failontimeout=On
  BalancerMember http://localhost connectiontimeout=1 retry=1 timeout=2
  BalancerMember http://sorry-server.sorry-server.svc.cluster.local:80 status=+H retry=0
</Proxy>

ProxyPass "/" "balancer://django/"
ProxyPassReverse "/" "balancer://django"
```

## Status Pages

Third party monitoring scrapers tend to look at the server status page and you might have to update the path like in [this telegraf example](https://github.com/influxdata/telegraf/blob/master/plugins/inputs/apache/apache.go#L190)

```
<Location "/1234abcd-1234-abcd-8033-e46cf419856e/206ebbc5-3c92-4767-99ba-bf8f81e21c3d/server-info">
  SetHandler server-info
  Require host localhost
</Location>

ExtendedStatus On
<Location "/1234abcd-1234-abcd-8033-e46cf419856e/2c46bf32-f5c0-480d-a9d7-455120ae56d5/server-status">
  SetHandler server-status
  Require env acl_addr_rfc1918
</Location>

<IfModule mod_proxy_balancer.c>
  <Location "/1234abcd-1234-abcd-8033-e46cf419856e/2911b5d1-ece8-442c-ae38-6185dc32bfbc/balancer-manager">
    SetHandler balancer-manager
    Require env acl_addr_rfc1918
  </Location>
</IfModule>

<IfModule mod_md.c>
  <Location "/1234abcd-1234-abcd-8033-e46cf419856e/4781b709-9b09-44b8-8104-f756ee7e26f7/md-status">
    SetHandler md-status
    Require env acl_addr_rfc1918
  </Location>

  MDCertificateStatus on
  <Location "/.httpd/certificate-status">
    Require env acl_addr_rfc1918
  </Location>
</IfModule>
```

## ACME TLS and Managed Domains

In short, Let's Encrypt.

```
<IfDefine MANAGEDDOMAINS>
  MDomain example.com www.example.com example.net www.example.net
  SSLProtocol -all +TLSv1.2 +TLSv1.3
  SSLSessionTickets Off
  Protocols h2 http/1.1 acme-tls/1
  MDStoreDir /etc/httpd/md
  MDCertificateAgreement accepted
  MDContactEmail certificate-manager@localhost
  MDPortMap http:8080 https:8443
  # "It is recommended that you have virtual hosts for all managed domains and do not rely on the global, fallback server configuration."
  MDBaseServer off
  MDPrivateKeys secp384r1 rsa4096
  MDRenewMode auto
  MDRequireHttps temporary # no HSTS header
  #MDRequireHttps permanent # with HSTS header
</IfDefine>

<IfDefine MDTRACELOGS>
    LogLevel notice ssl:info md:trace3
</IfDefine>
```

Sometimes you want to explore the webserver. You can use a shell script as a CGI to dump the environment variables the web server holds.

```
#!/bin/bash
# very dangerous shell script
echo Content-type: text/html
echo

echo "<html lang="en"><head><title>env</title></head><body bgcolor=\"#ededed\">"
echo "<p><pre>"
env
echo "</pre></p>"
echo "</body></html>"
```

This is really useful when you are trying to figure out details with your certificates and you've told mod_ssl to expose variables so you can run openssl on the client cert to compute a TLSA value.

```
<IfDefine DANGEROUS>
  ScriptAlias /1234abcd-1234-abcd-8033-e46cf419856e/7671228e-2d42-42f3-8198-e96729ed4a14/ "/var/www/cgi-bin/"
  <Directory "/var/www/cgi-bin">
    Options ExecCGI
    SSLOptions +StdEnvVars +ExportCertData
  </Directory>
</IfDefine>
```

Connect your client certificate name to the remoteuser variable for logs with [SSLUserName](https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslusername).

```
<If "%{SSL_CLIENT_S_DN} != ''">
  SSLUserName SSL_CLIENT_S_DN
</If>
```

A strong reason to use AJP instead of HTTP in your ProxyPass rules when possible is you get all the SSL metadata for free.

## Logs

The default NCSA extended log format is almost useful but we can do more. The important detail to notice in these log formats is I connect the unique_id on the request in the access log to associated messages in the error log.

When you configure your healthchecks, don't just send an HTTP/1.0 HEAD request and hope for the best. Create some kind of filter on source address or user-agent so you can filter that noise out of your logs.

```
BrowserMatch "^Probe-G4WsxDN8ijtTuAniNQ" useragent_healthcheck
BrowserMatch "^Monitor-DhVQBhSwfapBhHMiTdoA" useragent_healthcheck
```

Like so...

```
readinessProbe:
  initialDelaySeconds: 2
  timeoutSeconds: 1
  httpGet:
    path: /
    port: 8080
    httpHeaders:
     - name: Host
       value: www.example.com
     - name: User-Agent
       value: Probe-G4WsxDN8ijtTuAniNQ-example
     - name: Accept-Encoding
       value: gzip, deflate, br
```
            
Logs to standard output for container purists is pretty quick. Notice the healthcheck filter.

```
<IfDefine STDOUTLOGS>
  CustomLog /dev/stdout logformat-ndjson env=!useragent_healthcheck
  ErrorLog "/dev/stdout"
</IfDefine>
```

JSON access logs! The directive `GlobalLog` is fairly new and is different from `CustomLog` which may be set globally or on a per-vhost basis.

```
<IfDefine JSONLOGS>
  GlobalLog /var/log/httpd/json_log logformat-ndjson env=!useragent_healthcheck
  GlobalLog /var/log/httpd/healthcheck_log logformat-ndjson-healthcheck env=useragent_healthcheck
</IfDefine>
```

Here's a log format that includes almost everything you can get out of the box from the [log config module](https://httpd.apache.org/docs/current/mod/mod_log_config.html) with examples like directly logging headers too.

```
<IfDefine LOGFORMATJSON>

# https://httpd.apache.org/docs/2.4/mod/core.html#errorlogformat
ErrorLogFormat "{ error_timestamp:\"%{u}t\", \
 error_message:\"%M\", \
 error_os:\"%E\", \
 error_logid:\"%L\", \
 error_module:\"%-m\", \
 error_loglevel:\"%l\", \
 error_pid:\"%P\", \
 error_tid:\"%T\", \
 error_client:\"%a\", \
 uniqueid:\"%{UNIQUE_ID}e\" }"

# key:"value" format
LogFormat "{ timestamp:\"%{sec}t.%{usec_frac}t\", \
 servername:\"%v\", clientip:\"%a\", \
 localip:\"%A\", peerip:\"%{c}a\", \
 status:\"%>s\", method:\"%m\", \
 uri:\"%U\", qsa:\"%q\", \
 request:\"%r\", bytes:%B, \
 response_sec:%T, response_usec:%D, \
 keepalive:%k, connstat:\"%X\", \
 resphandler:\"%R\", errorid:\"%L\", \
 remoteuser:\"%u\", \
 h_host:\"%{Host}i\", \
 h_accept:\"%{accept}i\", \
 h_acceptchar:\"%{accept-charset}i\", \
 h_acceptenc:\"%{accept-encoding}i\", \
 h_acceptlang:\"%{accept-language}i\", \
 h_referer:\"%{Referer}i\", \
 h_useragent:\"%{User-Agent}i\", \
 apache_http2:\"%{HTTP2}x\" apache_https:\"%{HTTPS}x\" \
 apache_tls_version:\"%{SSL_PROTOCOL}x\" apache_tls_cipher:\"%{SSL_CIPHER}x\" \
 c_hit:\"%{cache-hit}e\", c_miss:\"%{cache-miss}e\", \
 c_revalidate:\"%{revalidate}e\", c_invalidate:\"%{cache-invalidate}e\", \
 c_status:\"%{cache-status}e\", c_age:%{Age}o, \
 e_acl_addr_rfc1918:\"%{acl_addr_rfc1918}e\", \
 e_useragent_healthcheck:\"%{useragent_healthcheck}e\", \
 uniqueid:\"%{UNIQUE_ID}e\" }" \
   logformat-ndjson

# log format with limited data for healthchecks
LogFormat "{ timestamp:\"%{sec}t.%{usec_frac}t\", \
 healthcheck:\"%{useragent_healthcheck}e\", \
 servername:\"%v\", clientip:\"%a\", \
 localip:\"%A\", peerip:\"%{c}a\", \
 status:\"%>s\", method:\"%m\", \
 h_useragent:\"%{User-Agent}i\", \
 uniqueid:\"%{UNIQUE_ID}e\" }" \
   logformat-ndjson-healthcheck

</IfDefine>
```

If you have a website doing more than say one hit a second, instead of writing logs per-line, let apache queue and flush:

```
BufferedLogs On
```

Finally, know there is a [forensic log module](https://httpd.apache.org/docs/2.4/mod/mod_log_forensic.html) listed in `/etc/httpd/conf.modules.d/00-optional.conf` you can enable.

```
<IfDefine FORENSICLOG>
  ForensicLog /var/log/httpd/forensic_log
</IfDefine>
```

### A form-based dashboard

Now that we have logs, we need more than `tail` and `grep` and `sort` and `uniq` and `wc` to make sense of them.

Make sure your log collector understands the logs have microsecond resolution when it ingests your logs and creates events. One second resolution is insufficient.

Pair up both the ServerName of your virtualhost config and the Host header as presented by the client. Lotta weird host headers on the Internet, like "localhost" and IP addresses.

Have some charts where you look at both extremes: The most popular hundred pages may reveal an obvious place to improve performance, but the least requested or most unique URLs hold secrets.

Top user agents, slowest web pages, response time across all hits, status codes over time, cache hit ratio, TLS version, TLS cipher.

## We Made it

- Have a default vhost that redirects.
- Require the Host header matches the ServerName and ServerAlias you use.
- Logs have the answers

# Thank you.
