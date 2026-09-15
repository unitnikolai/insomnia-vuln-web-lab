-- Ground-truth seed for the built-in apps in the top-level docker-compose.yml.
-- These are training apps, not real software with CVEs, so the "answer key"
-- here is vulnerability *classes* per app rather than CVE IDs — that's what
-- Vulhub is for (see seed/seed-vulhub.js). This is a curated starting set,
-- not a claim of exhaustiveness (Juice Shop alone ships ~100 discrete
-- challenges) — expand rows here as you tune the benchmark.

INSERT INTO labs (slug, name, kind, category, url_hint, description) VALUES
  ('juice-shop', 'OWASP Juice Shop', 'builtin', 'multi', 'http://juice-shop:3000',
   'Broadest single-app coverage: XSS, SQLi/NoSQLi, IDOR, JWT/crypto flaws, SSRF, XXE, prototype pollution, business logic. ~100 built-in challenges with a scoreboard at /#/score-board.'),
  ('dvwa', 'Damn Vulnerable Web Application', 'builtin', 'owasp-top10', 'http://dvwa',
   'Classic OWASP Top 10 with adjustable difficulty (low/medium/high/impossible) via the DVWA Security setting.'),
  ('mutillidae', 'OWASP Mutillidae II', 'builtin', 'owasp-top10', 'http://mutillidae',
   'Very wide breadth (OWASP Top 10 2007-2021 combined), including older/rarer bug classes DVWA does not cover.'),
  ('vampi', 'VAmPI', 'builtin', 'api-top10', 'http://vampi:5000',
   'API-specific: BOLA/IDOR, excessive data exposure, mass assignment, broken object property level auth, JWT weaknesses.'),
  ('dvga', 'Damn Vulnerable GraphQL Application', 'builtin', 'graphql', 'http://dvga:5013',
   'GraphQL-specific: introspection abuse, batching/DoS via query depth, injection through resolvers.'),
  ('webgoat', 'WebGoat', 'builtin', 'guided-lessons', 'http://webgoat:8080/WebGoat',
   'Guided lessons incl. Java insecure deserialization, XXE, SSRF, path traversal, JWT.'),
  ('webwolf', 'WebWolf', 'builtin', 'guided-lessons', 'http://webgoat:9090/WebWolf',
   'SSRF/phishing simulation companion to WebGoat — file/mail server used to complete several WebGoat lessons.')
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description);

-- DVWA
INSERT INTO vulnerabilities (lab_id, title, category, severity, description) VALUES
  ((SELECT id FROM labs WHERE slug='dvwa'), 'Brute Force (weak login rate limiting)', 'auth', 'medium', 'Login form has no lockout/rate limiting at low security.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'Command Injection', 'injection', 'critical', 'Ping utility page passes user input to a shell command unsanitized.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'CSRF (password change)', 'csrf', 'medium', 'Password change form has no anti-CSRF token at low security.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'File Inclusion (LFI/RFI)', 'file-inclusion', 'high', 'Page parameter used to include local or remote files.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'Unrestricted File Upload', 'file-upload', 'critical', 'Upload form accepts arbitrary file types, enabling webshell upload.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'Insecure CAPTCHA', 'auth', 'low', 'CAPTCHA verification can be bypassed or replayed.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'SQL Injection', 'injection', 'critical', 'User ID field is concatenated directly into a SQL query.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'SQL Injection (Blind)', 'injection', 'high', 'Boolean/time-based blind SQLi via unsanitized parameter.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'Weak Session IDs', 'session', 'medium', 'Session identifiers are predictable/sequential.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'Reflected XSS', 'xss', 'medium', 'Input reflected into the page without encoding.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'Stored XSS', 'xss', 'high', 'Guestbook input stored and rendered without encoding.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'DOM XSS', 'xss', 'medium', 'Client-side script writes an unsanitized URL fragment into the DOM.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'CSP Bypass', 'misconfig', 'low', 'Content-Security-Policy header can be bypassed via whitelisted sources.'),
  ((SELECT id FROM labs WHERE slug='dvwa'), 'JavaScript Client-Side Attacks', 'client-side', 'medium', 'Security decisions made in client-side JS can be tampered with.');

-- Mutillidae
INSERT INTO vulnerabilities (lab_id, title, category, severity, description) VALUES
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'SQL Injection (Extract Data)', 'injection', 'critical', 'Classic UNION-based data extraction.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'SQL Injection (Insert/Update/Auth Bypass)', 'injection', 'critical', 'Login bypass and data tampering via SQLi.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'HTML Injection', 'injection', 'medium', 'Unsanitized input rendered as raw HTML.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Reflected XSS', 'xss', 'medium', 'Input reflected without encoding.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Stored XSS', 'xss', 'high', 'Persistent script injection via comments/profile fields.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'DOM XSS', 'xss', 'medium', 'Client-side sink consumes untrusted input.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'LDAP Injection', 'injection', 'high', 'LDAP query built via unsanitized user input.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Command Injection', 'injection', 'critical', 'DNS lookup page passes input to a shell command.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Path/Directory Traversal', 'path-traversal', 'high', 'File parameter allows ../ traversal outside webroot.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Local File Inclusion', 'file-inclusion', 'high', 'Page parameter includes arbitrary local files.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Remote File Inclusion', 'file-inclusion', 'critical', 'Page parameter includes attacker-hosted remote files.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'CSRF', 'csrf', 'medium', 'State-changing requests lack anti-CSRF tokens.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Clickjacking', 'client-side', 'low', 'Pages can be framed, enabling UI redress attacks.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Insecure Direct Object Reference', 'access-control', 'high', 'Numeric IDs allow access to other users\' records.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Forced Browsing', 'access-control', 'medium', 'Unlinked admin pages reachable by guessing the URL.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Unvalidated Redirects/Forwards', 'access-control', 'medium', 'Redirect target taken from user input.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Sensitive Data Exposure (hidden fields / cleartext)', 'data-exposure', 'medium', 'Sensitive values sent in hidden fields or over HTTP.'),
  ((SELECT id FROM labs WHERE slug='mutillidae'), 'Using Components with Known Vulnerabilities', 'components', 'medium', 'Outdated bundled libraries with public CVEs.');

-- VAmPI
INSERT INTO vulnerabilities (lab_id, title, category, severity, description) VALUES
  ((SELECT id FROM labs WHERE slug='vampi'), 'BOLA / IDOR on /users/v1/{username}', 'access-control', 'high', 'Any authenticated user can read another user\'s record by changing the ID.'),
  ((SELECT id FROM labs WHERE slug='vampi'), 'Excessive Data Exposure', 'data-exposure', 'medium', 'Endpoints return full user objects including sensitive fields.'),
  ((SELECT id FROM labs WHERE slug='vampi'), 'Broken Function Level Authorization', 'access-control', 'high', 'Admin-only endpoints reachable by regular users.'),
  ((SELECT id FROM labs WHERE slug='vampi'), 'Mass Assignment', 'business-logic', 'high', 'User-supplied fields (e.g. admin flag) bind directly to the model.'),
  ((SELECT id FROM labs WHERE slug='vampi'), 'SQL Injection in API parameters', 'injection', 'critical', 'Unsanitized query parameters reach a raw SQL query.'),
  ((SELECT id FROM labs WHERE slug='vampi'), 'Improper Assets Management (deprecated /users/v1)', 'components', 'medium', 'Deprecated but still-active API version lacks current protections.'),
  ((SELECT id FROM labs WHERE slug='vampi'), 'Broken Authentication (weak/no JWT expiry)', 'auth', 'high', 'JWTs are long-lived or signed with a guessable secret.'),
  ((SELECT id FROM labs WHERE slug='vampi'), 'Security Misconfiguration (verbose errors)', 'misconfig', 'low', 'Stack traces and debug info leak in error responses.');

-- DVGA
INSERT INTO vulnerabilities (lab_id, title, category, severity, description) VALUES
  ((SELECT id FROM labs WHERE slug='dvga'), 'GraphQL Introspection Enabled', 'misconfig', 'medium', 'Full schema is queryable in a non-dev environment.'),
  ((SELECT id FROM labs WHERE slug='dvga'), 'Batching Attack', 'dos', 'high', 'Aliased/batched queries bypass rate limiting.'),
  ((SELECT id FROM labs WHERE slug='dvga'), 'Denial of Service via Query Depth/Complexity', 'dos', 'high', 'Deeply nested or circular queries exhaust server resources.'),
  ((SELECT id FROM labs WHERE slug='dvga'), 'SQL Injection via Resolver', 'injection', 'critical', 'A resolver builds SQL from unsanitized arguments.'),
  ((SELECT id FROM labs WHERE slug='dvga'), 'OS Command Injection via Resolver', 'injection', 'critical', 'A resolver passes arguments to a shell command.'),
  ((SELECT id FROM labs WHERE slug='dvga'), 'Broken Access Control (IDOR via GraphQL)', 'access-control', 'high', 'Object IDs in queries/mutations are not authorization-checked.'),
  ((SELECT id FROM labs WHERE slug='dvga'), 'Information Disclosure via Verbose Errors', 'data-exposure', 'medium', 'Stack traces returned in GraphQL error responses.'),
  ((SELECT id FROM labs WHERE slug='dvga'), 'CSRF via GET-based GraphQL Queries', 'csrf', 'medium', 'State-changing operations reachable via a simple GET request.');

-- WebGoat
INSERT INTO vulnerabilities (lab_id, title, category, severity, description) VALUES
  ((SELECT id FROM labs WHERE slug='webgoat'), 'SQL Injection (multiple lessons)', 'injection', 'critical', 'Numeric and string-based SQLi across several guided lessons.'),
  ((SELECT id FROM labs WHERE slug='webgoat'), 'XML External Entity (XXE) Injection', 'xxe', 'critical', 'XML parser resolves external entities from user-supplied XML.'),
  ((SELECT id FROM labs WHERE slug='webgoat'), 'Insecure Deserialization (Java)', 'deserialization', 'critical', 'Untrusted serialized Java objects are deserialized.'),
  ((SELECT id FROM labs WHERE slug='webgoat'), 'Server-Side Request Forgery', 'ssrf', 'high', 'Server fetches a URL supplied by the user without validation.'),
  ((SELECT id FROM labs WHERE slug='webgoat'), 'Path Traversal', 'path-traversal', 'high', 'File download/upload lessons allow ../ traversal.'),
  ((SELECT id FROM labs WHERE slug='webgoat'), 'JWT Vulnerabilities', 'auth', 'high', 'Weak signing/alg-confusion/refresh-token lessons.'),
  ((SELECT id FROM labs WHERE slug='webgoat'), 'Broken Access Control (IDOR lessons)', 'access-control', 'high', 'Direct object references across several lessons.'),
  ((SELECT id FROM labs WHERE slug='webgoat'), 'Cross-Site Scripting', 'xss', 'medium', 'Reflected/stored XSS lessons.'),
  ((SELECT id FROM labs WHERE slug='webgoat'), 'Insecure Password Reset', 'auth', 'medium', 'Password reset flow guessable/bypassable.'),
  ((SELECT id FROM labs WHERE slug='webgoat'), 'Vulnerable Components', 'components', 'high', 'Lesson(s) built around a known-vulnerable dependency.');

-- WebWolf
INSERT INTO vulnerabilities (lab_id, title, category, severity, description) VALUES
  ((SELECT id FROM labs WHERE slug='webwolf'), 'SSRF via File Retrieval', 'ssrf', 'high', 'WebWolf fetches attacker-controlled URLs on behalf of WebGoat lessons.'),
  ((SELECT id FROM labs WHERE slug='webwolf'), 'Phishing Simulation Endpoint', 'social-engineering', 'medium', 'Hosts attacker-crafted pages/mail used to complete phishing-style lessons.');

-- Juice Shop (representative categories — see /#/score-board in-app for the
-- full, versioned challenge list; expand rows here to track specific
-- challenges by name if you want per-challenge benchmarking).
INSERT INTO vulnerabilities (lab_id, title, category, severity, description) VALUES
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'Broken Access Control / IDOR (baskets, orders)', 'access-control', 'high', 'Other users\' baskets/orders reachable by ID manipulation.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'SQL Injection (login bypass)', 'injection', 'critical', 'Login form vulnerable to UNION/boolean-based SQLi.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'NoSQL Injection', 'injection', 'high', 'MongoDB-backed endpoint accepts operator injection.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'DOM / Reflected / Stored XSS', 'xss', 'high', 'Multiple XSS sinks across search, product reviews, and feedback.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'Broken Authentication (JWT forgery / weak reset)', 'auth', 'high', 'JWT alg confusion and guessable password-reset security questions.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'Sensitive Data Exposure (exposed API docs/files)', 'data-exposure', 'medium', 'Confidential files and API metadata reachable without auth.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'XXE via File Upload', 'xxe', 'critical', 'XML-based upload (e.g. package) parsed with external entities enabled.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'SSRF via Image URL Upload', 'ssrf', 'high', 'Avatar/image-by-URL feature fetches attacker-supplied URLs.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'Insecure Deserialization', 'deserialization', 'high', 'Untrusted input reaches an unsafe deserialization sink.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'Security Misconfiguration (CORS, directory listing)', 'misconfig', 'medium', 'Overly permissive CORS and exposed directory listings.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'Vulnerable and Outdated Components', 'components', 'medium', 'Bundled dependencies with known public CVEs.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'Cryptographic Issues (weak hashing, alg=none JWT)', 'crypto', 'high', 'MD5-hashed passwords and acceptance of unsigned JWTs.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'Business Logic Flaws (coupon abuse, negative quantity)', 'business-logic', 'medium', 'Pricing/quantity logic can be manipulated client-side.'),
  ((SELECT id FROM labs WHERE slug='juice-shop'), 'Prototype Pollution', 'injection', 'high', 'Merge utility allows polluting Object.prototype.');
