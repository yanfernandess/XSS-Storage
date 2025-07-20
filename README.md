# Description
During the analysis of the website ecodotempo.com.br, a Stored Cross-Site Scripting (XSS) vulnerability was discovered. This vulnerability allows an attacker to inject malicious scripts into fields that are later rendered to other users without proper sanitization, specifically on the main page of the unauthenticated (logged-out) area.

# Affected endpoint
ecodotempo.com.br/colecoes/cadastrar_realizar.php

# Affected parameter
name="nome" and name="descricao"

# Payload example:
<script>alert(document.cookie)</script>

# PoC
During the analysis of the website ecodotempo.com.br, a Stored Cross-Site Scripting (XSS) vulnerability was discovered. This vulnerability allows an attacker to inject malicious scripts into fields that are later rendered to other users without proper sanitization, specifically on the main page of the unauthenticated (logged-out) area.

The injected script was persistently stored in the application's backend and executed in the browser of any visitor who accessed the affected page, with no escaping mechanisms or protection via Content Security Policy (CSP) in place.

During testing on ecodotempo.com.br, the stored XSS vulnerability was specifically identified in the item collection creation process. It was possible to inject a malicious payload into the name or description fields of the collection, with no active mitigation mechanisms — such as input validation, code-level filters, Web Application Firewall (WAF), or security HTTP headers.

After creating the collection containing the malicious script, logging out, and then accessing the main login page again, the payload was automatically executed in the browser, resulting in a pop-up being displayed. In the test, this was used to demonstrate cookie extraction. This behavior confirms the lack of proper sanitization and the real possibility of arbitrary script execution within the victim’s browser context. See the evidence section below for an example.

<img width="1279" height="743" alt="Criando XSS" src="https://github.com/user-attachments/assets/3c85737c-16cf-4c6d-a644-b970bb3ca548" />
<img width="1279" height="939" alt="XSS Stored" src="https://github.com/user-attachments/assets/cb1e6c47-5fbd-46ba-a4d1-9d4aefe9d31d" />
<img width="1279" height="743" alt="Criado com sucesso" src="https://github.com/user-attachments/assets/21fbceb0-351c-4ea3-877a-79e02ae476c3" />
<img width="1268" height="777" alt="1" src="https://github.com/user-attachments/assets/98863e94-90e0-46b0-a508-47da06ec8cc5" />

Note: In addition to cookie theft, this vulnerability could be exploited for various malicious purposes such as redirecting users to harmful websites, exfiltrating sensitive data, altering page content for phishing attacks, or executing actions on behalf of the user, as previously described in the impact section.

# Impact
The presence of a stored XSS vulnerability on the main page of the unauthenticated area of ecodotempo.com.br poses a significant security risk. Since the injected script is permanently stored and served to every user who accesses the affected page, it opens the door to a range of client-side attacks. An attacker could exploit this flaw to execute arbitrary JavaScript in the browser of unsuspecting visitors, potentially stealing session cookies, redirecting users to malicious websites, performing actions on behalf of users without their consent, or manipulating page content to carry out phishing attempts. Because the vulnerability is exposed in a publicly accessible area, it increases the likelihood of exploitation at scale, especially by automated bots or targeted campaigns, potentially undermining user trust and the integrity of the platform.

# Mitigation
To remediate the stored XSS vulnerability found on the main page of the unauthenticated area of ecodotempo.com.br, the following actions should be taken:

All user input must be properly sanitized and validated on both the client and server sides before being stored or rendered. Specifically, any input that will be displayed in the HTML context should have special characters like <, >, ", ', and & encoded to prevent script execution. Additionally, the application should implement output encoding based on the context where the data is injected (HTML, JavaScript, attribute, URL, etc.).

It is also strongly recommended to enforce a Content Security Policy (CSP) to limit the execution of unauthorized scripts, and to disable inline scripts and external script loading from untrusted sources. Regular code reviews and automated security testing (e.g. with tools like OWASP ZAP or Burp Suite) should be incorporated into the development lifecycle to detect and prevent similar flaws in the future.

Finally, any already stored malicious payloads should be identified and removed from the system to eliminate existing risks.
