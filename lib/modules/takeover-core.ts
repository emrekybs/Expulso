// Subdomain-takeover fingerprints: a dangling CNAME to the service plus a tell-tale body string.
export const TAKEOVER_SIGNATURES: { service: string; cname: RegExp; body: RegExp }[] = [
  { service: "GitHub Pages", cname: /\.github\.io$/i, body: /There isn't a GitHub Pages site here|For root URLs \(like http:\/\/example\.com\/\) you must provide/i },
  { service: "Amazon S3", cname: /\.s3[.-][\w-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$/i, body: /NoSuchBucket|The specified bucket does not exist/i },
  { service: "Heroku", cname: /\.heroku(app|dns)\.com$/i, body: /No such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { service: "Cloudfront", cname: /\.cloudfront\.net$/i, body: /ERROR: The request could not be satisfied|Bad request\./i },
  { service: "Fastly", cname: /\.fastly\.net$/i, body: /Fastly error: unknown domain/i },
  { service: "Shopify", cname: /\.myshopify\.com$/i, body: /Sorry, this shop is currently unavailable|Only one step left/i },
  { service: "Zendesk", cname: /\.zendesk\.com$/i, body: /Help Center Closed|this help center no longer exists/i },
  { service: "Surge.sh", cname: /\.surge\.sh$/i, body: /project not found/i },
  { service: "Pantheon", cname: /\.pantheonsite\.io$/i, body: /The gods are wise|404 error unknown site/i },
  { service: "Tumblr", cname: /\.tumblr\.com$/i, body: /Whatever you were looking for doesn't currently exist at this address/i },
  { service: "Webflow", cname: /\.proxy\.webflow\.com$|\.webflow\.io$/i, body: /The page you are looking for doesn't exist or has been moved/i },
  { service: "Netlify", cname: /\.netlify\.(app|com)$/i, body: /Not Found - Request ID|There's nothing here yet/i },
  { service: "Azure", cname: /\.azurewebsites\.net$|\.cloudapp\.net$|\.trafficmanager\.net$/i, body: /404 Web Site not found|This Azure DNS zone/i },
  { service: "Unbounce", cname: /\.unbouncepages\.com$/i, body: /The requested URL was not found on this server/i },
  { service: "Readme.io", cname: /\.readme\.io$/i, body: /Project doesnt exist\.\.\. yet!/i },
];

/** Returns the service name if the CNAME matches and (no body given, or the body matches). */
export function matchTakeover(cname: string, body: string): string | null {
  for (const s of TAKEOVER_SIGNATURES) {
    if (!s.cname.test(cname)) continue;
    if (!body) return s.service; // CNAME alone is a candidate worth flagging
    if (s.body.test(body)) return s.service;
  }
  return null;
}
