// Web technology signatures. Each rule is [source, pattern, capturesVersion?]:
//   "header:<name>"  response header value      "cookie"  Set-Cookie names/values
//   "html"           page HTML                  "script"  <script src> and <link href>
//   "meta"           <meta name="generator">
// When a rule with capturesVersion matches, its first group becomes the version.

export type Cat =
  | "CMS" | "Framework" | "Language" | "Web server" | "CDN" | "Hosting" | "WAF"
  | "JavaScript library" | "UI / CSS" | "Build tool" | "Analytics" | "Tag manager"
  | "Advertising" | "Monitoring" | "Chat" | "Marketing" | "E-commerce" | "Payment"
  | "Security" | "Font" | "Maps" | "Video";

export type Rule = [on: string, re: RegExp, version?: boolean];

export interface TechSig {
  name: string;
  cat: Cat;
  rules: Rule[];
  /** Also report these technologies when this one is found (name must exist in TECH_SIGS). */
  implies?: string[];
  /** npm package name, used for vulnerability lookups when a version is known. */
  npm?: string;
}

export const TECH_SIGS: TechSig[] = [
  // ---- CMS & site builders ----
  { name: "WordPress", cat: "CMS", rules: [["html", /\/wp-(?:content|includes)\//], ["meta", /^WordPress\s*([\d.]*)/i, true], ["html", /<link[^>]+wp-json/i]] },
  { name: "WooCommerce", cat: "E-commerce", rules: [["html", /woocommerce/i], ["html", /wp-content\/plugins\/woocommerce/]], implies: ["WordPress"] },
  { name: "Joomla", cat: "CMS", rules: [["meta", /^Joomla!\s*([\d.]*)/i, true], ["html", /\/media\/jui\/|\/components\/com_/i]] },
  { name: "Drupal", cat: "CMS", rules: [["header:x-generator", /Drupal\s*([\d.]*)/i, true], ["meta", /^Drupal\s*([\d.]*)/i, true], ["html", /Drupal\.settings|\/sites\/(?:default|all)\/(?:themes|modules|files)\//]] },
  { name: "TYPO3", cat: "CMS", rules: [["meta", /TYPO3/i], ["html", /typo3(?:temp|conf)\//]] },
  { name: "Ghost", cat: "CMS", rules: [["meta", /^Ghost\s*([\d.]*)/i, true], ["html", /ghost-(?:portal|search)/]] },
  { name: "Hugo", cat: "Build tool", rules: [["meta", /^Hugo\s*([\d.]*)/i, true]] },
  { name: "Jekyll", cat: "Build tool", rules: [["meta", /^Jekyll\s*v?([\d.]*)/i, true]] },
  { name: "Craft CMS", cat: "CMS", rules: [["meta", /^Craft CMS/i], ["cookie", /CraftSessionId=/]] },
  { name: "Webflow", cat: "CMS", rules: [["meta", /^Webflow/i], ["html", /data-wf-page|webflow\.com\/js/]] },
  { name: "Umbraco", cat: "CMS", rules: [["html", /umbraco/i]] },
  { name: "Concrete CMS", cat: "CMS", rules: [["meta", /concrete5|Concrete CMS/i]] },
  { name: "1C-Bitrix", cat: "CMS", rules: [["html", /bitrix\/js\/|BX\.message/]] },
  { name: "Shopify", cat: "E-commerce", rules: [["html", /cdn\.shopify\.com|Shopify\.theme/], ["header:x-shopify-stage", /./]] },
  { name: "Wix", cat: "CMS", rules: [["html", /static\.wixstatic\.com|X-Wix-/], ["header:x-wix-request-id", /./]] },
  { name: "Squarespace", cat: "CMS", rules: [["html", /static1?\.squarespace\.com|SQUARESPACE_CONTEXT/]] },
  { name: "Magento", cat: "E-commerce", rules: [["html", /\/static\/(?:version\d+\/)?frontend\/|Mage\.Cookies|\/mage\/cookies/]] },
  { name: "PrestaShop", cat: "E-commerce", rules: [["meta", /PrestaShop/i], ["html", /prestashop/i]] },
  { name: "OpenCart", cat: "E-commerce", rules: [["html", /catalog\/view\/theme\//]] },
  { name: "BigCommerce", cat: "E-commerce", rules: [["html", /cdn\d*\.bigcommerce\.com|bigcommerce\.com\/s-/]] },

  // ---- Frameworks ----
  { name: "Next.js", cat: "Framework", rules: [["html", /__NEXT_DATA__|\/_next\/static\//]] },
  { name: "Nuxt", cat: "Framework", rules: [["html", /__NUXT__|\/_nuxt\//]] },
  { name: "Gatsby", cat: "Framework", rules: [["html", /___gatsby|\/page-data\/[^"']*\/page-data\.json/]] },
  { name: "Astro", cat: "Framework", rules: [["html", /astro-island|astro:\/\//]] },
  { name: "SvelteKit", cat: "Framework", rules: [["html", /__sveltekit_|\/_app\/immutable\//]] },
  { name: "Remix", cat: "Framework", rules: [["html", /__remixContext|window\.__remix/]] },
  { name: "Angular", cat: "Framework", npm: "@angular/core", rules: [["html", /\sng-version="([\d.]+)"/, true], ["html", /\sng-app[\s>=]/]] },
  { name: "React", cat: "JavaScript library", rules: [["html", /data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__/], ["script", /react(?:-dom)?(?:\.production)?(?:\.min)?\.js/i]] },
  { name: "Vue.js", cat: "JavaScript library", npm: "vue", rules: [["script", /vue(?:\.runtime)?(?:@|[.-])([\d.]+)/i, true], ["html", /data-v-[0-9a-f]{8}/], ["script", /vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js/i]] },
  { name: "Ember.js", cat: "Framework", rules: [["html", /ember-view|EmberENV|ember\.debug/]] },
  { name: "Alpine.js", cat: "JavaScript library", rules: [["html", /\sx-data=/], ["script", /alpinejs/i]] },
  { name: "Laravel", cat: "Framework", rules: [["cookie", /laravel_session=/]] },
  { name: "Django", cat: "Framework", rules: [["html", /name=["']csrfmiddlewaretoken["']/], ["cookie", /csrftoken=/]] },
  { name: "Ruby on Rails", cat: "Framework", rules: [["html", /<meta name="csrf-param" content="authenticity_token"/]] },
  { name: "ASP.NET", cat: "Framework", rules: [["header:x-aspnet-version", /([\d.]+)/, true], ["header:x-powered-by", /ASP\.NET/i], ["cookie", /ASP\.NET_SessionId=/]] },
  { name: "Express", cat: "Framework", rules: [["header:x-powered-by", /^Express$/]] },
  { name: "Webpack", cat: "Build tool", rules: [["html", /webpackJsonp|webpackChunk/]] },
  { name: "Vite", cat: "Build tool", rules: [["html", /\/@vite\/client|\/src\/main\.(?:t|j)sx?/]] },

  // ---- Languages ----
  { name: "PHP", cat: "Language", rules: [["header:x-powered-by", /PHP\/([\d.]+)/i, true], ["cookie", /PHPSESSID=/]] },
  { name: "Java servlet container", cat: "Language", rules: [["cookie", /JSESSIONID=/]] },

  // ---- Web servers ----
  { name: "nginx", cat: "Web server", rules: [["header:server", /nginx(?:\/([\d.]+))?/i, true]] },
  { name: "Apache HTTP Server", cat: "Web server", rules: [["header:server", /Apache(?:\/([\d.]+))?/i, true]] },
  { name: "Microsoft IIS", cat: "Web server", rules: [["header:server", /Microsoft-IIS\/([\d.]+)/i, true]] },
  { name: "LiteSpeed", cat: "Web server", rules: [["header:server", /LiteSpeed/i]] },
  { name: "Caddy", cat: "Web server", rules: [["header:server", /Caddy/i]] },
  { name: "OpenResty", cat: "Web server", rules: [["header:server", /openresty(?:\/([\d.]+))?/i, true]] },
  { name: "Apache Tomcat", cat: "Web server", rules: [["header:server", /Coyote|Tomcat/i]] },

  // ---- CDN / hosting / edge ----
  { name: "Cloudflare", cat: "CDN", rules: [["header:server", /cloudflare/i], ["header:cf-ray", /./]] },
  { name: "Akamai", cat: "CDN", rules: [["header:server", /AkamaiGHost|AkamaiNetStorage/i], ["header:x-akamai-transformed", /./]] },
  { name: "Fastly", cat: "CDN", rules: [["header:x-served-by", /cache-/i], ["header:server", /fastly/i], ["header:via", /fastly/i]] },
  { name: "Amazon CloudFront", cat: "CDN", rules: [["header:x-amz-cf-id", /./], ["header:via", /CloudFront/i], ["header:server", /CloudFront/i]] },
  { name: "Vercel", cat: "Hosting", rules: [["header:server", /^Vercel$/i], ["header:x-vercel-id", /./]] },
  { name: "Netlify", cat: "Hosting", rules: [["header:server", /Netlify/i], ["header:x-nf-request-id", /./]] },
  { name: "GitHub Pages", cat: "Hosting", rules: [["header:server", /GitHub\.com/i]] },
  { name: "Microsoft Azure", cat: "Hosting", rules: [["header:x-azure-ref", /./], ["header:x-msedge-ref", /./]] },
  { name: "Heroku", cat: "Hosting", rules: [["header:via", /vegur/i]] },
  { name: "Firebase", cat: "Hosting", rules: [["html", /firebaseapp\.com|firebaseio\.com|__firebase/]] },
  { name: "Supabase", cat: "Hosting", rules: [["html", /supabase\.(?:co|in)\b/]] },

  // ---- WAF ----
  { name: "Sucuri WAF", cat: "WAF", rules: [["header:server", /Sucuri/i]] },
  { name: "Imperva Incapsula", cat: "WAF", rules: [["cookie", /incap_ses|visid_incap/]] },
  { name: "Wordfence", cat: "WAF", rules: [["html", /Generated by Wordfence/]] },

  // ---- Analytics / tags / monitoring ----
  { name: "Google Analytics", cat: "Analytics", rules: [["script", /googletagmanager\.com\/gtag\/js\?id=(G-[A-Z0-9]+|UA-\d+-\d+)/i, true], ["script", /google-analytics\.com\/(?:ga|analytics)\.js/], ["html", /ga\(['"]create['"]/]] },
  { name: "Google Tag Manager", cat: "Tag manager", rules: [["script", /googletagmanager\.com\/gtm\.js\?id=(GTM-[A-Z0-9]+)/i, true], ["html", /googletagmanager\.com\/ns\.html/]] },
  { name: "Adobe Launch / Analytics", cat: "Tag manager", rules: [["script", /assets\.adobedtm\.com|satelliteLib-/]] },
  { name: "Meta Pixel", cat: "Advertising", rules: [["script", /connect\.facebook\.net\/[^"']*\/fbevents\.js/], ["html", /fbq\(['"]init['"]/]] },
  { name: "Microsoft Advertising (UET)", cat: "Advertising", rules: [["script", /bat\.bing\.com\/bat\.js/]] },
  { name: "LinkedIn Insight Tag", cat: "Advertising", rules: [["html", /snap\.licdn\.com|_linkedin_partner_id/]] },
  { name: "TikTok Pixel", cat: "Advertising", rules: [["html", /analytics\.tiktok\.com/]] },
  { name: "Hotjar", cat: "Analytics", rules: [["script", /static\.hotjar\.com/], ["html", /\bhjid\b/]] },
  { name: "Microsoft Clarity", cat: "Analytics", rules: [["script", /clarity\.ms/]] },
  { name: "Matomo", cat: "Analytics", rules: [["script", /matomo\.js|piwik\.js/], ["html", /_paq\.push/]] },
  { name: "Yandex Metrica", cat: "Analytics", rules: [["html", /mc\.yandex\.(?:ru|com)\/metrika/]] },
  { name: "Segment", cat: "Analytics", rules: [["script", /cdn\.segment\.com\/analytics/]] },
  { name: "Mixpanel", cat: "Analytics", rules: [["html", /cdn\.mxpnl\.com|mixpanel\.init/]] },
  { name: "Optimizely", cat: "Analytics", rules: [["script", /cdn\.optimizely\.com/]] },
  { name: "VWO", cat: "Analytics", rules: [["html", /dev\.visualwebsiteoptimizer\.com|_vwo_code/]] },
  { name: "Sentry", cat: "Monitoring", rules: [["script", /browser\.sentry-cdn\.com|js\.sentry-cdn\.com/], ["html", /Sentry\.init\(/]] },
  { name: "Datadog RUM", cat: "Monitoring", rules: [["script", /datadoghq-browser-agent|datadog-rum/]] },
  { name: "New Relic", cat: "Monitoring", rules: [["html", /js-agent\.newrelic\.com|NREUM/]] },

  // ---- Chat / marketing ----
  { name: "Intercom", cat: "Chat", rules: [["script", /widget\.intercom\.io|js\.intercomcdn\.com/], ["html", /intercomSettings/]] },
  { name: "Zendesk", cat: "Chat", rules: [["script", /static\.zdassets\.com|ekr\.zdassets\.com/]] },
  { name: "Crisp", cat: "Chat", rules: [["script", /client\.crisp\.chat/]] },
  { name: "Tawk.to", cat: "Chat", rules: [["script", /embed\.tawk\.to/]] },
  { name: "LiveChat", cat: "Chat", rules: [["script", /cdn\.livechatinc\.com/]] },
  { name: "Drift", cat: "Chat", rules: [["script", /js\.driftt\.com|drift\.com\/widget/]] },
  { name: "Tidio", cat: "Chat", rules: [["script", /code\.tidio\.co/]] },
  { name: "HubSpot", cat: "Marketing", rules: [["script", /js\.hs-scripts\.com|js\.hsforms\.net|js\.hs-analytics\.net/]] },
  { name: "Mailchimp", cat: "Marketing", rules: [["script", /chimpstatic\.com|list-manage\.com/]] },
  { name: "Klaviyo", cat: "Marketing", rules: [["script", /static\.klaviyo\.com/]] },

  // ---- Security / payment ----
  { name: "Google reCAPTCHA", cat: "Security", rules: [["script", /google\.com\/recaptcha|gstatic\.com\/recaptcha/]] },
  { name: "hCaptcha", cat: "Security", rules: [["script", /js\.hcaptcha\.com/]] },
  { name: "Cloudflare Turnstile", cat: "Security", rules: [["script", /challenges\.cloudflare\.com\/turnstile/]] },
  { name: "Stripe", cat: "Payment", rules: [["script", /js\.stripe\.com/]] },
  { name: "PayPal", cat: "Payment", rules: [["script", /paypal\.com\/sdk\/js|paypalobjects\.com/]] },

  // ---- JavaScript libraries ----
  { name: "jQuery", cat: "JavaScript library", npm: "jquery", rules: [["script", /jquery[.-]([\d.]+)(?:\.min|\.slim|\.slim\.min)?\.js/i, true], ["html", /jQuery v([\d.]+)/, true], ["script", /\/jquery(?:\.min|\.slim)?\.js/]] },
  { name: "jQuery UI", cat: "JavaScript library", rules: [["script", /jquery-ui[.-]?([\d.]*)/i, true]] },
  { name: "Bootstrap", cat: "UI / CSS", npm: "bootstrap", rules: [["script", /bootstrap[.-]([\d.]+)(?:\.min)?\.(?:css|js)/i, true], ["html", /Bootstrap v([\d.]+)/i, true], ["script", /bootstrap(?:\.min)?\.(?:css|js)/i]] },
  { name: "Tailwind CSS", cat: "UI / CSS", rules: [["script", /cdn\.tailwindcss\.com/]] },
  { name: "Font Awesome", cat: "Font", rules: [["script", /font-?awesome/i]] },
  { name: "Lodash", cat: "JavaScript library", npm: "lodash", rules: [["script", /lodash[.@-]([\d.]+)/i, true], ["script", /lodash(?:\.min)?\.js/i]] },
  { name: "Moment.js", cat: "JavaScript library", npm: "moment", rules: [["script", /moment@([\d.]+)/i, true], ["script", /moment(?:\.min)?\.js/i]] },
  { name: "Chart.js", cat: "JavaScript library", npm: "chart.js", rules: [["script", /chart\.js@?([\d.]*)/i, true]] },
  { name: "Swiper", cat: "UI / CSS", rules: [["script", /swiper/i]] },
  { name: "Slick Carousel", cat: "UI / CSS", rules: [["script", /slick(?:\.min)?\.js|slick-carousel/i]] },
  { name: "Modernizr", cat: "JavaScript library", rules: [["script", /modernizr/i]] },
  { name: "GSAP", cat: "JavaScript library", rules: [["script", /\/gsap(?:\.min)?\.js|gsap@/i]] },
  { name: "Video.js", cat: "Video", rules: [["script", /\/video(?:\.min)?\.js|videojs/i]] },
  { name: "YouTube embed", cat: "Video", rules: [["html", /youtube(?:-nocookie)?\.com\/embed\//]] },
  { name: "Vimeo embed", cat: "Video", rules: [["html", /player\.vimeo\.com/]] },
  { name: "Leaflet", cat: "Maps", rules: [["script", /leaflet(?:\.min)?\.js/i]] },
  { name: "Google Maps", cat: "Maps", rules: [["script", /maps\.googleapis\.com\/maps\/api/]] },
  { name: "Mapbox", cat: "Maps", rules: [["script", /api\.mapbox\.com/]] },

  // ---- Fonts ----
  { name: "Google Fonts", cat: "Font", rules: [["script", /fonts\.googleapis\.com\/css/]] },
  { name: "Adobe Fonts (Typekit)", cat: "Font", rules: [["script", /use\.typekit\.net/]] },
];

export const SIG_BY_NAME = new Map(TECH_SIGS.map((s) => [s.name, s]));
