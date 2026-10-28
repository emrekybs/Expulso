import { fetchWithTimeout, UserError } from "./net.ts";

const BASE = "https://api.hackertarget.com";

/** Queries the free HackerTarget API. An empty string means "no records". */
export async function htQuery(endpoint: string, q: string, timeoutMs = 25000): Promise<string> {
  const url = `${BASE}/${endpoint}/?q=${encodeURIComponent(q)}`;
  let res: Response;
  try {
    res = await fetchWithTimeout(url, { headers: { "user-agent": "ReconPanel/1.0" } }, timeoutMs);
  } catch (e) {
    if (e instanceof UserError) throw new UserError("HackerTarget did not answer in time.", "timeout");
    throw new UserError("Could not reach HackerTarget.", "upstream_error");
  }
  return interpretHt((await res.text()).trim(), res.status);
}

export function interpretHt(text: string, status = 200): string {
  if (/API count exceeded/i.test(text) || status === 429) {
    throw new UserError("HackerTarget free daily quota reached (about 50 queries per day per server IP).", "rate_limited");
  }
  if (/^error (check your search parameter|input invalid|check your api query)/i.test(text)) {
    throw new UserError("HackerTarget rejected the query as invalid.", "upstream_error");
  }
  if (/^error/i.test(text)) throw new UserError(`HackerTarget: ${text.replace(/^error\s*/i, "")}`, "upstream_error");
  if (/^no (dns )?(a )?records found|^no ptr records|^no records found/i.test(text)) return "";
  if (status >= 500) throw new UserError(`HackerTarget returned HTTP ${status}.`, "upstream_error");
  return text;
}
