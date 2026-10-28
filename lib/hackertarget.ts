import { fetchWithTimeout, UserError } from "./net.ts";

const BASE = "https://api.hackertarget.com";

/**
 * HackerTarget API'sine sorgu yapar (orijinal ExPulSo.py ile aynı kaynak).
 * Boş string dönerse "kayıt bulunamadı" anlamına gelir.
 */
export async function htQuery(endpoint: string, q: string, timeoutMs = 30000): Promise<string> {
  const key = process.env.HACKERTARGET_API_KEY;
  const url = `${BASE}/${endpoint}/?q=${encodeURIComponent(q)}${key ? `&apikey=${encodeURIComponent(key)}` : ""}`;
  let res: Response;
  try {
    res = await fetchWithTimeout(url, { headers: { "user-agent": "Expulso-CTI/2.0" } }, timeoutMs);
  } catch (e) {
    if (e instanceof UserError) throw new UserError("HackerTarget servisi zamanında yanıt vermedi.");
    throw new UserError("HackerTarget servisine bağlanılamadı.");
  }
  const text = (await res.text()).trim();
  return interpretHt(text, res.status);
}

export function interpretHt(text: string, status = 200): string {
  if (/API count exceeded/i.test(text) || status === 429) {
    throw new UserError(
      "HackerTarget ücretsiz günlük sorgu limiti doldu. Bir süre sonra tekrar deneyin veya Vercel ortam değişkenlerine HACKERTARGET_API_KEY ekleyin.",
    );
  }
  if (/^error check your (search|api) (parameter|query)/i.test(text) || /^error input invalid/i.test(text)) {
    throw new UserError("Geçersiz hedef: HackerTarget sorguyu kabul etmedi.");
  }
  if (/^error/i.test(text)) throw new UserError(`HackerTarget hatası: ${text.replace(/^error\s*/i, "")}`);
  if (/^No (DNS )?(A )?records found|^No PTR records|^no records found/i.test(text)) return "";
  if (status >= 500) throw new UserError(`HackerTarget servisi hata döndürdü (HTTP ${status}).`);
  return text;
}
