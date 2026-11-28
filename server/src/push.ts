import webpush from 'web-push';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Store } from './db.js';
import type { Chat, Message } from './types.js';
import { localize, previewText, uiLang } from './hub.js';

const host = (u: string) => { try { return new URL(u).host; } catch { return '?'; } };

/** FNV-1a, 32 Bit, Base 36. Muss mit chatHash() in web/public/sw.js übereinstimmen. */
export function chatHash(id: string) {
  let h = 0x811c9dc5;
  for (let i = 0; i < id.length; i++) { h ^= id.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(36);
}

type Sub = { endpoint: string; keys: { p256dh: string; auth: string }; ua?: string; created: number };

/**
 * Echte Push-Benachrichtigungen (Web Push mit VAPID): kommen auch an, wenn Chorus geschlossen ist
 * (iPhone: nur als installierte App vom Home-Bildschirm). Die Inhalte sind Ende-zu-Ende verschlüsselt
 * bis zum Gerät; Apple/Google sehen sie nicht.
 */
export class Push {
  readonly publicKey: string;
  constructor(dataDir: string) {
    const f = join(dataDir, 'vapid.json');
    let k: { publicKey: string; privateKey: string };
    if (existsSync(f)) k = JSON.parse(readFileSync(f, 'utf8'));
    else { k = webpush.generateVAPIDKeys(); writeFileSync(f, JSON.stringify(k), { mode: 0o600 }); }
    this.publicKey = k.publicKey;
    webpush.setVapidDetails(process.env.PUSH_SUBJECT ?? 'mailto:chorus@example.com', k.publicKey, k.privateKey);
  }

  subs(store: Store): Sub[] { return store.getSetting<Sub[]>('pushSubs', []); }
  add(store: Store, s: Sub) {
    if (!this.subs(store).some((x) => x.endpoint === s.endpoint)) console.log('[push] neues Gerät angemeldet', host(s.endpoint));
    store.setSetting('pushSubs', [...this.subs(store).filter((x) => x.endpoint !== s.endpoint), s].slice(-20)); }
  remove(store: Store, endpoint: string) { store.setSetting('pushSubs', this.subs(store).filter((x) => x.endpoint !== endpoint)); }
  preview(store: Store): boolean { return store.getSetting('pushPreview', true); }

  /** skip: Geräte, auf denen Chorus gerade offen und sichtbar ist. Die bekommen nichts, alle anderen schon.
   *  Alle Geräte gleichzeitig: ein hängendes, totes Abo hielt vorher die Zustellung an alle anderen auf. */
  async send(store: Store, payload: Record<string, unknown>, only?: string | Set<string>, skip?: Set<string>) {
    let ok = 0, gone = 0, fail = 0, open = 0;
    const subs = this.subs(store).filter((s) => !only || (typeof only === 'string' ? s.endpoint === only : only.has(s.endpoint)));
    if (!subs.length) return;
    // Bei jeder Push mitschicken, welche Chats noch ungelesen sind: Das Gerät schließt dann Mitteilungen von Chats,
    // die inzwischen woanders gelesen wurden, und setzt die Zahl am App-Symbol. iOS erlaubt keine „stillen“ Push zum Aufräumen.
    const body = JSON.stringify({ ...payload, ...this.unreadState(store) });
    await Promise.all(subs.map(async (s) => {
      if (skip?.has(s.endpoint)) { open++; return; }
      try { await webpush.sendNotification(s, body, { TTL: 6 * 3600, urgency: 'high', timeout: 15_000 }); ok++; }
      catch (e: any) {
        if (e?.statusCode === 404 || e?.statusCode === 410) { gone++; this.remove(store, s.endpoint); } // abgemeldet/abgelaufen
        else { fail++; console.warn('[push] Fehler', host(s.endpoint), e?.statusCode ?? '', e?.body ?? e?.message ?? e); }
      }
    }));
    console.log(`[push] gesendet ${ok}${open ? `, ${open} übersprungen (App dort offen)` : ''}${gone ? `, ${gone} abgelaufene Abos entfernt` : ''}${fail ? `, ${fail} fehlgeschlagen` : ''}`);
  }
  /** Push-Inhalte dürfen nur ~4 KB groß sein: Chats als kurze Prüfsumme (gleiche Rechnung im Service Worker).
   *  Bei sehr vielen ungelesenen Chats wird nichts geschlossen (lieber eine alte Mitteilung zu viel als eine zu wenig). */
  private unreadState(store: Store) {
    const cs = store.unreadChats();
    const badge = cs.reduce((n, c) => n + c.unread, 0);
    return cs.length > 200 ? { badge } : { badge, unread: cs.map((c) => chatHash(c.id)).join(',') };
  }

  /** Schon benachrichtigte Nachrichten: dieselbe Nachricht meldet sich nie zweimal (z. B. doppelt zugestellt) */
  private notified = new Set<string>();
  notify(store: Store, chat: Chat, m: Message, skip?: Set<string>, only?: Set<string>) {
    if (!this.subs(store).length) { console.log('[push] übersprungen: keine Geräte angemeldet'); return; }
    // only = Nachzügler (Gerät meldete „sichtbar“, antwortete aber nicht): gehört zur selben Nachricht, kein Doppel
    if (!only) {
      if (this.notified.has(m.id)) { console.log('[push] übersprungen: Nachricht schon gemeldet'); return; }
      this.notified.add(m.id);
      if (this.notified.size > 2000) this.notified = new Set([...this.notified].slice(-1000));
    }
    const full = this.preview(store);
    const lang = uiLang(store);
    const text = localize(previewText(m), lang);
    const imgIdx = m.deleted ? -1 : m.attachments.findIndex((a) => a.kind === 'image' || a.kind === 'video');
    void this.send(store, {
      title: full ? chat.title : 'Chorus',
      body: full ? (chat.kind === 'direct' ? text : `${m.senderName}: ${text}`) : localize('Neue Nachricht', lang),
      chatId: chat.id, tag: chat.id, msgId: m.id,
      // Vorschaubild (Foto/Video-Standbild). Der Service Worker lädt es selbst; iPhone/iPad zeigen keine Bilder in Benachrichtigungen
      ...(full && imgIdx >= 0 ? { image: `/api/attachment?m=${encodeURIComponent(m.id)}&i=${imgIdx}&thumb=1` } : {}),
    }, only, skip);
  }
}
