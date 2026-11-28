import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { chatHash } from './push.js';

// Der Service Worker rechnet dieselbe Prüfsumme, um Mitteilungen gelesener Chats zu schließen
test('Push: chatHash im Server und im Service Worker gleich', () => {
  const sw = readFileSync(new URL('../../web/public/sw.js', import.meta.url), 'utf8');
  const src = sw.match(/function chatHash\(id\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(src, 'chatHash fehlt in sw.js');
  const swHash = new Function(`${src}; return chatHash;`)() as (s: string) => string;
  for (const id of ['wa1:491701234567@s.whatsapp.net', 'tg:-100123', 'sig:g:abc==', 'ä😀']) assert.equal(swHash(id), chatHash(id));
});
