// Trello Inbox Sync — background service worker.
//
// The Trello Inbox is UI-only: its board/list IDs come back from
// /members/me?fields=inbox, but every REST endpoint 401s under any key+token,
// even with scope=account. Only cookie-authenticated browser sessions can
// read it — specifically the httpOnly `cloud.session.token` cookie on
// trello.com. This extension mirrors that cookie into a Cloudflare Worker's
// KV store so the Worker can fetch the Inbox on the widget's behalf.

const WORKER_ORIGIN = "https://trello-tasker-widget.pmaxhogan.workers.dev";
const SESSION_ENDPOINT = `${WORKER_ORIGIN}/trello-session`;
const COOKIE_NAME = "cloud.session.token";
const ALARM_NAME = "trello-inbox-sync";
// Trello session cookies live for ~30 days but the server may rotate them
// earlier. Re-sync every 6 hours as a safety net in addition to onChanged.
const PERIOD_MINUTES = 6 * 60;

async function getInboxSessionKey() {
  const { inboxSessionKey } = await chrome.storage.sync.get("inboxSessionKey");
  return typeof inboxSessionKey === "string" && inboxSessionKey.length > 0
    ? inboxSessionKey
    : null;
}

async function readCookie() {
  const cookie = await chrome.cookies.get({
    url: "https://trello.com/",
    name: COOKIE_NAME,
  });
  return cookie?.value ?? null;
}

async function recordStatus(status) {
  await chrome.storage.local.set({
    lastSync: Date.now(),
    lastStatus: status,
  });
}

async function syncCookie(reason) {
  const [sessionKey, token] = await Promise.all([
    getInboxSessionKey(),
    readCookie(),
  ]);
  if (!sessionKey) {
    await recordStatus("no INBOX_SESSION_KEY configured");
    return;
  }
  if (!token) {
    await recordStatus("no cookie — log in to trello.com");
    return;
  }
  try {
    const resp = await fetch(SESSION_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${sessionKey}`,
      },
      body: JSON.stringify({ token }),
    });
    if (resp.ok) {
      await recordStatus(`ok (${reason})`);
    } else {
      const text = await resp.text().catch(() => "");
      await recordStatus(`http ${resp.status}: ${text.slice(0, 120)}`);
    }
  } catch (err) {
    await recordStatus(`network error: ${err?.message ?? err}`);
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(ALARM_NAME, { periodInMinutes: PERIOD_MINUTES });
  syncCookie("install");
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(ALARM_NAME, { periodInMinutes: PERIOD_MINUTES });
  syncCookie("startup");
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) syncCookie("alarm");
});

chrome.cookies.onChanged.addListener(({ cookie, removed }) => {
  if (cookie.name !== COOKIE_NAME) return;
  if (!cookie.domain.endsWith("trello.com")) return;
  if (removed) return;
  syncCookie("cookie changed");
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "sync-now") {
    syncCookie("manual").then(() => sendResponse({ ok: true }));
    return true;
  }
});
