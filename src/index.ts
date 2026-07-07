import { OpenAPIHono } from "@hono/zod-openapi";

type AppEnv = {
  Bindings: Env;
};

const app = new OpenAPIHono<AppEnv>();

app.get("/health", (c) => c.text("OK"));

// Public privacy policy for the companion Chrome extension listing.
// Chrome Web Store rejects "owner sites" as privacy-policy URLs, so we serve
// a dedicated page with nothing else on it from the same origin the
// extension talks to.
const PRIVACY_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy — Trello Inbox Sync</title>
<style>
  :root { color-scheme: light dark; }
  body {
    font-family: system-ui, -apple-system, Segoe UI, sans-serif;
    line-height: 1.55;
    max-width: 720px;
    margin: 40px auto;
    padding: 0 20px;
  }
  h1 { margin-bottom: 4px; }
  .updated { color: #666; font-size: 14px; margin-bottom: 28px; }
  h2 { margin-top: 32px; font-size: 18px; }
  code { font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
  ul { padding-left: 22px; }
  li { margin: 4px 0; }
</style>
</head>
<body>
<h1>Trello Inbox Sync — Privacy Policy</h1>
<p class="updated">Last updated: 2026-07-05</p>

<h2>Who this applies to</h2>
<p>This policy applies to the Chrome extension <strong>Trello Inbox Sync</strong> (item ID <code>doiidcdjajjegchmhaahihopenpohmdp</code>), published by pmaxhogan for personal use with the <code>trello-tasker-widget</code> Cloudflare Worker.</p>

<h2>What data the extension collects</h2>
<p>The extension reads exactly <strong>one value</strong>: the <code>cloud.session.token</code> cookie set by <code>trello.com</code> in the user's own browser. No other cookies, page contents, form inputs, URLs, tab history, telemetry, analytics, crash reports, device identifiers, or usage metrics are read, recorded, or transmitted.</p>

<h2>Why it is collected</h2>
<p>Trello's built-in personal Inbox is not accessible through Trello's public REST API under any key + token combination — only browser sessions authenticated with the <code>cloud.session.token</code> cookie can read it. The extension exists solely to make the user's own Cloudflare Worker (the trello-tasker-widget backend) able to fetch the Inbox on the user's behalf, so it can be rendered on the user's Android Tasker widget.</p>

<h2>Where it is sent</h2>
<p>The cookie value is transmitted over HTTPS to a single endpoint: the user-specific Cloudflare Worker at <code>https://trello-tasker-widget.pmaxhogan.workers.dev/trello-session</code>. It is never sent anywhere else, and never sold, shared, or transferred to any third party, analytics service, advertising network, or affiliate.</p>

<h2>Where it is stored</h2>
<p>On the user's device: the extension's own configuration secret (the <code>INBOX_SESSION_KEY</code> the user pastes into the popup) and a last-sync timestamp/status are held in <code>chrome.storage.sync</code> and <code>chrome.storage.local</code>. On the backend: the Trello session cookie value is stored in a single Cloudflare Workers KV entry (<code>SESSION_KV["trello:cookie"]</code>) accessible only to the user's own Cloudflare account. Each new sync overwrites the previous value.</p>

<h2>Retention and deletion</h2>
<p>Uninstalling the extension immediately removes all extension-side storage from the browser. To delete the server-side copy, the user runs <code>wrangler kv key delete "trello:cookie" --namespace-id=&lt;their-namespace&gt;</code> against their own Cloudflare account, or deletes the KV namespace entirely.</p>

<h2>Third parties</h2>
<p>None. The extension does not integrate with, load code from, or send any data to any third-party service. Its only network activity is a single POST to the user's own Worker.</p>

<h2>Children</h2>
<p>The extension is not directed at children under 13 and does not knowingly collect data from them.</p>

<h2>Changes to this policy</h2>
<p>If the extension's data handling changes, this page will be updated and the "Last updated" date above will change. Users can review the current version at any time at this URL.</p>

<h2>Contact</h2>
<p>Questions or requests: <a href="mailto:max@maxhogan.dev">max@maxhogan.dev</a>.</p>
</body>
</html>`;

app.get("/privacy", (c) => c.html(PRIVACY_HTML));

function timingSafeEqualStr(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const av = encoder.encode(a);
  const bv = encoder.encode(b);
  if (av.byteLength !== bv.byteLength) {
    // still spend time on a comparison to keep timing uniform
    crypto.subtle.timingSafeEqual(av, av);
    return false;
  }
  return crypto.subtle.timingSafeEqual(av, bv);
}

// Auth middleware — gates /refresh with the widget-facing API_KEY.
// /trello-session bypasses this and is instead gated by INBOX_SESSION_KEY
// (distinct secret) so a leak of the widget key does not compromise the
// Chrome-extension endpoint and vice versa.
app.use("*", async (c, next) => {
  if (c.req.path === "/trello-session" || c.req.path === "/privacy") {
    await next();
    return;
  }
  const secret = c.env.API_KEY;
  if (!secret) return c.text("Missing secret binding", 500);
  const authToken = c.req.header("Authorization") || "";
  const bearer = authToken.split(" ")[1] ?? "";
  const token = bearer || c.req.query("apiKey") || "";
  if (!timingSafeEqualStr(token, secret)) return c.text("Unauthorized", 401);
  await next();
});

// POST /trello-session — companion Chrome extension pushes the current
// cloud.session.token cookie value here. Used to fetch the Inbox list, which
// Trello's public REST API 401s under any key+token.
//
// Security posture (this repo is public — do not weaken these):
// - Gated by INBOX_SESSION_KEY, distinct from the widget API_KEY. A leak of
//   one does not compromise the other. Extension stores the key in
//   chrome.storage.sync (per-user, encrypted); nothing hardcoded in source.
// - Constant-time comparison to prevent timing oracle on the key.
// - KV-backed rate limit (~20 writes/min globally) blunts a junk-token DoS
//   even if the key leaks — worst case the widget shows a stale/broken
//   Inbox row until the next legitimate sync overwrites the KV entry.
// - Shape validation on the cookie payload: Trello's cloud.session.token is
//   a URL-safe base64ish string, 40–4096 chars. Reject anything else.
const SESSION_COOKIE_SHAPE = /^[A-Za-z0-9._\-+/=%~]{40,4096}$/;

async function checkAndBumpSessionRate(kv: KVNamespace): Promise<boolean> {
  const windowSec = 60;
  const limit = 20;
  const bucket = Math.floor(Date.now() / 1000 / windowSec);
  const key = `sessionrate:${bucket}`;
  const current = parseInt((await kv.get(key)) ?? "0", 10);
  if (current >= limit) return false;
  await kv.put(key, String(current + 1), {
    expirationTtl: windowSec * 2,
  });
  return true;
}

app.post("/trello-session", async (c) => {
  const expected = c.env.INBOX_SESSION_KEY;
  if (!expected) return c.text("Missing secret binding", 500);
  const authToken = c.req.header("Authorization") || "";
  const bearer = authToken.split(" ")[1] ?? "";
  if (!timingSafeEqualStr(bearer, expected)) {
    return c.text("Unauthorized", 401);
  }
  if (!(await checkAndBumpSessionRate(c.env.SESSION_KV))) {
    return c.text("Rate limited", 429);
  }
  let body: { token?: unknown };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "invalid json" }, 400);
  }
  const token = body.token;
  if (typeof token !== "string" || !SESSION_COOKIE_SHAPE.test(token)) {
    return c.json({ error: "missing or malformed token" }, 400);
  }
  await c.env.SESSION_KV.put("trello:cookie", token);
  return c.json({ ok: true, length: token.length });
});

// Trello types

interface TrelloCard {
  id: string;
  name: string;
  desc: string;
  shortUrl: string;
  labels: { name: string }[];
}

// Button builders
function buildButtons(
  buttonNames: string[],
  card: TrelloCard,
  listId: string,
  toBoard: string,
  listNameToId: Record<string, string>,
  icons: Record<string, string>,
): any[] {
  const out: any[] = [];
  for (const btn of buttonNames) {
    if (btn === "Rename") {
      out.push({
        buttonType: "Square",
        contentColor: "onBackground",
        icon: icons.Rename,
        backgroundColor: "widgetBackground",
        cornerRadius: 1,
        padding: -10,
        size: { height: 25, width: 25 },
        type: "IconButton",
        useMaterialYouColors: true,
        task: "Card Rename",
        taskVariables: { par1: card.id },
      });
    } else if (btn === "Done") {
      out.push({
        type: "CheckBox",
        task: "Card Done & Move To Done",
        taskVariables: { card: card.id, list: listId, par2: card.id },
      });
    } else if (btn === "Archive") {
      out.push({
        buttonType: "Square",
        contentColor: "onBackground",
        icon: icons.Archive,
        backgroundColor: "widgetBackground",
        cornerRadius: 1,
        padding: -10,
        size: { height: 25, width: 25 },
        type: "IconButton",
        useMaterialYouColors: true,
        task: "Card Done (Archive Only)",
        taskVariables: {
          card: card.id,
          par2: card.id,
          is_done: true,
          par1: true,
        },
      });
    } else if (btn === "Tomorrow") {
      out.push({
        buttonType: "Square",
        contentColor: "onBackground",
        icon: icons.Tomorrow,
        backgroundColor: "widgetBackground",
        cornerRadius: 1,
        padding: -10,
        size: { height: 25, width: 25 },
        type: "IconButton",
        useMaterialYouColors: true,
        task: "Tomorrow",
        taskVariables: { card: card.shortUrl, par1: card.shortUrl },
      });
    } else {
      // Move-to-list button (Ready, Today, Work, etc.)
      const toListId = listNameToId[btn];
      if (!toListId || toListId.length !== 24) continue;
      const icon = icons[btn] || "";
      out.push({
        buttonType: "Square",
        contentColor: "onBackground",
        icon,
        backgroundColor: "widgetBackground",
        cornerRadius: 1,
        padding: -10,
        size: { height: 25, width: 25 },
        type: "IconButton",
        useMaterialYouColors: true,
        task: "Card Move",
        taskVariables: {
          card: card.id,
          to_list: toListId,
          to_board: toBoard,
          par2: card.id,
        },
      });
    }
  }
  return out;
}

// Card → widget row

function cardToWidgetRow(card: TrelloCard, buttons: any[]): any {
  const cardname = card.name; // already plain text from Trello API

  // Divider label → bold centered header row
  const hasDivider = card.labels.some((l) => l.name.includes("Divider"));
  if (hasDivider) {
    return {
      children: [
        {
          align: "Center",
          bold: true,
          maxLines: 2,
          text: cardname.toUpperCase(),
          isWeighted: false,
          size: { fillMaxWidth: true },
          task: "Open Par2",
          taskVariables: { par2: card.shortUrl },
          type: "Text",
        },
      ],
      horizontalAlignment: "Start",
      verticalAlignment: "Center",
      size: { fillMaxWidth: true },
      type: "Row",
    };
  }

  // Separator card (name contains "---------")
  if (cardname.includes("---------")) {
    return {
      backgroundColor: "secondary",
      cornerRadius: 5,
      size: { fillMaxWidth: true, height: 1 },
      type: "Spacer",
    };
  }

  // Normal card row: [buttons...] [card name text]
  return {
    children: [
      ...buttons,
      {
        align: "Start",
        maxLines: 2,
        text: cardname,
        isWeighted: false,
        type: "Text",
        task: "Open Par2",
        taskVariables: { par2: card.shortUrl },
      },
    ],
    horizontalAlignment: "Start",
    verticalAlignment: "Center",
    size: { fillMaxWidth: true },
    type: "Row",
    padding: { top: -3, bottom: -3, start: 0, end: 0 },
  };
}

// Build full widget scaffold for one list
function buildWidgetScaffold(
  listName: string,
  cards: TrelloCard[],
  items: any[],
  icons: Record<string, string>,
): any {
  return {
    children: [
      {
        type: "Column",
        paddingStart: 4,
        paddingEnd: 4,
        fillMaxWidth: true,
        verticalAlignment: "Center",
        horizontalAlignment: "Start",
        scrolling: true,
        useMaterialYouColors: true,
        children: [
          // Header row
          {
            children: [
              {
                align: "Start",
                bold: true,
                maxLines: 2,
                text: `${listName} \u2022 ${cards.length}`,
                isWeighted: false,
                type: "Text",
              },
              {
                isWeighted: true,
                size: { fillMaxWidth: true },
                type: "Spacer",
              },
              {
                buttonType: "Square",
                contentColor: "onBackground",
                icon: icons.Refresh,
                backgroundColor: "widgetBackground",
                cornerRadius: 1,
                padding: 5,
                size: 30,
                task: "Refresh All",
                type: "IconButton",
                useMaterialYouColors: true,
              },
            ],
            horizontalAlignment: "Start",
            verticalAlignment: "Center",
            padding: { top: 3 },
            size: { fillMaxWidth: true },
            type: "Row",
          },
          // Card rows
          ...items,
        ],
      },
    ],
    type: "Scaffold",
  };
}

// GET /refresh: returns widgets + work notification in one shot
// Optimized: uses Trello batch API to combine all fetches into a single HTTP request

app.get("/refresh", async (c) => {
  const trelloKey = c.env.TRELLO_KEY;
  const trelloToken = c.env.TRELLO_TOKEN;
  const toBoard = c.env.TO_BOARD;
  const listNameToId: Record<string, string> = JSON.parse(
    c.env.LIST_NAME_TO_ID,
  );
  const listNames = c.env.LIST_NAMES;
  const listNameToButtons = c.env.LIST_NAME_TO_BUTTONS;
  const icons = c.env.ICONS;
  const timeEstimateMap: Record<string, string> = JSON.parse(
    c.env.TIME_ESTIMATE_MAP,
  );
  const workListId = listNameToId["Work"];
  const doneListId = listNameToId["Done"];

  // Build reverse lookup: listId → listName
  const listIdToName: Record<string, string> = {};
  for (const [name, id] of Object.entries(listNameToId)) {
    listIdToName[id] = name;
  }

  // 3 parallel API calls:
  // 1. All board cards — covers Ready/Today/Progress/Work/Done widget lists
  // 2. Work list cards with actions — for computeSecondsInList on active work card
  // 3. Inbox list cards — Inbox is on a separate board, cookie-authenticated
  //
  // NOTE: Trello's built-in personal Inbox (from /members/me?fields=inbox) is
  // NOT accessible via key+token — every REST endpoint 401s regardless of scope.
  // It only responds to cookie-authenticated browser sessions. A companion
  // Chrome extension keeps SESSION_KV["trello:cookie"] fresh with the current
  // cloud.session.token cookie; we fetch the Inbox list via trello.com with
  // that cookie as `Cookie: cloud.session.token=<val>`.
  const auth = `key=${trelloKey}&token=${trelloToken}`;
  const inboxListId = listNameToId["Inbox"];
  const trelloSessionCookie = await c.env.SESSION_KV.get("trello:cookie");
  const [boardCardsResp, workCardsResp, inboxCardsResp] = await Promise.all([
    fetch(
      `https://api.trello.com/1/boards/${toBoard}/cards?customFieldItems=true&fields=name,desc,shortUrl,labels,idList,cover&label_fields=name&${auth}`,
    ),
    fetch(
      `https://api.trello.com/1/lists/${workListId}/cards?actions=updateCard:idList,moveCardToBoard,moveInboxCardToBoard&actions_limit=1000&customFieldItems=true&fields=id,name,desc,shortUrl,labels,cover&action_member=false&action_memberCreator=false&action_fields=data,date&label_fields=name&${auth}`,
    ),
    trelloSessionCookie
      ? fetch(
          `https://trello.com/1/lists/${inboxListId}/cards?customFieldItems=true&fields=name,desc,shortUrl,labels&label_fields=name`,
          { headers: { Cookie: `cloud.session.token=${trelloSessionCookie}` } },
        )
      : Promise.resolve(
          new Response("no session cookie stored", { status: 428 }),
        ),
  ]);

  if (!boardCardsResp.ok) {
    return c.json(
      { error: "Trello board cards API failed", status: boardCardsResp.status },
      500,
    );
  }

  const allCards: (TrelloCardFull & { idList: string })[] =
    await boardCardsResp.json();
  const workCardsWithActions: TrelloCardFull[] = workCardsResp.ok
    ? await workCardsResp.json()
    : [];
  let inboxCards: TrelloCardFull[] = [];
  let inboxError: string | null = null;
  if (inboxCardsResp.ok) {
    inboxCards = await inboxCardsResp.json();
  } else {
    const body = await inboxCardsResp.text().catch(() => "");
    inboxError = `${inboxCardsResp.status}: ${body.slice(0, 200)}`;
  }

  // Partition all board cards by list
  const cardsByListId: Record<string, TrelloCardFull[]> = {};
  for (const card of allCards) {
    const lid = card.idList;
    if (!cardsByListId[lid]) cardsByListId[lid] = [];
    cardsByListId[lid].push(card);
  }
  // Inbox is on a separate board — inject into the partition map
  cardsByListId[inboxListId] = inboxCards;

  // Build widgets for each list in LIST_NAMES
  const widgetResults = listNames.map((listName) => {
    const listId = listNameToId[listName];
    const cards: TrelloCardFull[] = cardsByListId[listId] ?? [];
    const buttonNames = (listNameToButtons[listName] || "").split(",");

    const items = cards.map((card) => {
      const buttons = buildButtons(
        buttonNames,
        card,
        listId,
        toBoard,
        listNameToId,
        icons,
      );
      return cardToWidgetRow(card, buttons);
    });

    if (listName === "Inbox" && inboxError) {
      const isNoCookie = inboxError.startsWith("428");
      const rowText = isNoCookie
        ? "Install Trello Inbox Sync extension → sign in to trello.com"
        : `Open Trello Inbox (session issue: ${inboxError})`;
      items.push({
        children: [
          {
            align: "Start",
            maxLines: 3,
            text: rowText,
            isWeighted: false,
            type: "Text",
            task: "Open Par2",
            taskVariables: { par2: "https://trello.com/inbox" },
          },
        ],
        horizontalAlignment: "Start",
        verticalAlignment: "Center",
        size: { fillMaxWidth: true },
        type: "Row",
      });
    }

    const widget = buildWidgetScaffold(listName, cards, items, icons);
    return { listName: `Card List ${listId}`, widget };
  });

  // Build work notification using partitioned cards
  const mustCards = cardsByListId[listNameToId["Today"]] ?? [];
  const progressCards = cardsByListId[listNameToId["Progress"]] ?? [];
  const workCards = workCardsWithActions;
  const doneCards = cardsByListId[doneListId] ?? [];

  const numMust = mustCards.length;
  const numProgress = progressCards.length;
  const numWork = workCards.length;
  const numDone = doneCards.length;

  const mustMinutes = sumEstimatedMinutes(mustCards, timeEstimateMap);
  const progressMinutes = sumEstimatedMinutes(progressCards, timeEstimateMap);
  const workMinutes = sumEstimatedMinutes(workCards, timeEstimateMap);
  const doneMinutes = sumEstimatedMinutes(doneCards, timeEstimateMap);
  const totalMinutes =
    mustMinutes + progressMinutes + workMinutes + doneMinutes;
  const completedMinutes = doneMinutes + workMinutes * 0.5;
  const progress =
    totalMinutes > 0 ? Math.round((completedMinutes / totalMinutes) * 100) : 0;

  const fmtMust = formatSeconds(mustMinutes * 60);
  const fmtProgress = formatSeconds(progressMinutes * 60);
  const fmtWork = formatSeconds(workMinutes * 60);
  const fmtDone = formatSeconds(doneMinutes * 60);
  const statusText = `${progress}%: ${fmtMust} MUST + ${fmtProgress} Progress + ${fmtWork} Work, ${fmtDone} Done`;

  const numTotal = numMust + numProgress + numWork + numDone;

  let workNotification: any;

  if (numDone === numTotal && numTotal > 0) {
    workNotification = {
      state: "all_done",
      progress,
      numMust,
      numProgress,
      numWork,
      numDone,
      numTotal,
      text: statusText,
    };
  } else if (workCards.length === 0) {
    workNotification = {
      state: "none_in_work",
      progress,
      numMust,
      numProgress,
      numWork,
      numDone,
      numTotal,
      icon: "W!",
      title: "None in progress",
      text: statusText,
    };
  } else {
    const card = workCards[0];
    const { priority, timeEstimate } = resolveCustomFields(
      card,
      timeEstimateMap,
    );
    const secondsInList = computeSecondsInList(card, workListId);
    const timeInList = formatSeconds(secondsInList);

    workNotification = {
      state: "in_work",
      progress,
      numMust,
      numProgress,
      numWork,
      numDone,
      numTotal,
      icon: "W",
      title: `${timeInList}/${timeEstimate}: ${card.name}`,
      text: statusText,
      card: {
        id: card.id,
        name: card.name,
        desc: card.desc,
        shortUrl: card.shortUrl,
        labels: card.labels,
        priority,
        timeEstimate,
        timeInList,
        secondsInList,
      },
    };
  }

  return c.json({
    widgets: widgetResults,
    workNotification,
    ...(inboxError ? { inboxError } : {}),
  });
});

// Custom field maps loaded from env secrets: TIME_ESTIMATE_MAP, PRIORITY_MAP

// Midpoint minutes for each time estimate bucket, used for progress calculation
const TIME_ESTIMATE_MINUTES: Record<string, number> = {
  "<5m": 2.5,
  "5-15m": 10,
  "15-30m": 22.5,
  "30m-1hr": 45,
  "1-3hrs": 120,
  "3+hrs": 240,
};

function sumEstimatedMinutes(
  cards: { customFieldItems: { idValue: string }[] }[],
  timeEstimateMap: Record<string, string>,
): number {
  let total = 0;
  for (const card of cards) {
    for (const field of card.customFieldItems) {
      const label = timeEstimateMap[field.idValue];
      if (label && label in TIME_ESTIMATE_MINUTES) {
        total += TIME_ESTIMATE_MINUTES[label];
        break;
      }
    }
  }
  return total;
}

function formatSeconds(seconds: number): string {
  if (seconds < 0) return "0s";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

interface TrelloAction {
  data: {
    listBefore?: { id: string };
    listAfter?: { id: string };
    list?: { id: string };
  };
  date: string;
}

interface TrelloCardFull extends TrelloCard {
  customFieldItems: { idValue: string; idCustomField: string }[];
  actions: TrelloAction[];
  checklists: any[];
  cover?: { color: string | null };
}

const COVER_COLOR_TO_PRIORITY: Record<string, string> = {
  red: "MUST",
  orange: "SHOULD",
  yellow: "COULD",
};

function computeSecondsInList(card: TrelloCardFull, listId: string): number {
  // Initial start time: derived from card ID (Trello ObjectId = first 8 hex chars = unix timestamp)
  let startEpoch = parseInt(card.id.substring(0, 8), 16);
  let secondsInList = 0;

  // Process actions in chronological order (Trello returns newest first)
  const actions = [...card.actions].reverse();

  for (const action of actions) {
    const actionEpoch = Math.floor(new Date(action.date).getTime() / 1000);

    const enteredList =
      action.data.listAfter?.id === listId || action.data.list?.id === listId;
    const exitedList = action.data.listBefore?.id === listId;

    if (enteredList) {
      startEpoch = actionEpoch;
    }

    if (exitedList) {
      const diff = actionEpoch - startEpoch;
      if (diff > 0) {
        secondsInList += diff;
      }
    }
  }

  // Add time from last enter to now
  const nowEpoch = Math.floor(Date.now() / 1000);
  secondsInList += nowEpoch - startEpoch;

  return secondsInList;
}

function resolveCustomFields(
  card: TrelloCardFull,
  timeEstimateMap: Record<string, string>,
): {
  priority: string;
  timeEstimate: string;
} {
  let timeEstimate = "???";

  for (const field of card.customFieldItems) {
    if (field.idValue in timeEstimateMap) {
      timeEstimate = timeEstimateMap[field.idValue];
    }
  }

  const priority =
    (card.cover?.color && COVER_COLOR_TO_PRIORITY[card.cover.color]) || "WOULD";

  return { priority, timeEstimate };
}

export default app;
export type { AppEnv };
