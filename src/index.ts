import { OpenAPIHono } from "@hono/zod-openapi";

type AppEnv = {
  Bindings: Env;
};

const app = new OpenAPIHono<AppEnv>();

app.get("/health", (c) => c.text("OK"));

// Auth middleware
app.use("*", async (c, next) => {
  const secret = c.env.API_KEY;
  if (!secret) return c.text("Missing secret binding", 500);

  const authToken = c.req.header("Authorization") || "";
  const bearer = authToken.split(" ")[1] ?? "";
  const token = bearer || c.req.query("apiKey") || "";

  const encoder = new TextEncoder();
  const userValue = encoder.encode(token);
  const secretValue = encoder.encode(secret);

  const lengthsMatch = userValue.byteLength === secretValue.byteLength;
  const isEqual = lengthsMatch
    ? crypto.subtle.timingSafeEqual(userValue, secretValue)
    : !crypto.subtle.timingSafeEqual(userValue, userValue);

  if (!isEqual) return c.text("Unauthorized", 401);
  await next();
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
  const priorityMap: Record<string, string> = JSON.parse(c.env.PRIORITY_MAP);
  const workListId = listNameToId["Work"];

  // Fetch all widget lists + board lists + work cards in parallel
  const widgetFetches = listNames.map(async (listName) => {
    const listId = listNameToId[listName];
    const url = `https://api.trello.com/1/lists/${listId}/cards?key=${trelloKey}&token=${trelloToken}&fields=name,desc,shortUrl,labels`;

    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(
        `Trello API failed for ${listName}: ${resp.status} ${resp.statusText}`,
      );
    }
    const cards: TrelloCard[] = await resp.json();

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

    const widget = buildWidgetScaffold(listName, cards, items, icons);
    return { listName: `Card List ${listId}`, widget };
  });

  const boardListsFetch = fetch(
    `https://api.trello.com/1/boards/${toBoard}/lists?fields=id,name&card_fields=id&cards=open&key=${trelloKey}&token=${trelloToken}`,
  );

  const workCardsFetch = fetch(
    `https://api.trello.com/1/lists/${workListId}/cards?actions_limit=1000&actions=updateCard:idList,moveCardToBoard,moveInboxCardToBoard&customFieldItems=true&fields=id,actions,name,desc,shortUrl,labels&checklists=all&action_member=false&action_memberCreator=false&action_fields=data,date&key=${trelloKey}&token=${trelloToken}`,
  );

  const [widgetResults, boardListsResp, workCardsResp] = await Promise.all([
    Promise.all(widgetFetches),
    boardListsFetch,
    workCardsFetch,
  ]);

  // Build work notification
  let workNotification: any;

  if (!boardListsResp.ok || !workCardsResp.ok) {
    workNotification = {
      state: "error",
      error: "Trello API failed",
      boardLists: boardListsResp.status,
      workCards: workCardsResp.status,
    };
  } else {
    const boardLists: TrelloBoardList[] = await boardListsResp.json();
    const workCards: TrelloCardFull[] = await workCardsResp.json();

    let numMust = 0;
    let numProgress = 0;
    let numDone = 0;
    for (const list of boardLists) {
      if (list.name === "MUST") numMust = list.cards.length;
      if (list.name === "In Progress") numProgress = list.cards.length;
      if (list.name === "Done") numDone = list.cards.length;
    }

    const numTotal = numMust + numProgress + numDone;
    const progress = numTotal > 0 ? Math.round((numDone / numTotal) * 100) : 0;

    if (numDone === numTotal && numTotal > 0) {
      workNotification = {
        state: "all_done",
        progress,
        numMust,
        numProgress,
        numDone,
        numTotal,
      };
    } else if (workCards.length === 0) {
      workNotification = {
        state: "none_in_work",
        progress,
        numMust,
        numProgress,
        numDone,
        numTotal,
        icon: "W!",
        title: "None in progress",
        text: `${progress}%: ${numMust} MUST + ${numProgress} Progress, ${numDone} Done`,
      };
    } else {
      const card = workCards[0];
      const { priority, timeEstimate } = resolveCustomFields(
        card,
        timeEstimateMap,
        priorityMap,
      );
      const secondsInList = computeSecondsInList(card, workListId);
      const timeInList = formatSeconds(secondsInList);

      workNotification = {
        state: "in_work",
        progress,
        numMust,
        numProgress,
        numDone,
        icon: "W",
        numTotal,
        title: `${timeInList}/${timeEstimate}: ${card.name}`,
        text: `${progress}%: ${numMust} MUST + ${numProgress} Progress, ${numDone} Done`,
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
  }

  return c.json({
    widgets: widgetResults,
    workNotification,
  });
});

// Custom field maps loaded from env secrets: TIME_ESTIMATE_MAP, PRIORITY_MAP

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
}

interface TrelloBoardList {
  id: string;
  name: string;
  cards: { id: string }[];
}

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
  priorityMap: Record<string, string>,
): {
  priority: string;
  timeEstimate: string;
} {
  let priority = "???";
  let timeEstimate = "???";

  for (const field of card.customFieldItems) {
    if (field.idValue in timeEstimateMap) {
      timeEstimate = timeEstimateMap[field.idValue];
    }
    if (field.idValue in priorityMap) {
      priority = priorityMap[field.idValue];
    }
  }

  return { priority, timeEstimate };
}

export default app;
export type { AppEnv };
