import { OpenAPIHono } from "@hono/zod-openapi";

type AppEnv = {
  Bindings: Env;
};

const app = new OpenAPIHono<AppEnv>();

// Auth middleware
app.use("*", async (c, next) => {
  const secret = c.env.API_KEY;
  if (!secret) return c.text("Missing secret binding", 500);

  const authToken = c.req.header("Authorization") || "";
  const bearer = authToken.split(" ")[1] ?? "";
  const token = bearer || c.req.query("apiToken") || "";

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

// # Trello types #

interface TrelloCard {
  id: string;
  name: string;
  desc: string;
  shortUrl: string;
  labels: { name: string }[];
}

// # Button builders (mirrors "Get Buttons Json" task) #

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

// # Card → widget row (mirrors "Card List Widget" loop body) #

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

// # Build full widget scaffold for one list #

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

// # GET /widgets: returns all widget JSON in one shot #

app.get("/widgets", async (c) => {
  const trelloKey = c.env.TRELLO_KEY;
  const trelloToken = c.env.TRELLO_TOKEN;
  const toBoard = c.env.TO_BOARD;
  const listNameToId: Record<string, string> = JSON.parse(
    c.env.LIST_NAME_TO_ID,
  );
  const listNames = c.env.LIST_NAMES;
  const listNameToButtons = c.env.LIST_NAME_TO_BUTTONS;
  const icons = c.env.ICONS;

  // Fetch all lists in parallel
  const fetches = listNames.map(async (listName) => {
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
    return [listName, widget] as const;
  });

  const results = await Promise.all(fetches);
  const output: Record<string, any> = {};
  for (const [name, widget] of results) {
    output[name] = widget;
  }

  return c.json(output);
});

export default app;
export type { AppEnv };
