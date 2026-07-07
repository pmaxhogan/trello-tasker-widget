const $ = (id) => document.getElementById(id);

async function refreshStatus() {
  const { lastSync, lastStatus } = await chrome.storage.local.get([
    "lastSync",
    "lastStatus",
  ]);
  const when = lastSync
    ? new Date(lastSync).toLocaleString()
    : "never";
  $("status").textContent = `Last sync: ${when}\nStatus: ${lastStatus ?? "—"}`;
}

async function init() {
  const { inboxSessionKey } =
    await chrome.storage.sync.get("inboxSessionKey");
  if (inboxSessionKey) $("inboxSessionKey").value = inboxSessionKey;
  await refreshStatus();
}

$("save").addEventListener("click", async () => {
  const value = $("inboxSessionKey").value.trim();
  await chrome.storage.sync.set({ inboxSessionKey: value });
  chrome.runtime.sendMessage({ type: "sync-now" }, refreshStatus);
});

$("syncNow").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "sync-now" }, refreshStatus);
});

init();
