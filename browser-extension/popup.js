const API_URL = "http://127.0.0.1:8000";

const elements = {
  connection: document.getElementById("connection"),
  dot: document.getElementById("status-dot"),
  mode: document.getElementById("mode"),
  engine: document.getElementById("engine"),
  worldModel: document.getElementById("world-model"),
  classifier: document.getElementById("classifier")
};

function setText(element, value) {
  element.textContent = value;
}

async function loadStatus() {
  try {
    const response = await fetch(`${API_URL}/api/health`);
    if (!response.ok) throw new Error("Agent unavailable");
    const health = await response.json();
    elements.connection.classList.add("online");
    elements.dot.classList.add("online");
    setText(elements.connection, "Local ShieldNet agent is online");
    setText(elements.mode, health.offline_ready ? "Offline" : "Connected");
    setText(elements.engine, health.device || "Local");
    setText(elements.worldModel, health.world_model_loaded ? "Loaded" : "Missing");
    setText(elements.classifier, health.secondary_model_loaded ? "Loaded" : "Missing");
  } catch (error) {
    setText(elements.connection, "Start ShieldNet to connect");
    setText(elements.mode, "Offline");
    setText(elements.engine, "Unavailable");
    setText(elements.worldModel, "--");
    setText(elements.classifier, "--");
  }
}

document.getElementById("dashboard").addEventListener("click", () => {
  chrome.tabs.create({ url: "https://shieldnet-sih.vercel.app/dashboard" });
});

document.getElementById("api").addEventListener("click", () => {
  chrome.tabs.create({ url: `${API_URL}/docs` });
});

loadStatus();