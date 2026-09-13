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

const VERCEL_URL = "https://shieldnet-sih.vercel.app/";
const LOCAL_REACT_URL = "http://localhost:5173/";
const STREAMLIT_URL = "http://127.0.0.1:8501/";

const defaultDashboardBtn = document.getElementById("dashboard");
if (defaultDashboardBtn) {
  defaultDashboardBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: "https://shieldnet-sih.vercel.app/dashboard" });
  });
}

const vercelBtn = document.getElementById("dashboard-vercel");
if (vercelBtn) {
  vercelBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: VERCEL_URL });
  });
}

const localBtn = document.getElementById("dashboard-local");
if (localBtn) {
  localBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: LOCAL_REACT_URL });
  });
}

const streamlitBtn = document.getElementById("dashboard-streamlit");
if (streamlitBtn) {
  streamlitBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: STREAMLIT_URL });
  });
}

const apiBtn = document.getElementById("api");
if (apiBtn) {
  apiBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: `${API_URL}/docs` });
  });
}

loadStatus();