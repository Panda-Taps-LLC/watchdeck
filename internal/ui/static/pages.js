// The page barrel that app.js imports once at boot: each page module
// registers itself when this file imports it. Page modules import app.js,
// copy.js and shared.js (the helpers pages share), never this file, so the
// barrel adds no import cycle.
import "./home.js";
import "./sessions.js";
import "./rules.js";
import "./settings.js";
import "./map.js";
