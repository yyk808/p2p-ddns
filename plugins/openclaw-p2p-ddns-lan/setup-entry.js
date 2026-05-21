import { defineSetupPluginEntry } from "openclaw/plugin-sdk/channel-core";

import { p2pDdnsLanPlugin } from "./src/channel.js";

export default defineSetupPluginEntry(p2pDdnsLanPlugin);
