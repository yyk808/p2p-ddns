import { defineChannelPluginEntry } from "openclaw/plugin-sdk/channel-core";

import { p2pDdnsLanPlugin } from "./src/channel.js";
import { startLanInboundBridge } from "./src/inbound.js";

export default defineChannelPluginEntry({
  id: "p2p-ddns-lan",
  name: "p2p-ddns LAN",
  description: "Direct LAN channel backed by p2p-ddns discovery.",
  plugin: p2pDdnsLanPlugin,
  registerCliMetadata(api) {
    api.registerCli(
      ({ program }) => {
        program
          .command("p2p-ddns-lan")
          .description("p2p-ddns LAN channel management");
      },
      {
        descriptors: [
          {
            name: "p2p-ddns-lan",
            description: "p2p-ddns LAN channel management",
            hasSubcommands: false,
          },
        ],
      },
    );
  },
  registerFull(api) {
    startLanInboundBridge(api).catch((error) => {
      api.logger.warn(
        `[p2p-ddns-lan] inbound bridge stopped: ${String(error)}`,
      );
    });
  },
});
