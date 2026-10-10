// opencode V2 entrypoint. opencode reads only the default export, and loads a
// plugin directory through its root index, so this file lives at the package
// root. Library exports live in src/lib.ts.
//
// Plugin.define() is an identity function, so the definition is exported
// directly: with only type imports the plugin needs no node_modules at runtime.
import type { Plugin } from "@opencode/plugin"
import { PLUGIN_ID, setupOpenBao } from "./src/plugin.ts"

export default {
  id: PLUGIN_ID,
  setup: (ctx) => setupOpenBao(ctx),
} satisfies Plugin.Plugin
