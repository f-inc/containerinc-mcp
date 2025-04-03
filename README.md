# @container-inc/mcp

MCP Server for deploying to [Container Inc.](https://container.inc)

> [!TIP]
> For now deployments are ephemneral and free. The platform is update coming soon to support more.

## Usage

```jsonc
// .cursor/mcp.json
{
  "mcpServers": {
    "@container-inc/mcp": {
      "command": "npx",
      "args": ["@container-inc/mcp"]
    }
  }
}
```

1. Place the above in a `.cursor/mcp.json` (or your editor's equivalent) file in your home directory.
2. Check the editor's settings to ensure it is enabled.
3. Just ask to deploy to Container Inc.

## Notes
* You'll be asked to login with GitHub this is so that:
  1. We can create a repository if needed
  2. Publish the docker image to ghcr.io
  3. Pull the code in the builder
* Ensure your project has a `Dockerfile` so it can be built
