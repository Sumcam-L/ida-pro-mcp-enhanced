// dsh-ida-mcp host bundle.
//
// The actual capability lives in cordis.patch.yml: it registers an
// @deepseek-ai/dsh-mcp-client instance that bridges the local ida-pro-mcp
// broker into ctx.tools. This empty apply exists so the package resolves
// cleanly as a bundle module.
export function apply() {}
