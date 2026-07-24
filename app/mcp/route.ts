import { createMcpHandler } from "mcp-handler";
import { z } from "zod";

const toolDescription =
  "Run WPScan to analyze WordPress websites. On Vercel, returns a safe command to run locally because CLI processes cannot execute in serverless functions.";

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

const handler = createMcpHandler(
  async (server) => {
    server.tool(
      "do-wpscan",
      toolDescription,
      {
        url: z.string().url().describe(
          "The target WordPress website URL to scan. Must be a valid URL starting with http:// or https://",
        ),
        detection_mode: z
          .enum(["mixed", "passive", "aggressive"])
          .optional()
          .describe(
            "Scan detection mode: 'mixed' (default) combines passive and aggressive, 'passive' for non-intrusive scanning, 'aggressive' for thorough but potentially detectable scanning",
          ),
        random_user_agent: z
          .boolean()
          .optional()
          .describe("Enable random user agent rotation for each request to avoid detection"),
        max_threads: z
          .number()
          .optional()
          .describe(
            "Maximum number of concurrent scanning threads. Default is 5. Higher values increase speed but may trigger rate limiting",
          ),
        disable_tls_checks: z
          .boolean()
          .optional()
          .describe(
            "Disable SSL/TLS certificate verification and allow TLS 1.0+ connections. Requires cURL 7.66 or higher for TLS downgrade support",
          ),
        proxy: z
          .string()
          .optional()
          .describe(
            "Proxy server to route requests through. Format: protocol://IP:port (e.g., http://127.0.0.1:8080). Supported protocols depend on installed cURL version",
          ),
        cookies: z
          .string()
          .optional()
          .describe(
            "Custom cookies to include in requests. Format: name1=value1; name2=value2. Useful for authenticated scanning",
          ),
        force: z
          .boolean()
          .optional()
          .describe(
            "Skip WordPress detection and 403 response checks. Use when you're certain the target is WordPress",
          ),
        enumerate: z
          .array(z.enum(["vp", "ap", "p", "vt", "at", "t", "tt", "cb", "dbe"]))
          .describe(
            "WordPress enumeration options: vp vulnerable plugins, ap all plugins, p popular plugins, vt vulnerable themes, at all themes, t popular themes, tt Timthumb vulnerabilities, cb configuration backups, and dbe database exports. Only one plugin mode and one theme mode should be used.",
          ),
      },
      async ({
        url,
        detection_mode,
        random_user_agent,
        max_threads,
        disable_tls_checks,
        proxy,
        cookies,
        force,
        enumerate,
      }) => {
        const args: string[] = ["-u", shellQuote(url)];

        if (detection_mode) args.push("--detection-mode", detection_mode);
        if (random_user_agent) args.push("--random-user-agent");
        if (max_threads !== undefined) args.push("-t", String(max_threads));
        if (disable_tls_checks) args.push("--disable-tls-checks");
        if (proxy) args.push("--proxy", shellQuote(proxy));
        if (cookies) args.push("--cookie-string", shellQuote(cookies));
        if (force) args.push("--force");
        if (enumerate.length > 0) args.push("-e", enumerate.join(","));

        const command = `wpscan ${args.join(" ")}`;

        return {
          content: [
            {
              type: "text" as const,
              text:
                "WPScan is a local CLI and cannot run inside a Vercel serverless function. " +
                "Only scan systems you own or are explicitly authorized to test. Run this command on a machine with WPScan installed:\n\n" +
                command,
            },
          ],
        };
      },
    );
  },
  {
    capabilities: {
      tools: {
        "do-wpscan": {
          description: toolDescription,
        },
      },
    },
  },
  {
    basePath: "",
    verboseLogs: true,
    maxDuration: 60,
    disableSse: true,
  },
);

export { handler as GET, handler as POST, handler as DELETE };
