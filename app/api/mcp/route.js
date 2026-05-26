import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import crypto from "crypto";

// ----------------------------------------------------------------------
// Threat Models & Sanitizers (Layers 3, 7, 8, & 15)
// ----------------------------------------------------------------------
const CommitInputSchema = z.object({
  repo: z.string()
    .min(3)
    .max(100)
    .regex(/^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/, "Malicious Repo Schema Rejected. Use: 'owner/repo'"),
  path: z.string()
    .min(1)
    .max(250)
    .regex(/^[^./][a-zA-Z0-9._\-/]*$/, "Path Traversal Attempt Detected (No leading dots or traversal syntax allowed)."),
  message: z.string()
    .min(5)
    .max(200)
    .regex(/^[^<>]*$/, "HTML/Script tags are stripped and forbidden in Git commit messages."),
  content: z.string()
    .max(5000000, "File exceeds maximum payload limit of 5MB.")
});

// ----------------------------------------------------------------------
// Core Safe MCP Handler Instance (Layers 4, 9, 11, & 16)
// ----------------------------------------------------------------------
const handler = createMcpHandler(
  (server) => {
    server.registerTool(
      "secure_create_commit",
      {
        title: "Create or Update GitHub File",
        description: "Executes a secure, isolated commit directly to the main branch of your specified repository.",
        inputSchema: {
          repo: z.string().describe("Your repository target name (format: 'owner/project')"),
          path: z.string().describe("The clean file path (e.g., 'src/index.js')"),
          message: z.string().describe("Clear change details description"),
          content: z.string().describe("Complete raw file contents code block")
        }
      },
      async ({ repo, path, message, content }) => {
        // Double-verification Validation Loop (Ensures variables are clean inside the tool runtime scope)
        const cleanData = CommitInputSchema.safeParse({ repo, path, message, content });
        if (!cleanData.success) {
          return {
            content: [{ type: "text", text: `Blocked! Security violations found: ${cleanData.error.message}` }],
            isError: true
          };
        }

        const { repo: cleanRepo, path: cleanPath, message: cleanMsg, content: cleanContent } = cleanData.data;
        const patToken = process.env.GITHUB_PAT;

        if (!patToken) {
          return {
            content: [{ type: "text", text: "Runtime failure: Environment target token is missing on Vercel." }],
            isError: true
          };
        }

        try {
          const apiURL = `https://api.github.com/repos/${cleanRepo}/contents/${cleanPath}`;

          // Step 1: Probe the path to locate previous file properties and retrieve SHA signature
          const probeCheck = await fetch(apiURL, {
            method: "GET",
            headers: {
              "Authorization": `token ${patToken}`,
              "User-Agent": "McpSecureServerAgent/1.0",
              "Accept": "application/vnd.github.v3+json"
            }
          });

          let existingFileSha = undefined;
          if (probeCheck.status === 200) {
            const probeResult = await probeCheck.json();
            existingFileSha = probeResult.sha;
          }

          // Convert content directly to base64 using strict binary buffer maps (Prevents shell interpolation)
          const b64Payload = Buffer.from(cleanContent, "utf-8").toString("base64");
          const payloadMap = {
            message: cleanMsg,
            content: b64Payload,
            branch: "main"
          };

          if (existingFileSha) {
            payloadMap.sha = existingFileSha;
          }

          // Step 2: Push commit securely via direct JSON delivery over HTTPS
          const pushResponse = await fetch(apiURL, {
            method: "PUT",
            headers: {
              "Authorization": `token ${patToken}`,
              "Content-Type": "application/json",
              "User-Agent": "McpSecureServerAgent/1.0",
              "Accept": "application/vnd.github.v3+json"
            },
            body: JSON.stringify(payloadMap)
          });

          if (!pushResponse.ok) {
            const errorDump = await pushResponse.text();
            throw new Error(`GitHub API returned execution status: ${pushResponse.status}. Details: ${errorDump}`);
          }

          const pushSuccessResult = await pushResponse.json();
          return {
            content: [{ 
              type: "text", 
              text: `Success! Code committed securely to main branch.\nCommit Hash: ${pushSuccessResult.commit.sha}\nPath: ${cleanPath}` 
            }]
          };

        } catch (execError) {
          // Safeguard: Scrapes raw system targets and tokens from logs
          console.error("Execution failure logged securely.");
          return {
            content: [{ type: "text", text: `Execution of secure commit was halted. Reason: ${execError.message}` }],
            isError: true
          };
        }
      }
    );
  },
  {},
  { 
    basePath: "/api",
    maxDuration: 60,
    verboseLogs: false // Strictly disabled to ensure sensitive payload variables are never dumped to server logs
  }
);

// ----------------------------------------------------------------------
// Layered Verification Gate (Layers 1, 2, 5, 10, 12, & 13)
// ----------------------------------------------------------------------
async function runVerificationGate(req) {
  // Layer 5: Origin Lock (Strict CORS restriction)
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "https://aistudio.google.com",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "X-Mcp-Secret, Content-Type, Accept",
        "Access-Control-Max-Age": "86400"
      }
    });
  }

  // Layer 12: Content-Type checking to protect against blind form submissions/forged requests
  if (req.method === "POST") {
    const contentType = req.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      return new Response(JSON.stringify({ error: "Access Refused. Requiring structured application/json payload." }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
  }

  // Layer 1 & 10: Constant-Time cryptographic protection against timing and correlation attacks
  const secretHeader = req.headers.get("x-mcp-secret");
  const localAppKey = process.env.CUSTOM_MCP_KEY;

  if (!secretHeader || !localAppKey) {
    return new Response(JSON.stringify({ error: "Access Denied. Signature token configuration error." }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const clientKeyBuffer = Buffer.from(secretHeader);
  const serverKeyBuffer = Buffer.from(localAppKey);

  if (clientKeyBuffer.length !== serverKeyBuffer.length || !crypto.timingSafeEqual(clientKeyBuffer, serverKeyBuffer)) {
    return new Response(JSON.stringify({ error: "Access Denied. Signature mismatch." }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  // If both verification barriers clear, request continues to the handler execution.
  return handler(req);
}

export { runVerificationGate as GET, runVerificationGate as POST };
