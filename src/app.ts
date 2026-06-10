import express from "express";
import cors from "cors";
import scanRoutes from "./routes/scan.route";
import { getDefaultRepositoryPath } from "./config/repository.config";

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  const defaultRepositoryPath = getDefaultRepositoryPath();

  res.type("html").send(`
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Security Engine</title>
        <style>
          :root {
            color-scheme: dark;
            --bg: #0b1020;
            --panel: #121a31;
            --panel-2: #0f1730;
            --border: #24304f;
            --text: #e7ecff;
            --muted: #aab5df;
            --accent: #7dd3fc;
            --accent-2: #34d399;
          }
          body {
            margin: 0;
            min-height: 100vh;
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: radial-gradient(circle at top, #162041 0%, var(--bg) 55%);
            color: var(--text);
            display: grid;
            place-items: center;
          }
          .card {
            width: min(920px, calc(100vw - 32px));
            background: linear-gradient(180deg, rgba(18, 26, 49, 0.95), rgba(10, 16, 32, 0.98));
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 28px;
            box-shadow: 0 24px 80px rgba(0, 0, 0, 0.45);
          }
          h1 { margin: 0 0 8px; font-size: 28px; }
          p { margin: 0 0 20px; color: var(--muted); line-height: 1.5; }
          label { display: block; margin: 18px 0 8px; font-weight: 600; }
          input {
            width: 100%;
            box-sizing: border-box;
            padding: 14px 16px;
            border-radius: 12px;
            border: 1px solid var(--border);
            background: var(--panel-2);
            color: var(--text);
            font-size: 15px;
          }
          .row {
            display: flex;
            gap: 12px;
            margin-top: 14px;
            flex-wrap: wrap;
          }
          button {
            appearance: none;
            border: 0;
            border-radius: 12px;
            padding: 12px 18px;
            font-weight: 700;
            cursor: pointer;
          }
          .primary { background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: #08111f; }
          .secondary { background: transparent; color: var(--text); border: 1px solid var(--border); }
          pre {
            margin-top: 20px;
            padding: 16px;
            background: #081021;
            border: 1px solid var(--border);
            border-radius: 14px;
            overflow: auto;
            min-height: 180px;
          }
          .hint { margin-top: 10px; font-size: 13px; color: var(--muted); }
          code { color: var(--accent); }
        </style>
      </head>
      <body>
        <main class="card">
          <h1>Security Engine</h1>
          <p>Paste a repository path, then run a scan. You can also send the path through <code>REPOSITORY_PATH</code>, <code>POST /scan</code>, or <code>GET /scan?repositoryPath=...</code>.</p>

          <label for="repositoryPath">Repository path</label>
          <input id="repositoryPath" type="text" placeholder="/Users/you/projects/repo" value="${defaultRepositoryPath.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}" />

          <div class="row">
            <button class="primary" id="scanButton">Run Scan</button>
            <button class="secondary" id="useCurrent">Use Env Default</button>
          </div>

          <div class="hint">If you leave the field empty, the server will use <code>REPOSITORY_PATH</code> when it is set.</div>
          <pre id="output">Waiting for input...</pre>
        </main>

        <script>
          const repositoryPathInput = document.getElementById('repositoryPath');
          const output = document.getElementById('output');
          const scanButton = document.getElementById('scanButton');
          const useCurrent = document.getElementById('useCurrent');

          useCurrent.addEventListener('click', () => {
            repositoryPathInput.value = ${JSON.stringify(defaultRepositoryPath)};
          });

          scanButton.addEventListener('click', async () => {
            const repositoryPath = repositoryPathInput.value.trim();

            if (!repositoryPath) {
              output.textContent = 'Enter a repository path or set REPOSITORY_PATH.';
              return;
            }

            output.textContent = 'Scanning...';

            try {
              const response = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ repositoryPath }),
              });

              const json = await response.json();
              output.textContent = JSON.stringify(json, null, 2);
            } catch (error) {
              output.textContent = String(error);
            }
          });
        </script>
      </body>
    </html>
  `);
});

app.use("/scan", scanRoutes);

const PORT = 3001;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});