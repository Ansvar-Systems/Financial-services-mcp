const HEADER_DELIMITER = "\r\n\r\n";

function writeFramedMessage(payload) {
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  const header = Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, "utf8");
  process.stdout.write(Buffer.concat([header, body]));
}

async function processRequest(handler, request) {
  if (Array.isArray(request)) {
    const responses = [];
    for (const entry of request) {
      const response = await handler(entry);
      if (response) {
        responses.push(response);
      }
    }
    if (responses.length > 0) {
      writeFramedMessage(responses);
    }
    return;
  }
  const response = await handler(request);
  if (response) {
    writeFramedMessage(response);
  }
}

function parseHeaders(headerText) {
  const headers = {};
  for (const line of headerText.split("\r\n")) {
    if (!line.trim()) {
      continue;
    }
    const [rawName, ...rawValue] = line.split(":");
    if (!rawName || rawValue.length === 0) {
      continue;
    }
    headers[rawName.trim().toLowerCase()] = rawValue.join(":").trim();
  }
  return headers;
}

export function startStdioTransport(handler) {
  let buffer = Buffer.alloc(0);
  process.stdin.on("data", async (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (true) {
      const headerIndex = buffer.indexOf(HEADER_DELIMITER);
      if (headerIndex === -1) {
        return;
      }
      const headerBytes = buffer.slice(0, headerIndex).toString("utf8");
      const headers = parseHeaders(headerBytes);
      const contentLength = Number(headers["content-length"] ?? 0);
      const totalLength = headerIndex + HEADER_DELIMITER.length + contentLength;
      if (!Number.isFinite(contentLength) || contentLength < 0) {
        return;
      }
      if (buffer.length < totalLength) {
        return;
      }
      const jsonText = buffer.slice(headerIndex + HEADER_DELIMITER.length, totalLength).toString("utf8");
      buffer = buffer.slice(totalLength);
      try {
        const request = JSON.parse(jsonText);
        await processRequest(handler, request);
      } catch (error) {
        writeFramedMessage({
          jsonrpc: "2.0",
          id: null,
          error: {
            code: -32700,
            message: "Parse error",
            data: error instanceof Error ? error.message : String(error)
          }
        });
      }
    }
  });
  process.stdin.resume();
}
