"use strict";

const http = require("node:http");

const pat = (id, userId = 17) => ({
  id, user_id: userId, name: `PAT ${id}`, active: true,
  expires_at: "2099-01-01", scopes: ["read_api"],
});

async function gitlabPatFixture(t) {
  const fixture = { pats: [], calls: [], respond: null };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    fixture.calls.push(url);
    res.setHeader("Content-Type", "application/json");
    if (url.pathname === "/api/v4/user") {
      res.end(JSON.stringify({ id: 17, username: "pat-owner", is_admin: false }));
      return;
    }
    if (url.pathname !== "/api/v4/personal_access_tokens") {
      res.end("[]");
      return;
    }
    const page = Number(url.searchParams.get("page") || 1);
    const perPage = Number(url.searchParams.get("per_page") || 20);
    const response = fixture.respond?.({ page, perPage, url }) || {
      data: fixture.pats.slice((page - 1) * perPage, page * perPage),
    };
    res.writeHead(response.status || 200, response.headers || {});
    res.end(JSON.stringify(response.data ?? { message: "Fixture page failure" }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  }));
  fixture.baseUrl = `http://127.0.0.1:${server.address().port}`;
  fixture.options = {
    baseUrl: fixture.baseUrl, token: "synthetic-fixture-token",
    include: { tokens: true, keys: false }, filters: { includePATs: true },
  };
  fixture.listings = () => fixture.calls.filter(
    (url) => url.pathname === "/api/v4/personal_access_tokens",
  );
  return fixture;
}

module.exports = { gitlabPatFixture, pat };
