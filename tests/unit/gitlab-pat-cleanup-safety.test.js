"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { scanGitLab } = require("../../apps/api/services/gitlabIntegration");
const { gitlabPatFixture, pat } = require("../helpers/gitlab-pat-fixture");

function summary(result, complete) {
  const entry = result.summary.find((item) => item.sourceKind === "gitlab-pat");
  assert.equal(entry.complete, complete);
  assert.equal(entry.truncated, !complete);
  return entry;
}

test("admin PAT scan continues after short pages before reporting complete", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.isAdmin = true;
  fixture.respond = ({ page }) => ({ data: page <= 2 ? [pat(page)] : [] });
  const result = await scanGitLab(fixture.options);
  assert.deepEqual(result.items.map((item) => item.sourceObjectId), ["1", "2"]);
  summary(result, true);
  assert.equal(fixture.listings().length, 3);
});

for (const response of [{ data: { unexpected: true } }, { data: [], headers: { "x-next-page": "2" } }]) {
  test(`admin invalid PAT page blocks cleanup: ${JSON.stringify(response)}`, async (t) => {
    const fixture = await gitlabPatFixture(t);
    fixture.isAdmin = true;
    fixture.respond = () => response;
    summary(await scanGitLab(fixture.options), false);
  });
}

test("admin repeated PAT page preserves earlier items but blocks cleanup", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.isAdmin = true;
  fixture.respond = () => ({ data: [pat(1)] });
  const result = await scanGitLab(fixture.options);
  assert.deepEqual(result.items.map((item) => item.sourceObjectId), ["1"]);
  summary(result, false);
  assert.equal(fixture.listings().length, 2);
});

test("admin item cap blocks cleanup when further PATs may exist", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.isAdmin = true;
  fixture.pats = [pat(1), pat(2)];
  const result = await scanGitLab({ ...fixture.options, maxItems: 1 });
  assert.deepEqual(result.items.map((item) => item.sourceObjectId), ["1"]);
  summary(result, false);
});

for (const count of [0, 1, 21, 100, 101, 200]) {
  test(`non-admin enumerates ${count} PATs with explicit pages and an exhaustion probe`, async (t) => {
    const fixture = await gitlabPatFixture(t);
    fixture.pats = Array.from({ length: count }, (_, i) => pat(i + 1));
    const result = await scanGitLab(fixture.options);
    assert.equal(result.items.length, count);
    assert.ok(result.items.every((item) => item.owner_username === "pat-owner"));
    summary(result, true);
    const calls = fixture.listings();
    assert.equal(calls.length, Math.ceil(count / 100) + 1);
    assert.ok(calls.every((url) => url.searchParams.get("per_page") === "100"));
    assert.deepEqual(calls.map((url) => Number(url.searchParams.get("page"))),
      Array.from({ length: calls.length }, (_, i) => i + 1));
  });
}

test("maxItems one preserves the first PAT without authorizing cleanup of the second", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.pats = [pat(1), pat(2)];
  const result = await scanGitLab({ ...fixture.options, maxItems: 1 });
  assert.deepEqual(result.items.map((item) => item.sourceObjectId), ["1"]);
  summary(result, false);
  assert.equal(fixture.listings().length, 1);
});

for (const count of [1, 100]) {
  test(`exact cap ${count} is complete only after a verified empty page`, async (t) => {
    const fixture = await gitlabPatFixture(t);
    fixture.pats = Array.from({ length: count }, (_, i) => pat(i + 1));
    summary(await scanGitLab({ ...fixture.options, maxItems: count }), true);
    assert.equal(fixture.listings().length, 2);
  });
}

test("an item beyond an exact full-page cap prevents cleanup", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.pats = Array.from({ length: 101 }, (_, i) => pat(i + 1));
  const result = await scanGitLab({ ...fixture.options, maxItems: 100 });
  summary(result, false);
  assert.equal(result.items.length, 100);
  assert.equal(fixture.listings().length, 2);
});

test("a failure after a full page preserves every successful PAT", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.pats = Array.from({ length: 100 }, (_, i) => pat(i + 1));
  fixture.respond = ({ page }) => page === 2 ? { status: 503 } : null;
  const result = await scanGitLab(fixture.options);
  summary(result, false);
  assert.equal(result.items.length, 100);
});

for (const status of [403, 404, 429, 503]) {
  for (const failedPage of [1, 2]) {
    test(`HTTP ${status} on page ${failedPage} preserves prior PATs and blocks cleanup`, async (t) => {
      const fixture = await gitlabPatFixture(t);
      fixture.pats = [pat(1)];
      fixture.respond = ({ page }) => page === failedPage ? { status } : null;
      if (failedPage === 1) {
        await assert.rejects(scanGitLab(fixture.options), { status });
        return;
      }
      const result = await scanGitLab(fixture.options);
      assert.equal(result.items.length, failedPage - 1);
      assert.equal(summary(result, false).status, status);
    });
  }
}

test("short server pages and empty continuation headers do not imply exhaustion", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.respond = ({ page }) => ({
    data: page <= 2 ? [pat(page)] : [],
    headers: { "x-next-page": "" },
  });
  const result = await scanGitLab(fixture.options);
  assert.equal(result.items.length, 2);
  summary(result, true);
  assert.equal(fixture.listings().length, 3);
});

for (const headers of [
  { "x-page": "1" },
  { "x-next-page": "2" },
  { "x-per-page": "20" },
]) {
  test(`inconsistent pagination headers fail closed: ${JSON.stringify(headers)}`, async (t) => {
    const fixture = await gitlabPatFixture(t);
    fixture.respond = ({ page }) => ({ data: [pat(page)], headers });
    const result = await scanGitLab(fixture.options);
    summary(result, false);
    assert.ok(result.items.length > 0);
    assert.ok(fixture.listings().length <= 2);
  });
}

test("a repeated page cannot loop forever or prove completion", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.respond = () => ({ data: [pat(1)] });
  const result = await scanGitLab(fixture.options);
  summary(result, false);
  assert.equal(result.items.length, 1);
  assert.equal(fixture.listings().length, 2);
});

for (const headers of [
  { "x-total-pages": "2" },
  { "x-total": "2" },
  { "x-next-page": "2" },
  { link: '<http://localhost/api/v4/personal_access_tokens?page=2>; rel="next"' },
]) {
  test(`an empty page cannot erase an earlier continuation promise: ${JSON.stringify(headers)}`, async (t) => {
    const fixture = await gitlabPatFixture(t);
    fixture.respond = ({ page }) => page === 1
      ? { data: [pat(1)], headers } : { data: [] };
    const result = await scanGitLab(fixture.options);
    summary(result, false);
    assert.equal(result.items.length, 1);
  });
}

test("standard GitLab headers permit a complete scan beyond the last page", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.respond = ({ page }) => ({
    data: page === 1 ? [pat(1)] : [],
    headers: { "x-page": String(page), "x-per-page": "100",
      "x-next-page": "", "x-total-pages": "1", "x-total": "1" },
  });
  summary(await scanGitLab(fixture.options), true);
});

test("filtered pages are bounded even when the server never exhausts", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.respond = ({ page }) => ({ data: [pat(page, 17), { ...pat(page + 1000), revoked: true }] });
  const result = await scanGitLab({ ...fixture.options, maxItems: 2000 });
  summary(result, false);
  assert.equal(result.items.length, 100);
  assert.equal(fixture.listings().length, 100);
});

for (const response of [
  { data: { unexpected: true } },
  { data: [], headers: { "x-next-page": "2" } },
  { data: [], headers: { "x-total-pages": "2" } },
]) {
  test(`invalid or contradictory empty response blocks cleanup: ${JSON.stringify(response)}`, async (t) => {
    const fixture = await gitlabPatFixture(t);
    fixture.respond = () => response;
    await assert.rejects(scanGitLab(fixture.options), /GitLab PAT/);
  });
}

test("paginated owners still require an exact current-user ID match", async (t) => {
  const fixture = await gitlabPatFixture(t);
  fixture.respond = ({ page }) => ({ data: page === 1 ? [pat(1)] :
    page === 2 ? [pat(2, 18), pat(3, "17")] : [] });
  const result = await scanGitLab(fixture.options);
  assert.deepEqual(result.items.map((item) => item.owner_username), ["pat-owner", null, null]);
  summary(result, true);
});
