import { expect, test, type Page } from "@playwright/test";

const token = (payload: Record<string, unknown>) =>
  `header.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.signature`;

async function mockApi(page: Page) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;

    if (path === "/api/v1/interfaces") {
      await route.fulfill({ json: { data: [] } });
      return;
    }
    if (path === "/api/v1/auth/ws-ticket") {
      await route.fulfill({ json: { ticket: "browser-test-ticket", expires_in_seconds: 30 } });
      return;
    }
    await route.fulfill({ json: {} });
  });
}

test("a protected page redirects an anonymous visitor to login", async ({ page }) => {
  await page.goto("/");

  await expect(page).toHaveURL(/\/login\/$/);
  await expect(page.getByLabel("Username")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign In" })).toBeVisible();
});

test("invalid credentials show feedback without leaving the login page", async ({ page }) => {
  await page.route("**/api/v1/auth/login", (route) =>
    route.fulfill({ status: 401, json: { error: "bad credentials" } }),
  );
  await page.goto("/login/");

  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("wrong-password");
  await page.getByRole("button", { name: "Sign In" }).click();

  await expect(page.getByText("Invalid username or password")).toBeVisible();
  await expect(page).toHaveURL(/\/login\/$/);
  await expect(page.evaluate(() => localStorage.getItem("aifw_token"))).resolves.toBeNull();
});

test("TOTP login stores the session and opens the authenticated shell", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/v1/auth/login", (route) =>
    route.fulfill({ json: { totp_required: true } }),
  );
  await page.route("**/api/v1/auth/totp/login", (route) =>
    route.fulfill({
      json: {
        access_token: token({
          sub: "user-1",
          username: "admin",
          role: "admin",
          exp: Math.floor(Date.now() / 1000) + 300,
        }),
      },
    }),
  );
  await page.goto("/login/");

  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("correct-password");
  await page.getByRole("button", { name: "Sign In" }).click();
  await expect(page.getByText("Enter the 6-digit code")).toBeVisible();

  await page.getByLabel("TOTP Code").fill("123456");
  await page.getByRole("button", { name: "Verify" }).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("button", { name: "Monitoring" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Logout" })).toBeVisible();
  await expect(page.evaluate(() => localStorage.getItem("aifw_token"))).resolves.toBeTruthy();
});

test("an expired session is removed before a protected page renders", async ({ page }) => {
  await page.addInitScript((expiredToken) => {
    localStorage.setItem("aifw_token", expiredToken);
  }, token({ sub: "user-1", exp: Math.floor(Date.now() / 1000) - 60 }));

  await page.goto("/");

  await expect(page).toHaveURL(/\/login\/$/);
  await expect(page.evaluate(() => localStorage.getItem("aifw_token"))).resolves.toBeNull();
});
