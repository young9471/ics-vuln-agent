import { expect, test } from "@playwright/test";

test.describe("authentication", () => {
  test.skip(!process.env.E2E_BASE_URL, "set E2E_BASE_URL to run browser E2E");

  test("login page shows Protocol Agent branding", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByText("Protocol Agent").first()).toBeVisible();
    await expect(page.getByRole("button", { name: "登录" })).toBeVisible();
  });

  test("login reaches the case list", async ({ page }) => {
    const username = process.env.E2E_USERNAME;
    const password = process.env.E2E_PASSWORD;
    test.skip(!username || !password, "set E2E_USERNAME/E2E_PASSWORD");
    await page.goto("/login");
    await page.getByLabel("用户名").fill(username!);
    await page.getByLabel("密码").fill(password!);
    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: "登录" }).click();
    await expect(page).toHaveURL(/\/protocol\/cases/);
    await expect(page.getByRole("heading", { name: "协议案例" })).toBeVisible();
  });
});
