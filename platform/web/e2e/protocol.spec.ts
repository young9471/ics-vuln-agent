import { expect, test } from "@playwright/test";

test.describe("protocol case workflow", () => {
  test.skip(!process.env.E2E_BASE_URL, "set E2E_BASE_URL to run browser E2E");
  test.skip(!process.env.E2E_CASE_ID, "set E2E_CASE_ID to a seeded case");

  test("case detail exposes run statistics and state machine", async ({ page }) => {
    const caseId = process.env.E2E_CASE_ID!;
    await page.goto(`/protocol/cases/detail?id=${caseId}`);
    await expect(page.getByText("运行统计")).toBeVisible();
    await page.getByRole("tab", { name: "会话状态机" }).click();
    await expect(page.getByText(/尚无会话状态机记录|状态迁移/).first()).toBeVisible();
    await page.getByRole("tab", { name: "报告" }).click();
    await expect(page.getByText("交付文档")).toBeVisible();
    const exportButton = page.getByRole("button", { name: "导出 zip" });
    if (await exportButton.isVisible().catch(() => false)) {
      const waitDownload = page.waitForEvent("download");
      await exportButton.click();
      const download = await waitDownload;
      expect(download.suggestedFilename()).toMatch(/reports\.zip$/);
    }
  });

  test("P4 toolchain settings are visible", async ({ page }) => {
    const username = process.env.E2E_USERNAME;
    const password = process.env.E2E_PASSWORD;
    test.skip(!username || !password, "set E2E_USERNAME/E2E_PASSWORD");
    await page.goto("/login");
    await page.getByLabel("用户名").fill(username!);
    await page.getByLabel("密码").fill(password!);
    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: "登录" }).click();
    await page.goto("/system/tools");
    await expect(page.getByRole("heading", { name: "工具链" })).toBeVisible();
    await expect(page.getByText("可选分析后端")).toBeVisible();
  });

  test("case creation form is usable", async ({ page }) => {
    test.skip(process.env.E2E_CREATE_CASE !== "1", "set E2E_CREATE_CASE=1 to create a case");
    await page.goto("/protocol/cases");
    await page.getByRole("button", { name: "新建案例" }).click();
    await page.getByLabel("案例名称").fill(`E2E case ${Date.now()}`);
    await page.getByRole("button", { name: "创建" }).click();
    await expect(page.getByRole("dialog")).toBeHidden();
  });
});
