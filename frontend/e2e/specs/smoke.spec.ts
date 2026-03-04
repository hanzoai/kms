import { test, expect } from "@playwright/test";

test.describe("KMS Frontend Smoke Tests", () => {
  test("login page loads", async ({ page }) => {
    await page.goto("/login");
    await expect(page).toHaveTitle(/KMS|Hanzo|Login/i);
  });

  test("login form renders", async ({ page }) => {
    await page.goto("/login");
    // Should show email input
    const emailInput = page.locator('input[type="email"]');
    await expect(emailInput).toBeVisible();
  });

  test("Sign in with Hanzo button is visible", async ({ page }) => {
    await page.goto("/login");
    const hanzoButton = page.getByRole("button", {
      name: /sign in with hanzo/i,
    });
    await expect(hanzoButton).toBeVisible();
  });

  test("signup page loads", async ({ page }) => {
    await page.goto("/signup");
    // Should redirect to login or show signup form
    await expect(page.locator("body")).not.toBeEmpty();
  });

  test("no console errors on login page", async ({ page }) => {
    const errors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") errors.push(msg.text());
    });
    await page.goto("/login");
    await page.waitForLoadState("networkidle");
    // Filter out expected errors (e.g., failed API calls when no backend)
    const unexpected = errors.filter(
      (e) => !e.includes("Failed to fetch") && !e.includes("NetworkError")
    );
    expect(unexpected).toHaveLength(0);
  });

  test("white-label brand name appears", async ({ page }) => {
    await page.goto("/login");
    // Should show brand name (Hanzo KMS, Lux KMS, etc.)
    const heading = page.locator("h1");
    await expect(heading).toContainText(/KMS/i);
  });
});
