from playwright.sync_api import sync_playwright
import os

SCREENSHOT_DIR = r"c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent\screenshots"
BASE_URL = "http://localhost:3000"
VIEWPORT_WIDTH = 1400
VIEWPORT_HEIGHT = 900
WAIT_MS = 2000

PAGES = [
    ("/", "dashboard.png"),
    ("/intelligence", "intelligence_intel.png"),
    ("/intelligence?tab=alerts", "intelligence_alerts.png"),
    ("/intelligence?tab=entities", "intelligence_entities.png"),
    ("/intelligence?tab=pirs", "intelligence_pirs.png"),
    ("/intelligence?tab=reports", "intelligence_reports.png"),
    ("/analysis", "analysis_graph.png"),
    ("/analysis?tab=pipeline", "analysis_pipeline.png"),
    ("/model-workshop", "model_prompt.png"),
    ("/model-workshop?tab=pipeline", "model_pipeline.png"),
    ("/model-workshop?tab=finetune", "model_finetune.png"),
    ("/ai-apps", "ai_qa.png"),
    ("/ai-apps?tab=translate", "ai_translate.png"),
    ("/ai-apps?tab=content", "ai_content.png"),
    ("/ai-apps?tab=analytics", "ai_analytics.png"),
    ("/system", "system_deploy.png"),
    ("/system?tab=settings", "system_settings.png"),
]

def take_screenshot(page, path, filename):
    full_path = os.path.join(SCREENSHOT_DIR, filename)
    page.goto(f"{BASE_URL}{path}", wait_until="networkidle", timeout=30000)
    page.wait_for_timeout(WAIT_MS)
    page.screenshot(path=full_path, full_page=False)
    print(f"[OK] {filename} <- {path}")

def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
            device_scale_factor=1,
        )
        page = context.new_page()

        # Login
        print("[INFO] Navigating to login page...")
        page.goto(f"{BASE_URL}/login", wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(1000)

        # Try common login form selectors
        username_selectors = [
            'input[type="text"]',
            'input[name="username"]',
            'input[placeholder*="用户"]',
            'input[placeholder*="账号"]',
            'input[id="username"]',
        ]
        password_selectors = [
            'input[type="password"]',
            'input[name="password"]',
            'input[placeholder*="密码"]',
            'input[id="password"]',
        ]

        username_input = None
        for sel in username_selectors:
            loc = page.locator(sel)
            if loc.count() > 0:
                username_input = loc.first
                break

        password_input = None
        for sel in password_selectors:
            loc = page.locator(sel)
            if loc.count() > 0:
                password_input = loc.first
                break

        if username_input and password_input:
            print("[INFO] Found login form, filling credentials...")
            username_input.fill("admin")
            password_input.fill("Admin@2024")

            # Find and click login button
            login_selectors = [
                'button[type="submit"]',
                'button:has-text("登录")',
                'button:has-text("Login")',
                'button:has-text("登 录")',
            ]
            for sel in login_selectors:
                loc = page.locator(sel)
                if loc.count() > 0:
                    loc.first.click()
                    print(f"[INFO] Clicked login button: {sel}")
                    break

            page.wait_for_load_state("networkidle", timeout=15000)
            page.wait_for_timeout(2000)
            print(f"[INFO] After login, current URL: {page.url}")
        else:
            print("[WARN] Could not find login form elements, attempting direct navigation...")

        # Take screenshots of all pages
        for path, filename in PAGES:
            try:
                take_screenshot(page, path, filename)
            except Exception as e:
                print(f"[ERROR] Failed to screenshot {filename}: {e}")

        # Logout and take login page screenshot
        print("[INFO] Attempting logout...")
        try:
            # Try to find and click logout button
            logout_selectors = [
                'button:has-text("退出")',
                'button:has-text("登出")',
                'a:has-text("退出")',
                'a:has-text("登出")',
                'button:has-text("Logout")',
                '[data-testid="logout"]',
            ]
            logged_out = False
            for sel in logout_selectors:
                loc = page.locator(sel)
                if loc.count() > 0:
                    loc.first.click()
                    page.wait_for_timeout(1000)
                    logged_out = True
                    print(f"[INFO] Clicked logout: {sel}")
                    break

            if not logged_out:
                # Try clearing cookies/localStorage to force logout
                page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
                page.goto(f"{BASE_URL}/login", wait_until="networkidle", timeout=15000)
                page.wait_for_timeout(1000)
                print("[INFO] Cleared storage and navigated to login page")

            # Navigate to login page to be sure
            page.goto(f"{BASE_URL}/login", wait_until="networkidle", timeout=15000)
            page.wait_for_timeout(WAIT_MS)
            login_path = os.path.join(SCREENSHOT_DIR, "login.png")
            page.screenshot(path=login_path, full_page=False)
            print(f"[OK] login.png <- /login")
        except Exception as e:
            print(f"[ERROR] Failed to screenshot login.png: {e}")

        browser.close()

    print("\n[DONE] All screenshots completed!")
    print(f"[INFO] Screenshots saved to: {SCREENSHOT_DIR}")

if __name__ == "__main__":
    main()
