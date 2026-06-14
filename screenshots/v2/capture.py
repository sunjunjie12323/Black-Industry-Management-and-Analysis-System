from playwright.sync_api import sync_playwright
import json

SCREENSHOT_DIR = r"c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent\screenshots\v2"
BASE_URL = "http://localhost:3000"
VIEWPORT = {"width": 1400, "height": 900}
WAIT_MS = 3000

console_errors = []

def handle_console(msg):
    if msg.type in ("error", "warning"):
        console_errors.append({
            "type": msg.type,
            "text": msg.text,
            "location": msg.location.get("url", "")
        })

pages_to_capture = [
    ("/", "dashboard.png", "首页"),
    ("/intelligence", "intelligence.png", "情报中心"),
    ("/analysis", "analysis.png", "深度分析"),
    ("/model-workshop", "model-workshop.png", "模型工坊"),
    ("/ai-apps", "ai-apps.png", "AI应用"),
    ("/system", "system.png", "系统管理"),
]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport=VIEWPORT)
    page = context.new_page()
    page.on("console", handle_console)

    print("=== Step 1: 登录 ===")
    page.goto(f"{BASE_URL}/login", wait_until="networkidle")
    page.wait_for_timeout(WAIT_MS)

    page_content = page.content()
    print(f"Login page title: {page.title()}")
    print(f"Login page URL: {page.url}")

    username_selectors = [
        'input[type="text"]',
        'input[placeholder*="用户"]',
        'input[placeholder*="账号"]',
        'input[placeholder*="username"]',
        'input[name="username"]',
        'input[id="username"]',
        'input[id="userName"]',
    ]
    password_selectors = [
        'input[type="password"]',
        'input[placeholder*="密码"]',
        'input[placeholder*="password"]',
        'input[name="password"]',
        'input[id="password"]',
    ]

    username_input = None
    for sel in username_selectors:
        loc = page.locator(sel)
        if loc.count() > 0:
            username_input = sel
            print(f"Found username input with selector: {sel}")
            break

    password_input = None
    for sel in password_selectors:
        loc = page.locator(sel)
        if loc.count() > 0:
            password_input = sel
            print(f"Found password input with selector: {sel}")
            break

    if username_input and password_input:
        page.locator(username_input).fill("admin")
        page.locator(password_input).fill("Admin@2024")

        submit_selectors = [
            'button[type="submit"]',
            'button:has-text("登录")',
            'button:has-text("登 录")',
            'button:has-text("Login")',
            'button:has-text("Sign")',
            'input[type="submit"]',
        ]
        submitted = False
        for sel in submit_selectors:
            loc = page.locator(sel)
            if loc.count() > 0:
                loc.click()
                submitted = True
                print(f"Clicked submit with selector: {sel}")
                break

        if not submitted:
            page.keyboard.press("Enter")
            print("Pressed Enter to submit")

        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(WAIT_MS)
        print(f"After login URL: {page.url}")
    else:
        print("WARNING: Could not find login form inputs!")

    print("\n=== Step 2: 截图各页面 ===")
    for path, filename, desc in pages_to_capture:
        print(f"Navigating to {path} ({desc})...")
        page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
        page.wait_for_timeout(WAIT_MS)
        screenshot_path = f"{SCREENSHOT_DIR}\\{filename}"
        page.screenshot(path=screenshot_path, full_page=False)
        print(f"  Saved: {screenshot_path}")

    print("\n=== Step 3: 登出并截图登录页 ===")
    logout_selectors = [
        'button:has-text("退出")',
        'button:has-text("登出")',
        'button:has-text("注销")',
        'a:has-text("退出")',
        'a:has-text("登出")',
        'a:has-text("注销")',
        'text=退出登录',
        'text=Logout',
        'text=Sign out',
    ]

    logout_done = False
    for sel in logout_selectors:
        loc = page.locator(sel)
        if loc.count() > 0:
            loc.first.click()
            logout_done = True
            print(f"Clicked logout with selector: {sel}")
            break

    if not logout_done:
        page.goto(f"{BASE_URL}/login", wait_until="networkidle")
        print("Navigated directly to login page")

        try:
            page.context.clear_cookies()
        except:
            pass

        try:
            page.evaluate("localStorage.clear(); sessionStorage.clear();")
        except:
            pass

        page.reload(wait_until="networkidle")

    page.wait_for_timeout(WAIT_MS)
    login_screenshot = f"{SCREENSHOT_DIR}\\login.png"
    page.screenshot(path=login_screenshot, full_page=False)
    print(f"  Saved: {login_screenshot}")

    browser.close()

print("\n=== 截图完成 ===")
print(f"截图目录: {SCREENSHOT_DIR}")
print(f"\n控制台错误/警告 ({len(console_errors)} 条):")
if console_errors:
    for err in console_errors[:20]:
        print(f"  [{err['type'].upper()}] {err['text'][:120]}")
else:
    print("  无控制台错误")

print("\n所有截图文件:")
import os
for f in sorted(os.listdir(SCREENSHOT_DIR)):
    if f.endswith('.png'):
        fpath = os.path.join(SCREENSHOT_DIR, f)
        size = os.path.getsize(fpath)
        print(f"  {f} ({size:,} bytes)")
