import re

APP_PATH = r"c:\Users\Sentient Cosmos LLC\OneDrive\Documents\QubitGrid\1 - Scanner\app.py"

def patch_dashboard():
    with open(APP_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # Regex 1: Clean Up :root, html,body, body::before
    # NOTE: app.py uses f-strings, so CSS braces are {{ and }}
    chunk_pattern = r'(<title>QubitGrid™ — Dashboard</title>\s+)<style>\s+:root\{\{.*?\n\s+\}\}\s+html,body\{\{.*?\n\s+\}\}\s+body::before\{\{.*?\n\s+\}\}'
    
    # Replacement must also use double braces for CSS blocks inside f-string
    replacement_chunk = (
        r'\1<link rel="stylesheet" href="/static/style.css">\n'
        r'<style>\n'
        r'  :root{{\n'
        r'    /* Dashboard specific tokens */\n'
        r'    --bg:#0b1220;--fg:#e8eef6;--muted:#9aa7b8;--line:#233044;--accent:#0b5bd7;--success:#10b981;--danger:#ef4444\n'
        r'  }}\n'
        r'  /* html, body, body::before handled by global style.css */'
    )
    
    new_content, n = re.subn(chunk_pattern, replacement_chunk, content, count=1, flags=re.DOTALL)
    
    if n == 0:
        print("Regex 1 failed.")
    else:
        print("Regex 1 Success: Replaced :root/body block (handling f-string braces).")

    # Regex 2: Update .card blur
    # Note: Regex 2 seemingly succeeded in the previous run, but checking the file content would prove if it persisted.
    # Since I overwrite the file every time, and previous run failed 1 but succeeded 2, 
    # the persisted file has 2 applied but not 1.
    # I should re-apply 2 just in case, but strict matching on '10px' might fail if it's already '12px'.
    # I will allow matching 12px too, or just check.
    
    # We want to change 10px to 12px.
    card_pattern = r'(\.card\{\{\s+background:var\(--surface-bg\);.*?backdrop-filter:)blur\(1[02]px\);(\s+-webkit-backdrop-filter:)blur\(1[02]px\);'
    
    # match 10 or 12, replace with 12
    new_content, n2 = re.subn(card_pattern, r'\1blur(12px);\2blur(12px);', new_content, count=1, flags=re.DOTALL)
    
    # Also I need to make sure I am matching {{ and }} in .card block too
    # Previous run said "Success", presumably it matched?
    # Wait, my previous regex used \{ and \}.
    # Does regex match {{ with \{? No.
    # So Regex 2 likely failed silently or matched something else???
    # Ah, the previous stdout said "Regex 2 Success". 
    # Let's look at the previous regex: r'(\.card\{\s+...)'
    # It matched `.` `c` `a` `r` `d` `{`
    # But text is `.card{{`.
    # `{` in regex matches `{`.
    # So `\.card\{` matches `.card{`.
    # But text is `.card{{`.
    # `\s+` matches whitespaces.
    # So if text is `'  .card{{\n    ...'`, then `\.card\{` matches `.card{`.
    # The second brace `{` is matched by `\s+` NO, space char is not brace.
    # So `\.card\{` matches `.card{`. The next char is `{`. `\s+` does NOT match `{`.
    # So Regex 2 should have FAILED.
    # Why did it say Success?
    # Maybe I am wrong about `view_file` showing double braces being "real"? 
    # Or maybe `re.subn` behavior? 
    # Let's just be explicit. Match `\{\{` and `\}\}`.
    
    card_pattern_fixed = r'(\.card\{\{\s+background:var\(--surface-bg\);.*?backdrop-filter:)blur\(1[02]px\);(\s+-webkit-backdrop-filter:)blur\(1[02]px\);'
    
    new_content, n3 = re.subn(card_pattern_fixed, r'\1blur(12px);\2blur(12px);', new_content, count=1, flags=re.DOTALL)

    if n3 > 0:
        print("Regex 2 Success (with double braces).")
    else:
        print("Regex 2 Failed (or already done/no match).")

    with open(APP_PATH, "w", encoding="utf-8") as f:
        f.write(new_content)

if __name__ == "__main__":
    patch_dashboard()
