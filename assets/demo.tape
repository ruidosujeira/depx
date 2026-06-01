# depx demo tape — recorded with Charm VHS (https://github.com/charmbracelet/vhs)
#
# Regenerate the GIF from the repo root with:
#   cargo build --release
#   (cd examples/demo-app && npm install)   # only needed once
#   vhs assets/demo.tape
#
# Scenes 1-4 run against examples/demo-app (a tiny npm project); scene 5 runs
# `depx duplicates` against depx's own Cargo.lock.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 20
Set Margin 16
Set BorderRadius 8
Set WindowBar Colorful
Set Theme "Dracula"
Set TypingSpeed 55ms

# --- setup (hidden): put the freshly built binary on PATH, clean prompt ---
Hide
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type 'export PS1="\$ "'
Enter
Type "cd examples/demo-app"
Enter
Type "clear"
Enter
Show

Sleep 800ms

# --- Scene 1: which dependencies are actually used? ---
Type "depx analyze"
Sleep 600ms
Enter
Sleep 4500ms
Type "clear"
Enter
Sleep 400ms

# --- Scene 2: why is this package even here? ---
Type "depx why wrappy"
Sleep 600ms
Enter
Sleep 3500ms
Type "clear"
Enter
Sleep 400ms

# --- Scene 3: real, version-aware vulnerabilities (OSV) ---
Type "depx audit"
Sleep 600ms
Enter
Sleep 5000ms
Type "clear"
Enter
Sleep 400ms

# --- Scene 4: deprecated packages still in use ---
Type "depx deprecated"
Sleep 600ms
Enter
Sleep 5000ms
Type "clear"
Enter
Sleep 400ms

# --- Scene 5: duplicate crates in a Rust project (depx itself) ---
Hide
Type "cd ../.."
Enter
Type "clear"
Enter
Show
Sleep 400ms
Type "depx duplicates"
Sleep 600ms
Enter
Sleep 4500ms
