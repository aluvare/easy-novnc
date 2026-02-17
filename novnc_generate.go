//go:build ignore

package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	noVNCVersion = "1.6.0"
	noVNCURL     = "https://github.com/novnc/noVNC/archive/refs/tags/v" + noVNCVersion + ".zip"
	noVNCDir     = "novnc"
)

const vncScript = `<script>
try {
	var params = new URLSearchParams(window.location.search);
	var path = params.get("path");
	if (path) {
		fetch(path).then(function(resp) {
			return resp.text();
		}).then(function(txt) {
			if (txt.indexOf("not websocket") === -1) alert(txt);
		});
	}
} catch(ex) {
	console.log(ex);
}
</script>`

// moduleBridge exposes the noVNC UI instance to non-module scripts.
const moduleBridge = `<script type="module">
import UI from "./app/ui.js";
window._noVNC_UI = UI;
</script>`

// typeTextAddon injects a "Type Text" button and overlay into the noVNC UI.
const typeTextAddon = `<script>
(function() {
    "use strict";

    function charToKeysym(ch) {
        var cp = ch.codePointAt(0);
        if (cp === 0x0A) return 0xFF0D;  // newline -> Return
        if (cp === 0x0D) return 0xFF0D;  // CR -> Return
        if (cp === 0x09) return 0xFF09;  // Tab
        if (cp === 0x08) return 0xFF08;  // Backspace
        if (cp === 0x1B) return 0xFF1B;  // Escape
        if (cp >= 0x20 && cp <= 0xFF) return cp;  // Latin-1 direct
        return 0x01000000 | cp;  // Unicode keysym
    }

    function typeText(rfb, text, delayMs) {
        var chars = Array.from(text);
        var i = 0;
        function next() {
            if (i >= chars.length) return;
            var ks = charToKeysym(chars[i]);
            rfb.sendKey(ks);
            i++;
            if (i < chars.length) {
                setTimeout(next, delayMs);
            }
        }
        next();
    }

    function init() {
        var ui = window._noVNC_UI;
        if (!ui) {
            setTimeout(init, 200);
            return;
        }

        // --- Overlay panel ---
        var overlay = document.createElement("div");
        overlay.id = "noVNC_type_text_overlay";
        overlay.style.cssText = "display:none;position:fixed;top:0;left:0;width:100%;height:100%;" +
            "background:rgba(0,0,0,0.5);z-index:10000;align-items:center;justify-content:center;";

        var panel = document.createElement("div");
        panel.style.cssText = "background:#2b2b2b;color:#e0e0e0;border-radius:8px;padding:20px;" +
            "width:90%;max-width:420px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;";

        var title = document.createElement("div");
        title.style.cssText = "display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;";
        title.innerHTML = '<span style="font-size:1.1rem;font-weight:600;">Type Text</span>';

        var closeBtn = document.createElement("button");
        closeBtn.textContent = "\u00D7";
        closeBtn.style.cssText = "background:none;border:none;color:#e0e0e0;font-size:1.5rem;cursor:pointer;padding:0 4px;";
        closeBtn.onclick = function() { overlay.style.display = "none"; };
        title.appendChild(closeBtn);

        var textarea = document.createElement("textarea");
        textarea.placeholder = "Paste or type text here...";
        textarea.style.cssText = "width:100%;height:120px;background:#1a1a1a;color:#e0e0e0;border:1px solid #555;" +
            "border-radius:6px;padding:10px;font-family:monospace;font-size:0.9rem;resize:vertical;box-sizing:border-box;";

        var opts = document.createElement("div");
        opts.style.cssText = "display:flex;align-items:center;gap:12px;margin-top:12px;";

        var delayLabel = document.createElement("label");
        delayLabel.style.cssText = "font-size:0.85rem;white-space:nowrap;";
        delayLabel.textContent = "Delay (ms):";

        var delayInput = document.createElement("input");
        delayInput.type = "number";
        delayInput.value = "50";
        delayInput.min = "0";
        delayInput.max = "2000";
        delayInput.style.cssText = "width:70px;background:#1a1a1a;color:#e0e0e0;border:1px solid #555;" +
            "border-radius:4px;padding:4px 8px;font-size:0.85rem;";

        var sendBtn = document.createElement("button");
        sendBtn.textContent = "Type";
        sendBtn.style.cssText = "margin-left:auto;background:#3b82f6;color:#fff;border:none;border-radius:6px;" +
            "padding:8px 20px;font-size:0.9rem;font-weight:500;cursor:pointer;";
        sendBtn.onmouseenter = function() { sendBtn.style.background = "#2563eb"; };
        sendBtn.onmouseleave = function() { sendBtn.style.background = "#3b82f6"; };
        sendBtn.onclick = function() {
            var rfb = ui.rfb;
            if (!rfb) { alert("Not connected to VNC"); return; }
            var text = textarea.value;
            if (!text) return;
            var delay = parseInt(delayInput.value, 10) || 50;
            overlay.style.display = "none";
            typeText(rfb, text, delay);
        };

        opts.appendChild(delayLabel);
        opts.appendChild(delayInput);
        opts.appendChild(sendBtn);

        panel.appendChild(title);
        panel.appendChild(textarea);
        panel.appendChild(opts);
        overlay.appendChild(panel);
        document.body.appendChild(overlay);

        overlay.addEventListener("click", function(e) {
            if (e.target === overlay) overlay.style.display = "none";
        });

        // --- Control bar button ---
        var controlbar = document.getElementById("noVNC_control_bar");
        if (controlbar) {
            var clipBtn = document.getElementById("noVNC_clipboard_button");
            var btn = document.createElement("button");
            btn.id = "noVNC_type_text_button";
            btn.className = "noVNC_button";
            btn.title = "Type Text";
            btn.style.cssText = "display:flex;align-items:center;justify-content:center;";
            btn.innerHTML = '<img src="app/images/keyboard.svg" alt="Type Text" style="width:24px;height:24px;filter:invert(1);">';
            btn.onclick = function() {
                overlay.style.display = "flex";
                textarea.value = "";
                textarea.focus();
            };
            if (clipBtn && clipBtn.nextSibling) {
                controlbar.insertBefore(btn, clipBtn.nextSibling);
            } else {
                controlbar.appendChild(btn);
            }
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", function() { setTimeout(init, 500); });
    } else {
        setTimeout(init, 500);
    }
})();
</script>`

func main() {
	fmt.Printf("Downloading noVNC v%s...\n", noVNCVersion)

	resp, err := http.Get(noVNCURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading noVNC: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Error downloading noVNC: HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}

	// Remove existing directory
	os.RemoveAll(noVNCDir)

	// Extract ZIP
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading ZIP: %v\n", err)
		os.Exit(1)
	}

	prefix := fmt.Sprintf("noVNC-%s/", noVNCVersion)
	var foundVNC bool

	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, prefix) {
			continue
		}

		relPath := strings.TrimPrefix(f.Name, prefix)
		if relPath == "" {
			continue
		}

		targetPath := filepath.Join(noVNCDir, relPath)

		if f.FileInfo().IsDir() {
			os.MkdirAll(targetPath, 0755)
			continue
		}

		os.MkdirAll(filepath.Dir(targetPath), 0755)

		rc, err := f.Open()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting %s: %v\n", f.Name, err)
			os.Exit(1)
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", f.Name, err)
			os.Exit(1)
		}

		// Inject custom scripts into vnc.html
		if filepath.Base(targetPath) == "vnc.html" {
			foundVNC = true
			data = bytes.ReplaceAll(data, []byte("</head>"), []byte(moduleBridge+"\n</head>"))
			data = bytes.ReplaceAll(data, []byte("</body>"), []byte(vncScript+"\n"+typeTextAddon+"\n</body>"))
		}

		if err := os.WriteFile(targetPath, data, f.Mode()); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", targetPath, err)
			os.Exit(1)
		}
	}

	if !foundVNC {
		fmt.Fprintf(os.Stderr, "Error: vnc.html not found in noVNC archive\n")
		os.Exit(1)
	}

	fmt.Printf("noVNC v%s extracted to %s/\n", noVNCVersion, noVNCDir)
}
