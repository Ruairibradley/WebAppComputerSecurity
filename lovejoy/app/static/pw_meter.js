(function () {
    /* Password strength meter and match indicator */
  function ready(fn) {
    /* Run fn() when DOM is ready */
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn, { once: true });
    } else {
      fn();
    }
  }

  function assessPw(pw) {
    //5 satisfied criteria = max strength for password.
    let s = 0;
    if ((pw || "").length >= 12) s++;
    if (/[A-Z]/.test(pw)) s++;
    if (/[a-z]/.test(pw)) s++;
    if (/\d/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    return s;
  }

  function hookPwMeter(inputId, barId, listId) {
    /* Hook up password strength meter */
    const input = document.getElementById(inputId);
    if (!input) return;
    const bar = document.getElementById(barId);
    const list = document.getElementById(listId);
    const seg = bar ? bar.querySelector("div") : null;

    function update() {
      const v = input.value || "";
      const s = assessPw(v);
      if (seg) {
        const pct = (s / 5) * 100;
        seg.style.width = pct + "%";
        seg.style.background = s < 3 ? "#fca5a5" : (s < 5 ? "#fcd34d" : "#86efac");
      }
      if (list) {
        const rules = [
          ["≥ 12 chars", v.length >= 12],
          ["uppercase", /[A-Z]/.test(v)],
          ["lowercase", /[a-z]/.test(v)],
          ["digit", /\d/.test(v)],
          ["special", /[^A-Za-z0-9]/.test(v)] 
        ]; /* 5 rules for password strength */ 
        list.innerHTML = rules
            .map(([t, ok]) => `<li>${ok ? "✓" : "✗"} ${t}</li>`)
            .join("");
      }
    }

    input.addEventListener("input", update);
    update(); 
  }

  function hookPwMatch(pwId, confirmId, outputId) {
    /* Hook up password match indicator */
    const pw = document.getElementById(pwId);
    const cf = document.getElementById(confirmId);
    const out = document.getElementById(outputId);
    if (!pw || !cf || !out) return;

    function render() {
      const a = pw.value || "";
      const b = cf.value || "";
      if (!b) { out.textContent = ""; return; }
      if (a === b) {
        out.textContent = "Passwords match";
        out.style.color = "#166534";
      } else {
        out.textContent = "Passwords do not match";
        out.style.color = "#b91c1c";
      }
    }

    pw.addEventListener("input", render);
    cf.addEventListener("input", render);
    render();
  }

  ready(function () {
    // Registration
    hookPwMeter("pw_reg", "meter_reg", "rules_reg");
    hookPwMatch("pw_reg", "pw_confirm_reg", "match_reg");
    // Reset
    hookPwMeter("pw_reset", "meter_reset", "rules_reset");
    hookPwMatch("pw_reset", "pw_confirm_reset", "match_reset");
    // Minimal diagnostic in DevTools Console confirms load
    console.log("[pw_meter] hooks initialised");
  });
})(); /* password strength meter not showing dont know why - maybe come back */

