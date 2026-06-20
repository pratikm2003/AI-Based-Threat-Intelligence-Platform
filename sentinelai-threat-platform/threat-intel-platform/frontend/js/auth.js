/**
 * auth.js
 * --------
 * Powers index.html (login) and register.html. Both pages share this
 * one file - it just checks which form is present on the page.
 */

function setAlert(box, message) {
  if (!message) {
    box.classList.add("hidden");
    box.textContent = "";
    return;
  }
  box.classList.remove("hidden");
  box.textContent = message;
}

function wirePasswordToggles() {
  document.querySelectorAll("[data-password-toggle]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const input = document.querySelector(btn.getAttribute("data-password-toggle"));
      if (!input) return;
      const isPassword = input.type === "password";
      input.type = isPassword ? "text" : "password";
      btn.innerHTML = isPassword ? EYE_OFF_ICON : EYE_ICON;
    });
  });
}

const EYE_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>`;
const EYE_OFF_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18"/><path d="M10.6 10.6a2 2 0 0 0 2.8 2.8"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 1 11s4 7 11 7a9.77 9.77 0 0 0 5.39-1.61"/></svg>`;

async function redirectIfLoggedIn() {
  try {
    await API.get("/api/auth/me");
    window.location.href = "dashboard.html";
  } catch (err) {
    /* not logged in - stay on this page, which is what we want */
  }
}

function initLoginForm() {
  const form = document.getElementById("loginForm");
  if (!form) return;

  const alertBox = document.getElementById("authAlert");
  const submitBtn = document.getElementById("loginSubmit");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    setAlert(alertBox, "");

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    if (!username || !password) {
      setAlert(alertBox, "Please enter both your username and password.");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "Signing in…";
    try {
      await API.post("/api/auth/login", { username, password });
      window.location.href = "dashboard.html";
    } catch (err) {
      setAlert(alertBox, err.message || "Login failed.");
      submitBtn.disabled = false;
      submitBtn.textContent = "Sign in";
    }
  });

  document.querySelectorAll("[data-fill-demo]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.getElementById("username").value = btn.getAttribute("data-fill-demo");
      document.getElementById("password").value = btn.getAttribute("data-fill-password");
    });
  });
}

function initRegisterForm() {
  const form = document.getElementById("registerForm");
  if (!form) return;

  const alertBox = document.getElementById("authAlert");
  const successBox = document.getElementById("authSuccess");
  const submitBtn = document.getElementById("registerSubmit");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    setAlert(alertBox, "");
    successBox.classList.add("hidden");

    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;

    if (!username || !email || !password) {
      setAlert(alertBox, "All fields are required.");
      return;
    }
    if (password !== confirmPassword) {
      setAlert(alertBox, "Passwords do not match.");
      return;
    }
    if (password.length < 6) {
      setAlert(alertBox, "Password must be at least 6 characters long.");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "Creating account…";
    try {
      await API.post("/api/auth/register", { username, email, password });
      form.reset();
      successBox.textContent = "Account created. Redirecting to sign in…";
      successBox.classList.remove("hidden");
      setTimeout(() => { window.location.href = "index.html"; }, 1400);
    } catch (err) {
      setAlert(alertBox, err.message || "Registration failed.");
      submitBtn.disabled = false;
      submitBtn.textContent = "Create account";
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  redirectIfLoggedIn();
  wirePasswordToggles();
  initLoginForm();
  initRegisterForm();
});
