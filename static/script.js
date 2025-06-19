// /static/script.js
let token = "";
let usernameDisplay = "";
let isLoginMode = true;

function toggleAuthMode() {
  isLoginMode = !isLoginMode;

  document.getElementById("auth-title").textContent = isLoginMode
    ? "Login"
    : "Register";
  document.getElementById("auth-btn").textContent = isLoginMode
    ? "Login"
    : "Register";
  document.querySelector("#auth-section p a").textContent = isLoginMode
    ? "Don't have an account? Register"
    : "Already have an account? Login";
  document.getElementById("auth-message").textContent = "";
}

async function handleAuth() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const endpoint = isLoginMode ? "/login" : "/register";

  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  const data = await res.json();

  if (res.status === 200 || res.status === 201) {
    if (isLoginMode) {
      token = data.access_token;
      usernameDisplay = data.username; // Store the username
      document.getElementById("auth-section").style.display = "none";
      document.getElementById("welcome-section").style.display = "block"; // Show welcome section
      document.getElementById("user-name-display").textContent =
        usernameDisplay; // Display username
      document.getElementById("predict-section").style.display = "block";
    }
    document.getElementById("auth-message").textContent = isLoginMode
      ? "Login successful!"
      : "Registration successful! Please login.";
  } else {
    document.getElementById("auth-message").textContent =
      data.message || "An error occurred.";
  }
}

async function predict() {
  const amount = parseFloat(document.getElementById("amount").value);
  const old_balance = parseFloat(document.getElementById("old_balance").value);
  const new_balance = parseFloat(document.getElementById("new_balance").value);
  const type = document.getElementById("type").value;

  const res = await fetch("/predict", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ amount, old_balance, new_balance, type }),
  });

  const data = await res.json();
  document.getElementById("result-message").textContent =
    res.status === 200 ? data.result : data.error;
}

function logout() {
  token = "";
  usernameDisplay = ""; // Clear the username
  document.getElementById("predict-section").style.display = "none";
  document.getElementById("welcome-section").style.display = "none"; // Hide welcome section
  document.getElementById("auth-section").style.display = "block";
  document.getElementById("auth-message").textContent = "Logged out.";
}
