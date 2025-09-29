// 회원가입
document.getElementById("registerForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("regEmail").value;
  const nickname = document.getElementById("regNickname").value;
  const password = document.getElementById("regPassword").value;

  const res = await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, nickname, password })
  });

  const data = await res.json();
  alert(data.message || data.error);
});

// 로그인
document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();
  if (data.token) {
    alert("로그인 성공!");
    localStorage.setItem("token", data.token);
    window.location.href = "/"; // 메인 페이지로 이동
  } else {
    alert(data.error);
  }
});
