const API_URL = "https://api.test.lucas5823.c44.integrator.host/auth";

// Função de login
async function login() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const errorDiv = document.getElementById("error");
    errorDiv.textContent = "";

    try {
        const res = await fetch(`${API_URL}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();

        if (!res.ok) {
            console.error("Erro no login:", data);
            throw new Error(data.error || "Erro no login"); 
        }

        // Salva o accessToken correto
        localStorage.setItem("accessToken", data.accessToken);
        localStorage.setItem("refreshToken", data.refreshToken);
        window.location.href = "home.html";

    } catch (e) {
        console.error("Falha ao efetuar login:", e);
        errorDiv.textContent = e.message;
    }
}

// Função para carregar informações do usuário
async function loadUser() {
    const token = localStorage.getItem("accessToken");
    if (!token) {
        window.location.href = "index.html";
        return;
    }

    try {
        const res = await fetch(`${API_URL}/me`, {
            headers: { "Authorization": `Bearer ${token}` }
        });

        if (!res.ok) {
            console.error("Falha ao buscar usuário:", await res.text());
            localStorage.removeItem("accessToken");
            window.location.href = "login.html";
            return;
        }

        const user = await res.json();
        document.getElementById("userId").textContent = user.id;
        document.getElementById("userUsername").textContent = user.username;
        document.getElementById("userEmail").textContent = user.email;
        document.getElementById("userName").textContent = user.name;
        document.getElementById("userRoles").textContent = user.roles.join(", ");

    } catch (err) {
        console.error("Erro ao carregar usuário:", err);
        localStorage.removeItem("accessToken");
        window.location.href = "login.html";
    }
}

// Função de logout
function logout() {
    localStorage.removeItem("accessToken");
    window.location.href = "index.html";
}

// Função para mostrar tokens
function mostrarTokens() {
    const accessToken = localStorage.getItem("accessToken");
    const refreshToken = localStorage.getItem("refreshToken");

    console.log("Access Token:", accessToken);
    console.log("Refresh Token:", refreshToken);

    const tokensDiv = document.getElementById("tokens");
    if (tokensDiv) {
        tokensDiv.innerHTML = `
            <p><strong>Access Token:</strong> ${accessToken || "Não encontrado"}</p>
            <p><strong>Refresh Token:</strong> ${refreshToken || "Não encontrado"}</p>
        `;
    }
}

// Funções de validação
function isEmailValid(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isPasswordValid(password) {
    return password.length >= 6; // senha mínima de 6 caracteres
}

function isPhoneValid(phone) {
    return /^\d{9}$/.test(phone); // apenas 9 dígitos
}

// Função para registrar usuário
async function register() {
    const API_URL = "https://api.test.lucas5823.c44.integrator.host/auth";
    const errorDiv = document.getElementById("error");
    errorDiv.textContent = "";

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();
    const email = document.getElementById("email").value.trim();
    const name = document.getElementById("name").value.trim();
    const dateBirth = document.getElementById("dateBirth").value;
    const countryCode = document.getElementById("countryCode").value;
    const ddd = document.getElementById("ddd").value.trim();
    const phone = document.getElementById("phone").value.trim();

    // Validações
    if (!username) { errorDiv.textContent = "Username é obrigatório."; return; }
    if (!password) { errorDiv.textContent = "Senha é obrigatória."; return; }
    if (!isPasswordValid(password)) { errorDiv.textContent = "Senha deve ter ao menos 6 caracteres."; return; }
    if (!email) { errorDiv.textContent = "Email é obrigatório."; return; }
    if (!isEmailValid(email)) { errorDiv.textContent = "Email inválido."; return; }
    if (!name) { errorDiv.textContent = "Nome é obrigatório."; return; }
    if (!dateBirth) { errorDiv.textContent = "Data de nascimento é obrigatória."; return; }
    if (!countryCode) { errorDiv.textContent = "Selecione o código do país."; return; }
    if (!ddd) { errorDiv.textContent = "DDD é obrigatório."; return; }
    if (!phone) { errorDiv.textContent = "Telefone é obrigatório."; return; }
    if (!isPhoneValid(phone)) { errorDiv.textContent = "Telefone inválido. Deve ter 9 dígitos."; return; }

    // Monta o telefone no formato: +CódigoPais DDD Número
    const numberTel = `${countryCode}${ddd}${phone}`;

    const payload = { username, password, email, name, dateBirth, numberTel };

    try {
        const res = await fetch(`${API_URL}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || "Erro ao cadastrar usuário");
        }

        alert("Cadastro realizado com sucesso!");
        window.location.href = "index.html";

    } catch (e) {
        console.error("Erro no registro:", e);
        errorDiv.textContent = e.message;
    }
}
