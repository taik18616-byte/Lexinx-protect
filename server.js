<body>

<div class="container">

    <!-- REGISTER -->
    <div id="registerPage" class="card">

        <h1>LEXINX PROTECT</h1>
        <h2>Create Account</h2>

        <input
            id="registerUsername"
            placeholder="Username"
            autocomplete="username">

        <input
            id="registerPassword"
            type="password"
            placeholder="Password"
            autocomplete="new-password">

        <input
            id="registerCode"
            placeholder="Access Code">

        <button onclick="register()">
            Create Account
        </button>

        <p id="registerStatus" class="status"></p>

        <button
            class="gray"
            onclick="showLogin()">
            Already have an account? Login
        </button>

    </div>


    <!-- LOGIN -->
    <div id="loginPage" class="card hidden">

        <h1>LEXINX PROTECT</h1>
        <h2>Login</h2>

        <input
            id="loginUsername"
            placeholder="Username"
            autocomplete="username">

        <input
            id="loginPassword"
            type="password"
            placeholder="Password"
            autocomplete="current-password">

        <button onclick="login()">
            Login
        </button>

        <p id="loginStatus" class="status"></p>

        <button
            class="gray"
            onclick="showRegister()">
            Create new account
        </button>

    </div>


    <!-- DASHBOARD -->
    <div id="dashboardPage" class="hidden">

        <div class="card">

            <div class="top">

                <div>
                    <h1>LEXINX PROTECT</h1>

                    <span class="badge">
                        SCRIPT PANEL
                    </span>
                </div>

                <button
                    class="gray"
                    onclick="logout()">
                    Logout
                </button>

            </div>

        </div>


        <!-- ACCOUNT -->
        <div class="card">

            <h2>Account</h2>

            <div id="accountInfo">
                Loading...
            </div>

        </div>


        <!-- SCRIPT EDITOR -->
        <div class="card">

            <h2 id="editorTitle">
                Create Script
            </h2>

            <input
                id="scriptName"
                placeholder="Script name">

            <textarea
                id="scriptSource"
                placeholder="Paste Lua source here..."></textarea>

            <button
                id="createBtn"
                onclick="createScript()">
                Create Script
            </button>

            <button
                id="saveBtn"
                class="hidden"
                onclick="saveScript()">
                Save Changes
            </button>

            <button
                id="cancelBtn"
                class="gray hidden"
                onclick="cancelEdit()">
                Cancel
            </button>

            <div
                id="editorStatus"
                class="status">
            </div>

        </div>


        <!-- SCRIPT LIST -->
        <div class="card">

            <div class="top">

                <h2>
                    My Scripts
                </h2>

                <button
                    class="gray"
                    onclick="loadScripts()">
                    Refresh
                </button>

            </div>

            <div id="scriptList">
                Loading...
            </div>

        </div>

    </div>

</div>


<script>

let editingID = null;


/* =========================================================
   PAGE SWITCH
========================================================= */

function hideAllPages(){

    document
        .getElementById("registerPage")
        .classList.add("hidden");

    document
        .getElementById("loginPage")
        .classList.add("hidden");

    document
        .getElementById("dashboardPage")
        .classList.add("hidden");
}


function showRegister(){

    hideAllPages();

    document
        .getElementById("registerPage")
        .classList.remove("hidden");
}


function showLogin(){

    hideAllPages();

    document
        .getElementById("loginPage")
        .classList.remove("hidden");
}


function showDashboard(){

    hideAllPages();

    document
        .getElementById("dashboardPage")
        .classList.remove("hidden");

    loadAccount();
    loadScripts();
}


/* =========================================================
   API
========================================================= */

async function api(url, options = {}){

    const response =
        await fetch(
            url,
            {
                credentials:"same-origin",
                ...options,

                headers:{
                    "Content-Type":
                        "application/json",

                    ...(options.headers || {})
                }
            }
        );

    let data;

    try{

        data =
            await response.json();

    }catch{

        data = {
            ok:false,
            error:
                await response.text()
        };
    }

    return {
        response,
        data
    };
}


/* =========================================================
   REGISTER
========================================================= */

async function register(){

    const username =
        document
            .getElementById(
                "registerUsername"
            )
            .value
            .trim();

    const password =
        document
            .getElementById(
                "registerPassword"
            )
            .value;

    const code =
        document
            .getElementById(
                "registerCode"
            )
            .value
            .trim();

    const status =
        document
            .getElementById(
                "registerStatus"
            );

    if(!username ||
       !password ||
       !code){

        status.textContent =
            "Please fill in all fields.";

        return;
    }

    status.textContent =
        "Creating account...";

    const result =
        await api(
            "/api/register",
            {
                method:"POST",

                body:
                    JSON.stringify({
                        username,
                        password,
                        code
                    })
            }
        );

    if(
        !result.response.ok ||
        !result.data.ok
    ){

        status.textContent =
            result.data.error ||
            "Registration failed.";

        return;
    }

    /*
       QUAN TRỌNG:

       Không vào dashboard.
       Không đăng nhập tự động.

       Chuyển thẳng sang LOGIN.
    */

    document
        .getElementById(
            "loginUsername"
        )
        .value =
        username;

    document
        .getElementById(
            "loginPassword"
        )
        .value = "";

    document
        .getElementById(
            "loginStatus"
        )
        .textContent =
        "Account created. Please login.";

    showLogin();
}


/* =========================================================
   LOGIN
========================================================= */

async function login(){

    const username =
        document
            .getElementById(
                "loginUsername"
            )
            .value
            .trim();

    const password =
        document
            .getElementById(
                "loginPassword"
            )
            .value;

    const status =
        document
            .getElementById(
                "loginStatus"
            );

    if(!username || !password){

        status.textContent =
            "Enter username and password.";

        return;
    }

    status.textContent =
        "Logging in...";

    const result =
        await api(
            "/api/login",
            {
                method:"POST",

                body:
                    JSON.stringify({
                        username,
                        password
                    })
            }
        );

    if(
        !result.response.ok ||
        !result.data.ok
    ){

        status.textContent =
            result.data.error ||
            "Login failed.";

        return;
    }

    /*
       Login thành công
       → Dashboard
    */

    showDashboard();
}


/* =========================================================
   CHECK SESSION
========================================================= */

async function checkSession(){

    const result =
        await api("/api/me");

    if(
        result.response.ok &&
        result.data.ok
    ){

        showDashboard();

    }else{

        showRegister();
    }
}


/* =========================================================
   ACCOUNT
========================================================= */

async function loadAccount(){

    const result =
        await api("/api/me");

    if(
        !result.response.ok ||
        !result.data.ok
    ){

        showLogin();
        return;
    }

    const account =
        result.data;

    document
        .getElementById(
            "accountInfo"
        )
        .innerHTML =

        `
        <b>Username:</b>
        ${escapeHTML(account.username)}
        <br>

        <b>Access:</b>
        ${escapeHTML(account.accessType)}
        <br>

        <b>Scripts:</b>
        ${account.scriptCount}
        `;
}


/* =========================================================
   LOGOUT
========================================================= */

async function logout(){

    await api(
        "/api/logout",
        {
            method:"POST"
        }
    );

    editingID = null;

    cancelEdit();

    /*
       Logout → Login
       Không về Register.
    */

    showLogin();
}


/* =========================================================
   CREATE SCRIPT
========================================================= */

async function createScript(){

    const name =
        document
            .getElementById(
                "scriptName"
            )
            .value
            .trim();

    const source =
        document
            .getElementById(
                "scriptSource"
            )
            .value;

    const status =
        document
            .getElementById(
                "editorStatus"
            );

    if(!source.trim()){

        status.textContent =
            "Script is empty.";

        return;
    }

    status.textContent =
        "Creating...";

    const result =
        await api(
            "/api/create",
            {
                method:"POST",

                body:
                    JSON.stringify({
                        name,
                        source
                    })
            }
        );

    if(
        !result.response.ok ||
        !result.data.ok
    ){

        status.textContent =
            result.data.error ||
            "Create failed.";

        return;
    }

    status.textContent =
        "Script created successfully.";

    document
        .getElementById(
            "scriptName"
        )
        .value = "";

    document
        .getElementById(
            "scriptSource"
        )
        .value = "";

    loadAccount();
    loadScripts();
}


/* =========================================================
   LOAD SCRIPTS
========================================================= */

async function loadScripts(){

    const list =
        document
            .getElementById(
                "scriptList"
            );

    list.textContent =
        "Loading...";

    const result =
        await api(
            "/api/scripts"
        );

    if(
        !result.response.ok ||
        !result.data.ok
    ){

        list.textContent =
            result.data.error ||
            "Unable to load scripts.";

        return;
    }

    const scripts =
        result.data.scripts;

    if(!scripts.length){

        list.innerHTML =
            "<p>No scripts yet.</p>";

        return;
    }

    list.innerHTML =
        scripts
            .map(script => {

                return `
                <div class="script">

                    <div class="script-name">
                        ${escapeHTML(
                            script.name
                        )}
                    </div>

                    <div class="small">
                        ID:
                        ${escapeHTML(
                            script.id
                        )}
                    </div>

                    <div class="loader">
                        ${escapeHTML(
                            script.loader
                        )}
                    </div>

                    <br>

                    <button
                        onclick='copyText(${JSON.stringify(script.loader)})'>
                        Copy Loader
                    </button>

                    <button
                        class="gray"
                        onclick='editScript(${JSON.stringify(script.id)})'>
                        Edit
                    </button>

                    <button
                        class="red"
                        onclick='deleteScript(${JSON.stringify(script.id)})'>
                        Delete
                    </button>

                </div>
                `;

            })
            .join("");
}


/* =========================================================
   EDIT
========================================================= */

async function editScript(id){

    const result =
        await api(
            "/api/scripts/" +
            encodeURIComponent(id)
        );

    if(
        !result.response.ok ||
        !result.data.ok
    ){

        alert(
            result.data.error ||
            "Unable to load script."
        );

        return;
    }

    const script =
        result.data.script;

    editingID =
        script.id;

    document
        .getElementById(
            "scriptName"
        )
        .value =
        script.name;

    document
        .getElementById(
            "scriptSource"
        )
        .value =
        script.source;

    document
        .getElementById(
            "editorTitle"
        )
        .textContent =
        "Edit Script";

    document
        .getElementById(
            "createBtn"
        )
        .classList
        .add("hidden");

    document
        .getElementById(
            "saveBtn"
        )
        .classList
        .remove("hidden");

    document
        .getElementById(
            "cancelBtn"
        )
        .classList
        .remove("hidden");

    window.scrollTo({
        top:0,
        behavior:"smooth"
    });
}


/* =========================================================
   SAVE
========================================================= */

async function saveScript(){

    if(!editingID)
        return;

    const name =
        document
            .getElementById(
                "scriptName"
            )
            .value
            .trim();

    const source =
        document
            .getElementById(
                "scriptSource"
            )
            .value;

    const result =
        await api(
            "/api/scripts/" +
            encodeURIComponent(
                editingID
            ),
            {
                method:"PUT",

                body:
                    JSON.stringify({
                        name,
                        source
                    })
            }
        );

    if(
        !result.response.ok ||
        !result.data.ok
    ){

        document
            .getElementById(
                "editorStatus"
            )
            .textContent =
            result.data.error ||
            "Save failed.";

        return;
    }

    document
        .getElementById(
            "editorStatus"
        )
        .textContent =
        "Saved successfully.";

    loadAccount();
    loadScripts();
}


/* =========================================================
   CANCEL EDIT
========================================================= */

function cancelEdit(){

    editingID = null;

    document
        .getElementById(
            "editorTitle"
        )
        .textContent =
        "Create Script";

    document
        .getElementById(
            "createBtn"
        )
        .classList
        .remove("hidden");

    document
        .getElementById(
            "saveBtn"
        )
        .classList
        .add("hidden");

    document
        .getElementById(
            "cancelBtn"
        )
        .classList
        .add("hidden");

    document
        .getElementById(
            "scriptName"
        )
        .value = "";

    document
        .getElementById(
            "scriptSource"
        )
        .value = "";

    document
        .getElementById(
            "editorStatus"
        )
        .textContent = "";
}


/* =========================================================
   DELETE
========================================================= */

async function deleteScript(id){

    if(
        !confirm(
            "Delete this script?"
        )
    ){
        return;
    }

    const result =
        await api(
            "/api/scripts/" +
            encodeURIComponent(id),
            {
                method:"DELETE"
            }
        );

    if(
        !result.response.ok ||
        !result.data.ok
    ){

        alert(
            result.data.error ||
            "Delete failed."
        );

        return;
    }

    if(editingID === id){

        cancelEdit();
    }

    loadAccount();
    loadScripts();
}


/* =========================================================
   COPY LOADER
========================================================= */

async function copyText(text){

    try{

        await navigator
            .clipboard
            .writeText(text);

        alert(
            "Loader copied!"
        );

    }catch{

        const textarea =
            document.createElement(
                "textarea"
            );

        textarea.value = text;

        document
            .body
            .appendChild(textarea);

        textarea.select();

        document.execCommand(
            "copy"
        );

        textarea.remove();

        alert(
            "Loader copied!"
        );
    }
}


/* =========================================================
   ESCAPE
========================================================= */

function escapeHTML(value){

    return String(value)
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
}


/* =========================================================
   START
========================================================= */

checkSession();

</script>

</body>
