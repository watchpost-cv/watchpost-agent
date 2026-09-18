import fs from "node:fs";

const html = fs.readFileSync("public/index.html", "utf8");
const js = fs.readFileSync("public/assets/js/script.js", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

// First-run setup: Username, Email, Password, Confirm password.
const setup = html.split('<form id="setup-form"')[1].split("</form>")[0];
for (const id of ["setup-confirm"]) {
  a(setup.includes('id="' + id + '"'), "setup form missing " + id);
}
a(setup.includes('name="username"'), "setup form missing username");
a(setup.includes('name="email"'), "setup form missing email");
a(setup.includes('name="password"'), "setup form missing password");
// Additional-account creation (admin panel) has username, email, password, confirm.
const accountForm = html.split('<form id="account-form"')[1].split("</form>")[0];
a(accountForm.includes('name="username"') && accountForm.includes('name="email"') && accountForm.includes('name="password"') && accountForm.includes('id="account-confirm"'),
  "account-form missing canonical fields");
// Frontend validates confirmation in both forms.
a(js.includes("Passwords do not match."), "frontend must validate password confirmation");
console.log("watchpost-agent account-creation contract: ok");