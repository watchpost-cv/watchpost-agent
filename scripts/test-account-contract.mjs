import fs from "node:fs";

const publicHtml = fs.readFileSync("public/index.html", "utf8");
const contentHtml = fs.readFileSync("content/index.html", "utf8");
const js = fs.readFileSync("public/assets/js/script.js", "utf8");
const manageHtml = fs.readFileSync("public/manage.html", "utf8");
const manageJs = fs.readFileSync("public/manage.js", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

// First-run setup (served + Nift source): Username, Email, Password, Confirm.
for (const [label, html] of [["public", publicHtml], ["content", contentHtml]]) {
  const setup = html.split('<form id="setup-form"')[1].split("</form>")[0];
  for (const id of ["setup-confirm"]) {
    a(setup.includes('id="' + id + '"'), label + " setup form missing " + id);
  }
  a(setup.includes('name="username"'), label + " setup form missing username");
  a(setup.includes('name="email"'), label + " setup form missing email");
  a(setup.includes('name="password"'), label + " setup form missing password");
}
a(js.includes("Passwords do not match."), "setup frontend must validate password confirmation");

// Application admin panel account creation: username, email, password, confirm.
const accountForm = publicHtml.split('<form id="account-form"')[1].split("</form>")[0];
a(accountForm.includes('name="username"') && accountForm.includes('name="email"') && accountForm.includes('name="password"') && accountForm.includes('id="account-confirm"'),
  "account-form missing canonical fields");

// /manage Add user dialog + handler.
const dialog = manageHtml.split("<dialog>")[1].split("</dialog>")[0];
for (const id of ["username", "email", "password", "confirm"]) {
  a(dialog.includes('name="' + id + '"'), "/manage Add user dialog missing " + id);
}
a(/Display name|display/.test(dialog) === false, "/manage Add user dialog requests a display name");
a(manageJs.includes("Passwords do not match."), "/manage frontend must validate password confirmation");
a(manageJs.includes("username:f.get(\"username\")") || manageJs.includes("username:f.get('username')"), "/manage create payload must send username");

// Login form (served + Nift source): the identifier field is labelled
// "Username or email" and is a text field so usernames pass validation. The
// backend resolves both username and email against the same identifier.
for (const [label, html] of [["public", publicHtml], ["content", contentHtml]]) {
  const login = html.split('<form id="login-form"')[1].split("</form>")[0];
  a(login.includes("Username or email"), label + " login form label must say 'Username or email'");
  a(!/type="email"/.test(login), label + " login identifier must be type=text, not type=email");
  a(login.includes('autocomplete="username"'), label + " login identifier must keep autocomplete=username");
}

// Header Log out control stays on one line and yields gracefully for long
// emails: no fixed pixel width, white-space:nowrap on the button, ellipsis on
// the account name.
const pairingCss = fs.readFileSync("public/assets/css/pairing.css", "utf8");
a(pairingCss.includes(".topbar .account button{width:auto"), "pairing.css Log out button must not use a fixed pixel width");
a(pairingCss.includes("white-space:nowrap"), "pairing.css Log out button must keep white-space:nowrap");
a(pairingCss.includes("text-overflow:ellipsis"), "pairing.css account name must ellipsize for long emails");

console.log("watchpost-agent account-creation contract: ok");