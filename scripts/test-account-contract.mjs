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

console.log("watchpost-agent account-creation contract: ok");