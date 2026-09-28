/* API d'envoi de l'e-mail de réinitialisation (Vercel, Node 20).
   - Le lien est généré avec Firebase Admin SDK (les clés restent côté serveur).
   - L'e-mail est envoyé par nos soins avec notre propre HTML.
   - Le mot de passe est réellement changé par Firebase Auth (confirmPasswordReset, côté page). */
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

function initAdmin() {
  if (admin.apps.length) return;
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n")
    })
  });
}

/* Limite de demandes (en mémoire : best-effort, suffisant contre les abus simples) */
const compteurs = new Map();
function trop(cle, max, fenetreMs) {
  const now = Date.now();
  const liste = (compteurs.get(cle) || []).filter(t => now - t < fenetreMs);
  liste.push(now);
  compteurs.set(cle, liste);
  return liste.length > max;
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function gabarit(lien, pseudo) {
  const salut = pseudo ? `Bonjour ${esc(pseudo)},` : "Bonjour,";
  return `<!DOCTYPE html>
<html lang="fr"><body style="margin:0;padding:0;background:#0d1015;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0d1015;padding:32px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#171d25;border:1px solid #232a34;border-radius:22px;font-family:Arial,Helvetica,sans-serif;color:#e9edf2;">
<tr><td style="padding:32px 28px 8px;">
<h1 style="margin:0;font-size:24px;letter-spacing:-.02em;">Taux de suspicion</h1>
</td></tr>
<tr><td style="padding:8px 28px;font-size:15px;line-height:1.5;color:#e9edf2;">
<p style="margin:12px 0;">${salut}</p>
<p style="margin:12px 0;">Vous avez demandé à réinitialiser votre mot de passe. Cliquez sur le bouton ci-dessous pour en choisir un nouveau.</p>
</td></tr>
<tr><td align="center" style="padding:12px 28px 20px;">
<a href="${esc(lien)}" style="display:inline-block;background:#6ee7c8;color:#06241c;text-decoration:none;font-weight:700;font-size:15px;padding:13px 26px;border-radius:999px;">Choisir un nouveau mot de passe</a>
</td></tr>
<tr><td style="padding:0 28px 28px;font-size:12px;line-height:1.5;color:#8b96a5;">
<p style="margin:8px 0;">Ce lien est valable environ une heure et ne fonctionne qu'une seule fois.</p>
<p style="margin:8px 0;">Si le bouton ne marche pas, copiez cette adresse dans votre navigateur :<br><span style="word-break:break-all;color:#8b96a5;">${esc(lien)}</span></p>
<p style="margin:8px 0;">Vous n'êtes pas à l'origine de cette demande ? Ignorez simplement cet e-mail : votre mot de passe ne change pas.</p>
</td></tr>
</table>
</td></tr></table>
</body></html>`;
}

module.exports = async (req, res) => {
  const origine = req.headers.origin || "";
  const autorises = (process.env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
  if (autorises.includes(origine)) {
    res.setHeader("Access-Control-Allow-Origin", origine);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false });
  if (!autorises.includes(origine)) return res.status(403).json({ ok: false });

  const email = String((req.body && req.body.email) || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)
    return res.status(400).json({ ok: false, erreur: "E-mail invalide." });

  const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "inconnue";
  if (trop("ip:" + ip, 10, 10 * 60e3) || trop("mail:" + email, 3, 10 * 60e3))
    return res.status(429).json({ ok: false });

  try {
    initAdmin();
    let utilisateur;
    try { utilisateur = await admin.auth().getUserByEmail(email); }
    catch (e) {
      /* Compte inexistant : même réponse qu'un succès, pour ne pas révéler qui est inscrit */
      if (e.code === "auth/user-not-found") return res.status(200).json({ ok: true });
      throw e;
    }
    if (utilisateur.disabled) return res.status(200).json({ ok: true });

    /* Firebase génère le vrai lien ; on en garde uniquement le code (oobCode) pour bâtir notre lien vers le site */
    const lienFirebase = await admin.auth().generatePasswordResetLink(email);
    const code = new URL(lienFirebase).searchParams.get("oobCode");
    if (!code) throw new Error("oobCode manquant");
    const site = String(process.env.SITE_URL || "").replace(/\/+$/, "");
    const lien = `${site}/?mode=resetPassword&oobCode=${encodeURIComponent(code)}`;

    const transport = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
    });
    await transport.sendMail({
      from: `"Taux de suspicion" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: "Réinitialisation de votre mot de passe",
      text: `Pour choisir un nouveau mot de passe, ouvrez ce lien (valable environ une heure) :\n${lien}\n\nSi vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.`,
      html: gabarit(lien, utilisateur.displayName)
    });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("reset-password:", e && e.code || "", e && e.message || e);
    return res.status(500).json({ ok: false });
  }
};
