// console.log(admin);
const admin = require("firebase-admin");

let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else {
    serviceAccount = require("./serviceAccountKey.json");
}

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const {
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require("@simplewebauthn/server");

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json());

let currentChallenge = "";

// Generate registration challenge
app.get("/generate-registration-options", (req, res) => {

    currentChallenge = crypto.randomBytes(32).toString("base64url");

    res.json({
        challenge: currentChallenge,
        rp: {
            name: "SecureChat"
        },
        user: {
            id: crypto.randomBytes(16).toString("base64url"),
            name: "user@example.com",
            displayName: "Secure Chat User"
        },
        pubKeyCredParams: [
    {
        alg: -7,
        type: "public-key"
    },
    {
        alg: -257,
        type: "public-key"
    }
],
        authenticatorSelection: {
            authenticatorAttachment: "platform",
            userVerification: "required"
        },
        timeout: 60000,
        attestation: "none"
    });

});

// Verify registration
app.post("/verify-registration", async (req, res) => {

    try {

        const { uid, credential } = req.body;

       await db.collection("users").doc(uid).set({

    credentialID: credential.id,

    registered: true

}, { merge: true });

        // Save temporarily for authentication
        global.savedCredential = {
            id: credential.id
        };

        res.json({
            verified: true
        });

    } catch (error) {

    console.log("========== FIRESTORE ERROR ==========");
    console.error(error);
    console.error(error.stack);

    res.status(500).json({
        verified: false,
        error: error.message
    });

}
        });
    
app.get("/generate-authentication-options", (req, res) => {

    if (!global.savedCredential) {

        return res.status(400).json({
            error: "No fingerprint registered."
        });

    }

    currentChallenge = crypto.randomBytes(32).toString("base64url");

    res.json({

        challenge: currentChallenge,

        allowCredentials: [

            {
                id: global.savedCredential.id,
                type: "public-key"
            }

        ],

        timeout: 60000,

        userVerification: "required"

    });

});
app.post("/verify-authentication", (req, res) => {

    res.json({
        verified: true
    });

});
app.get("/", (req, res) => {
    res.send("Server is working!");
});

console.log("Loading routes...");
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`SecureChat WebAuthn Server Running on port ${PORT}`);
});