import express from "express";
import { exec } from "child_process";

const app = express();

/*
====================================
HARDCODED SECRETS
====================================
*/

const JWT_SECRET =
    "SUPER_SECRET_PRODUCTION_KEY";

const API_KEY =
    "sk_live_test_key_123";

const DB_PASSWORD =
    "admin123";

/*
====================================
DATABASE
====================================
*/


/*
====================================
AUTHENTICATION
====================================
*/


/*
====================================
CRYPTO
====================================
*/



/*
====================================
PATH TRAVERSAL
====================================
*/

import fs from "fs";

function readUserFile(
    userInput: string
) {

    return fs.readFileSync(
        "/tmp/" + userInput,
        "utf8"
    );

}

/*
====================================
COMMAND INJECTION
====================================
*/

function runCommand(
    command: string
) {

    exec(command);

}

/*
====================================
EVAL
====================================
*/

function executeCode(
    payload: string
) {

    return eval(payload);

}

/*
====================================
UNAUTHENTICATED PUBLIC ROUTES
====================================
*/

app.get(
    "/public",
    (req, res) => {

        res.send(
            "public endpoint"
        );

    }
);

app.post(
    "/admin",
    (req, res) => {

        res.send(
            "admin endpoint"
        );

    }
);

/*
====================================
SQL INJECTION STYLE
====================================
*/

function findUser(
    username: string
) {

    const query =
        "SELECT * FROM users WHERE username = '"
        + username
        + "'";

    console.log(query);

}

/*
====================================
SECRETS VIA ENV
====================================
*/

const STRIPE_SECRET =
    process.env.STRIPE_SECRET;

const PRIVATE_KEY =
    process.env.PRIVATE_KEY;

/*
====================================
EXTERNAL SERVICE
====================================
*/

const STRIPE_URL =
    "https://api.stripe.com";

/*
====================================
DUMMY EXPORT
====================================
*/

export default app;