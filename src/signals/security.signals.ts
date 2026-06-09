export const SECURITY_SIGNALS = {

    authentication: {
        keywords: [
            "jwt",
            "login",
            "signin",
            "authenticate",
            "token"
        ],
        patterns: [
            "jwt.sign(",
            "jwt.verify(",
            "passport.authenticate("
        ]
    },

    authorization: {
        keywords: [
            "role",
            "permission",
            "rbac",
            "admin"
        ],
        patterns: [
            "hasRole(",
            "checkPermission(",
            "authorize("
        ]
    },

    secrets: {
        keywords: [
            "api_key",
            "secret",
            "password",
            "token",
            "private_key"
        ],
        patterns: [
            "process.env",
            "JWT_SECRET",
            "API_KEY"
        ]
    },

    encryption: {
        keywords: [
            "bcrypt",
            "crypto",
            "hash"
        ],
        patterns: [
            "bcrypt.hash(",
            "bcrypt.compare(",
            "crypto.createHash("
        ]
    },

    input_validation: {
        keywords: [
            "validator",
            "validation",
            "sanitize"
        ],
        patterns: [
            "Joi.object(",
            "z.object(",
            "validate("
        ]
    },

    logging: {
        keywords: [
            "logger",
            "winston",
            "morgan"
        ],
        patterns: [
            "console.log(",
            "logger.info(",
            "logger.error("
        ]
    }

};