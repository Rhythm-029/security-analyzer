export const TECHNOLOGY_SIGNALS = {

    nodejs: {
        keywords: [
            "package.json",
            "node_modules"
        ],
        patterns: [
            "require(",
            "process.env",
            "module.exports"
        ]
    },

    express: {
        keywords: [
            "express",
            "router"
        ],
        patterns: [
            "express()",
            "Router()",
            "router.get(",
            "router.post("
        ]
    },

    mongodb: {
        keywords: [
            "mongodb",
            "mongoose"
        ],
        patterns: [
            "mongoose.connect(",
            "Schema(",
            "model("
        ]
    },

    jwt: {
        keywords: [
            "jwt",
            "jsonwebtoken"
        ],
        patterns: [
            "jwt.sign(",
            "jwt.verify("
        ]
    }

};