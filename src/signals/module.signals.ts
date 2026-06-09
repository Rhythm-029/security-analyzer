export const MODULE_SIGNALS = {

    authentication: {

        keywords: [
            "auth",
            "login",
            "signin",
            "signup",
            "token",
            "session"
        ],

        patterns: [
            "jwt.verify",
            "jwt.sign",
            "bcrypt.compare",
            "bcrypt.hash",
            "passport.authenticate",
            "oauth"
        ]

    },

    authorization: {

        keywords: [
            "role",
            "permission",
            "rbac",
            "access"
        ],

        patterns: [
            "hasRole",
            "checkPermission",
            "authorize",
            "isAdmin"
        ]

    },

    api: {

        keywords: [
            "route",
            "api",
            "controller"
        ],

        patterns: [
            "router.get",
            "router.post",
            "router.put",
            "router.delete",
            "app.get",
            "app.post"
        ]

    },

    database: {

        keywords: [
            "repository",
            "database",
            "db"
        ],

        patterns: [
            "mongoose.connect",
            "prisma.",
            "sequelize.",
            "typeorm."
        ]

    }

};