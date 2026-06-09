import {
    Project,
    SyntaxKind,
    CallExpression,
    PropertyAccessExpression,
    ClassDeclaration,
    FunctionDeclaration,
    InterfaceDeclaration
}
from "ts-morph";

import {
    ASTContext
}
from "./ast.types";

export class ASTParserService {

    analyze(
        filePath: string
    ): ASTContext {

        const project =
            new Project();

        const sourceFile =
            project.addSourceFileAtPath(
                filePath
            );

        const imports: string[] = [];

        const routes: {
            method: string;
            path: string;
            middleware: string[];
        }[] = [];

        const middleware: string[] = [];

        const databaseCalls: string[] = [];

        const jwtUsage: string[] = [];

        const envVariables: string[] = [];

        const classes: string[] = [];

        const functions: string[] = [];

        const interfaces: string[] = [];

        /*
        --------------------------------
        IMPORTS
        --------------------------------
        */

        sourceFile
            .getImportDeclarations()
            .forEach(importDecl => {

                imports.push(
                    importDecl
                        .getModuleSpecifierValue()
                );

            });

        /*
        --------------------------------
        AST WALK
        --------------------------------
        */

        sourceFile
            .forEachDescendant(node => {

                /*
                --------------------------------
                CLASS DETECTION
                --------------------------------
                */

                if (
                    node.getKind() ===
                    SyntaxKind.ClassDeclaration
                ) {

                    const classNode =
                        node as ClassDeclaration;

                    const className =
                        classNode.getName();

                    if (className) {

                        classes.push(
                            className
                        );

                    }

                }

                /*
                --------------------------------
                FUNCTION DETECTION
                --------------------------------
                */

                if (
                    node.getKind() ===
                    SyntaxKind.FunctionDeclaration
                ) {

                    const functionNode =
                        node as FunctionDeclaration;

                    const functionName =
                        functionNode.getName();

                    if (functionName) {

                        functions.push(
                            functionName
                        );

                    }

                }

                /*
                --------------------------------
                INTERFACE DETECTION
                --------------------------------
                */

                if (
                    node.getKind() ===
                    SyntaxKind.InterfaceDeclaration
                ) {

                    const interfaceNode =
                        node as InterfaceDeclaration;

                    const interfaceName =
                        interfaceNode.getName();

                    if (interfaceName) {

                        interfaces.push(
                            interfaceName
                        );

                    }

                }

                /*
                --------------------------------
                CALL EXPRESSIONS
                --------------------------------
                */

                if (
                    node.getKind() ===
                    SyntaxKind.CallExpression
                ) {

                    const callExpression =
                        node as CallExpression;

                    const expression =
                        callExpression
                            .getExpression()
                            .getText();

                    /*
                    --------------------------------
                    ROUTES
                    --------------------------------
                    */

                    if (
                        expression === "router.get" ||
                        expression === "router.post" ||
                        expression === "router.put" ||
                        expression === "router.delete"
                    ) {

                        const args =
                            callExpression
                                .getArguments();

                        const routePath =
                            args[0]
                                ?.getText()
                                .replace(
                                    /['"]/g,
                                    ""
                                );

                        routes.push({

                            method:
                                expression
                                    .split(".")[1]
                                    .toUpperCase(),

                            path:
                                routePath || "",

                            middleware: []

                        });

                    }

                    /*
                    --------------------------------
                    MIDDLEWARE
                    --------------------------------
                    */

                    if (
                        expression === "app.use" ||
                        expression === "router.use"
                    ) {

                        const args =
                            callExpression
                                .getArguments();

                        if (
                            args.length > 0
                        ) {

                            middleware.push(
                                args[0]
                                    .getText()
                            );

                        }

                    }

                    /*
                    --------------------------------
                    JWT
                    --------------------------------
                    */

                    if (
                        expression === "jwt.sign" ||
                        expression === "jwt.verify"
                    ) {

                        jwtUsage.push(
                            expression
                        );

                    }

                    /*
                    --------------------------------
                    DATABASE
                    --------------------------------
                    */

                    if (

                        expression.includes(
                            "mongoose"
                        ) ||

                        expression.includes(
                            "connect"
                        ) ||

                        expression.includes(
                            "find"
                        ) ||

                        expression.includes(
                            "findOne"
                        ) ||

                        expression.includes(
                            "save"
                        ) ||

                        expression.includes(
                            "update"
                        )

                    ) {

                        databaseCalls.push(
                            expression
                        );

                    }

                }

                /*
                --------------------------------
                ENV VARIABLES
                --------------------------------
                */

                if (
                    node.getKind() ===
                    SyntaxKind.PropertyAccessExpression
                ) {

                    const propertyAccess =
                        node as PropertyAccessExpression;

                    const text =
                        propertyAccess
                            .getText();

                    if (
                        text.startsWith(
                            "process.env."
                        )
                    ) {

                        envVariables.push(
                            text
                        );

                    }

                }

            });

        return {

            imports,

            routes,

            middleware,

            databaseCalls,

            jwtUsage,

            envVariables,

            classes,

            functions,

            interfaces

        };

    }

}