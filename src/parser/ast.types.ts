export interface ASTContext {

    imports: string[];

    routes: {
        method: string;
        path: string;
        middleware: string[];
    }[];

    middleware: string[];

    databaseCalls: string[];

    jwtUsage: string[];

    envVariables: string[];

    classes: string[];

    functions: string[];

    interfaces: string[];

}