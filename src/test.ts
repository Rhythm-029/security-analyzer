import { ContextEngineService }
from "./services/contextEngine.service";

const engine =
    new ContextEngineService();

async function run() {

    const result =
        await engine.analyzeFile(
            "auth.ts",
            `
            jwt.verify(token);
            bcrypt.compare(password);
            `
        );

    console.log(result);

}

run();

const userInput = process.argv[2];

eval(userInput);