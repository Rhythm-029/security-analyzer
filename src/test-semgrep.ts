import {
    SemgrepService
}
from "./semgrep/semgrep.service";

async function run() {

    const semgrep =
        new SemgrepService();

    const findings =
        await semgrep.scanRepository(
            process.cwd()
        );

    console.log(
        JSON.stringify(
            findings,
            null,
            2
        )
    );

}

run();