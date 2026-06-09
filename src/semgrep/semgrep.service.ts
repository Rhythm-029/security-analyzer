import { exec } from "child_process";
import { promisify } from "util";

import { SemgrepFinding }
from "./semgrep.types";

const execAsync =
    promisify(exec);

export class SemgrepService {

    async scanRepository(
        repositoryPath: string
    ): Promise<SemgrepFinding[]> {

        try {

            const { stdout } =
                await execAsync(

                    `semgrep scan --config auto --json "${repositoryPath}"`

                );

            const result =
                JSON.parse(stdout);

            const findings:
                SemgrepFinding[] = [];

            for (
                const finding of
                result.results || []
            ) {

                findings.push({

                    ruleId:
                        finding.check_id,

                    severity:
                        finding.extra
                            ?.severity ||
                        "INFO",

                    file:
                        finding.path,

                    line:
                        finding.start
                            ?.line || 0,

                    message:
                        finding.extra
                            ?.message || ""

                });

            }

            return findings;

        } catch (error) {

            console.error(
                "Semgrep Error:",
                error
            );

            return [];

        }

    }

}