export interface SemgrepFinding {

    ruleId: string;

    severity: string;

    file: string;

    line: number;

    message: string;

}