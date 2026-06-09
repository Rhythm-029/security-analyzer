export interface SecurityFinding {

    type: string;

    severity:
        | "LOW"
        | "MEDIUM"
        | "HIGH"
        | "CRITICAL";

    file: string;

    description: string;

}