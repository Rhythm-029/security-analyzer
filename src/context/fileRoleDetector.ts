export class FileRoleDetector {

    detect(
        filePath: string
    ): string {

        if (
            filePath.includes(
                "/controllers/"
            )
        ) {
            return "controller";
        }

        if (
            filePath.includes(
                "/services/"
            )
        ) {
            return "service";
        }

        if (
            filePath.includes(
                "/routes/"
            )
        ) {
            return "route";
        }

        if (
            filePath.includes(
                "/middleware/"
            )
        ) {
            return "middleware";
        }

        if (
            filePath.includes(
                "/models/"
            )
        ) {
            return "model";
        }

        if (
            filePath.includes(
                "/repositories/"
            )
        ) {
            return "repository";
        }

        if (
            filePath.includes(
                "/ai/"
            )
        ) {
            return "ai";
        }

        return "unknown";

    }

}