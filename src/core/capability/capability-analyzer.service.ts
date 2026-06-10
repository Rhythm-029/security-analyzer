import {
  CapabilityCategory,
  CapabilityDescriptor,
  DependencyAnalysisResult,
  RepositoryGraphSnapshot,
  SourceFactSet,
} from "../domain/appsec.types";
import { CapabilityAnalyzerContract } from "../contracts/appsec.contracts";

type CapabilitySeed = {
  name: string;
  category: CapabilityCategory;
  evidence: string[];
  graphEvidence: string[];
  confidence: number;
};

export class CapabilityAnalyzerService
  implements CapabilityAnalyzerContract
{
  analyze(params: {
    graph: RepositoryGraphSnapshot;
    sourceFactsByFile: Map<string, SourceFactSet>;
    dependencyFacts: DependencyAnalysisResult;
  }): CapabilityDescriptor[] {

    const seeds =
      new Map<string, CapabilitySeed>();

    const addSeed = (
      name: string,
      category: CapabilityCategory,
      evidence: string[],
      graphEvidence: string[],
      confidence: number
    ) => {

      const existing =
        seeds.get(name);

      if (!existing) {

        seeds.set(name, {
          name,
          category,
          evidence,
          graphEvidence,
          confidence,
        });

        return;

      }

      seeds.set(name, {

        ...existing,

        evidence:
          Array.from(
            new Set([
              ...existing.evidence,
              ...evidence
            ])
          ),

        graphEvidence:
          Array.from(
            new Set([
              ...existing.graphEvidence,
              ...graphEvidence
            ])
          ),

        confidence:
          Math.max(
            existing.confidence,
            confidence
          ),

      });

    };

    const authenticationIndicators = [

      "jwt.sign",
      "jwt.verify",

      "passport.authenticate",
      "passport.use",

      "oauth.authenticate",

      "securitycontextholder",
      "authenticationmanager",

    ];

    const authorizationIndicators = [

      "authorize",
      "checkpermission",

      "hasrole",
      "hasauthority",

      "rbac",
      "acl",

    ];

    const cryptoIndicators = [

      "bcrypt.hash",
      "bcrypt.compare",

      "crypto.createhash",
      "crypto.encrypt",
      "crypto.decrypt",

      "openssl",

    ];

    const databaseIndicators = [

      "mongoose.connect",

      "prisma.",

      "sequelize",

      "typeorm",

      "jdbc",

      "entityframework",

    ];

    for (
      const [filePath, facts]
      of params.sourceFactsByFile.entries()
    ) {

      const callSet =
        new Set(
          facts.functionCalls.map(
            call =>
              call.toLowerCase()
          )
        );

      const importSet =
        new Set(
          facts.imports.map(
            specifier =>
              specifier.toLowerCase()
          )
        );

      if (
        facts.envReferences.length > 0
      ) {

        addSeed(
          "secret_management",
          "secret_management",
          facts.envReferences,
          [filePath],
          0.85
        );

      }

      if (
        facts.routes.length > 0
      ) {

        addSeed(
          "api_exposure",
          "network_exposure",
          facts.routes.map(
            route =>
              `${route.method} ${route.path}`
          ),
          [filePath],
          0.95
        );

      }

      if (

        [...callSet].some(
          call =>
            authenticationIndicators.some(
              indicator =>
                call.includes(
                  indicator
                )
            )
        )

      ) {

        addSeed(
          "authentication",
          "authentication",
          facts.functionCalls,
          [filePath],
          0.95
        );

      }

      if (

        [...callSet].some(
          call =>
            authorizationIndicators.some(
              indicator =>
                call.includes(
                  indicator
                )
            )
        )

      ) {

        addSeed(
          "authorization",
          "authorization",
          facts.functionCalls,
          [filePath],
          0.90
        );

      }

      if (

        [...callSet].some(
          call =>
            cryptoIndicators.some(
              indicator =>
                call.includes(
                  indicator
                )
            )
        )

      ) {

        addSeed(
          "crypto",
          "crypto",
          facts.functionCalls,
          [filePath],
          0.95
        );

      }

      if (

        [...callSet].some(
          call =>
            databaseIndicators.some(
              indicator =>
                call.includes(
                  indicator
                )
            )
        )

      ) {

        addSeed(
          "data_access",
          "data_access",
          facts.functionCalls,
          [filePath],
          0.90
        );

      }

      if (

        [...importSet].some(
          specifier =>
            specifier === "dotenv"
        )

      ) {

        addSeed(
          "configuration",
          "configuration",
          facts.imports,
          [filePath],
          0.75
        );

      }

    }

    for (
      const dependency
      of params.dependencyFacts.dependencies
    ) {

      const name =
        dependency.name.toLowerCase();

      const filePath =
        dependency.sourceFile;

      if (

        name === "jsonwebtoken"
        || name === "passport"
        || name === "passport-jwt"

      ) {

        addSeed(
          "authentication",
          "authentication",
          [dependency.name],
          [filePath],
          0.85
        );

      }

      if (

        name === "bcrypt"
        || name === "bcryptjs"

      ) {

        addSeed(
          "crypto",
          "crypto",
          [dependency.name],
          [filePath],
          0.85
        );

      }

      if (

        name.includes("vault")
        || name.includes("kms")

      ) {

        addSeed(
          "secret_management",
          "secret_management",
          [dependency.name],
          [filePath],
          0.90
        );

      }

      if (

        name === "mongoose"
        || name === "prisma"
        || name === "sequelize"
        || name === "typeorm"

      ) {

        addSeed(
          "data_access",
          "data_access",
          [dependency.name],
          [filePath],
          0.90
        );

      }

      if (

        name === "stripe"
        || name === "razorpay"

      ) {

        addSeed(
          "payment_processing",
          "external_service",
          [dependency.name],
          [filePath],
          0.85
        );

      }

    }

    void params.graph;

    return Array.from(
      seeds.values()
    ).map(
      seed => ({
        id:
          `capability:${seed.name}`,

        name:
          seed.name,

        category:
          seed.category,

        confidence:
          Math.min(
            1,
            seed.confidence
          ),

        evidence:
          seed.evidence,

        graphEvidence:
          seed.graphEvidence,
      })
    );

  }
}