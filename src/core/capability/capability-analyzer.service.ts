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
      "supabase.auth",
      "clerk.session",
      "nextauth",
      "signin",
      "verifytoken",
      "authenticate",
      "sessionmiddleware"
    ];

    const authorizationIndicators = [
      "authorize",
      "checkpermission",
      "hasrole",
      "hasauthority",
      "rbac",
      "acl",
      "guard",
      "policy",
      "permit"
    ];

    const cryptoIndicators = [
      "bcrypt.hash",
      "bcrypt.compare",
      "crypto.createhash",
      "crypto.encrypt",
      "crypto.decrypt",
      "openssl",
      "argon2.hash",
      "argon2.verify",
      "pbkdf2",
      "cipher"
    ];

    const databaseIndicators = [
      "mongoose.connect",
      "prisma.",
      "sequelize",
      "typeorm",
      "jdbc",
      "entityframework",
      "gorm.open",
      "sql.open",
      "redis.createclient",
      "redis.connect",
      "db.collection",
      "firestore.collection",
      "client.query",
      "db.query"
    ];

    const externalServiceIndicators = [
      "stripe.charges",
      "stripe.paymentintents",
      "twilio.messages",
      "sendgrid.send",
      "sentry.captureexception",
      "datadog.gauge",
      "cloudinary.uploader"
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

      const sensitiveEnvKeywords = ["key", "secret", "token", "password", "pwd", "auth", "cred", "cert", "private", "hash", "salt"];
      const SENSITIVE_EXCLUDE = ["port", "home", "node_env", "repository_path", "host", "path"];

      const sensitiveEnvs = facts.envReferences.filter(ref => {
        const lower = ref.toLowerCase();
        const matchesSensitive = sensitiveEnvKeywords.some(keyword => lower.includes(keyword));
        const isExcluded = SENSITIVE_EXCLUDE.some(excl => lower.endsWith("." + excl) || lower.endsWith("['" + excl + "']") || lower.endsWith("[\"" + excl + "\"]"));
        return matchesSensitive && !isExcluded;
      });

      if (sensitiveEnvs.length > 0) {
        addSeed(
          "secret_management",
          "secret_management",
          sensitiveEnvs,
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
        [...callSet].some(
          call =>
            externalServiceIndicators.some(
              indicator =>
                call.includes(
                  indicator
                )
            )
        )
      ) {
        addSeed(
          "external_services",
          "external_service",
          facts.functionCalls,
          [filePath],
          0.90
        );
      }

      if (
        [...importSet].some(
          specifier =>
            specifier === "dotenv" || specifier === "godotenv" || specifier === "dotenvy"
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
        || name.includes("next-auth")
        || name.includes("clerk")
        || name.includes("auth0")
        || name.includes("supabase")
        || name.includes("express-session")
        || name.includes("spring-security")
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
        name.includes("casl")
        || name.includes("accesscontrol")
        || name.includes("rbac")
        || name.includes("authorize")
      ) {
        addSeed(
          "authorization",
          "authorization",
          [dependency.name],
          [filePath],
          0.85
        );
      }

      if (
        name === "bcrypt"
        || name === "bcryptjs"
        || name.includes("argon2")
        || name.includes("crypto")
        || name.includes("scrypt")
        || name.includes("rust-crypto")
        || name.includes("ring")
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
        || name.includes("mongodb")
        || name.includes("redis")
        || name.includes("mysql")
        || name.includes("pg")
        || name.includes("sqlite")
        || name.includes("gorm")
        || name.includes("entityframework")
        || name.includes("hibernate")
        || name.includes("spring-data")
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
        || name === "twilio"
        || name.includes("sendgrid")
        || name.includes("sentry")
        || name.includes("datadog")
        || name.includes("cloudinary")
        || name.includes("aws-sdk")
        || name.includes("google-cloud")
        || name.includes("firebase")
      ) {
        addSeed(
          "external_services",
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