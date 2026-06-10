import {
  RepositoryContext,
  RiskAssessment,
  RiskFactors,
  SecurityFinding,
} from "../domain/appsec.types";
import { RiskEngineContract } from "../contracts/appsec.contracts";

const SEVERITY_WEIGHTS: Record<SecurityFinding["severity"], number> = {
  CRITICAL: 100,
  HIGH: 80,
  MEDIUM: 55,
  LOW: 25,
};

export class RiskEngineService implements RiskEngineContract {
  assess(findings: SecurityFinding[], context: RepositoryContext): RiskAssessment {
    const scoredFindings = findings.map(finding => this.scoreFinding(finding, context));
    const topFindings = scoredFindings.sort((left, right) => right.riskScore - left.riskScore).slice(0, 10);
    const contextBaseline = this.calculateContextBaseline(context);

    if (topFindings.length === 0) {
      return {
        score: contextBaseline,
        level: this.levelFromScore(contextBaseline),
        factors: {
          severity: 0,
          reachability: contextBaseline,
          exposure: contextBaseline,
          exploitability: contextBaseline,
          criticality: contextBaseline,
          businessImpact: contextBaseline,
          confidence: 1,
        },
      };
    }

    const averages = this.averageFactors(topFindings);
    const score = this.clamp(
      Math.round((this.average(topFindings.map(finding => finding.riskScore)) * 0.72) + (contextBaseline * 0.28)),
      0,
      100,
    );

    return {
      score,
      level: this.levelFromScore(score),
      factors: {
        severity: averages.severity,
        reachability: averages.reachability,
        exposure: Math.max(averages.exposure, contextBaseline),
        exploitability: averages.exploitability,
        criticality: averages.criticality,
        businessImpact: averages.businessImpact,
        confidence: averages.confidence,
      },
    };
  }

  private scoreFinding(finding: SecurityFinding, context: RepositoryContext): SecurityFinding {
    const severityWeight = SEVERITY_WEIGHTS[finding.severity];
    const exposureMatch = this.isExposedPath(finding.filePath, context);
    const exposure = Math.max(finding.exposure, exposureMatch.exposureScore);
    const reachability = Math.max(finding.reachability, exposureMatch.reachabilityScore);
    const exploitability = Math.max(finding.exploitability, exposureMatch.exploitabilityScore);
    const criticality = Math.max(finding.criticality, this.criticalAssetScore(context));
    const businessImpact = Math.max(finding.businessImpact, this.businessImpactScore(context, finding));

    const dependencyRisk = this.dependencyRiskScore(finding, context);
    const authFactor = exposureMatch.authFactor;
    const secretsFactor = this.secretFactor(finding, context);

    const score = this.clamp(
      Math.round(
        (severityWeight * 0.3)
          + (reachability * 0.2)
          + (exposure * 0.18)
          + (exploitability * 0.15)
          + (criticality * 0.08)
          + (businessImpact * 0.06)
          + (dependencyRisk * 0.03)
          + (authFactor * 0.02)
          + (secretsFactor * 0.02),
      ),
      0,
      100,
    );

    return {
      ...finding,
      riskScore: score,
    };
  }

  private calculateContextBaseline(context: RepositoryContext): number {
    const exposureWeight = context.exposures.reduce((total, exposure) => {
      if (exposure.authentication === "none" || exposure.authentication === "unknown") {
        return total + 12;
      }

      return total + 6;
    }, 0);

    const securityWeight = context.securityModules.length * 5;
    const serviceWeight = context.thirdPartyServices.reduce((total, service) => total + this.serviceWeight(service.category), 0);
    const dataStoreWeight = context.dataStores.reduce((total, store) => total + this.dataStoreWeight(store.kind), 0);
    const authCapabilityWeight = context.capabilities.filter(capability => capability.category === "authentication" || capability.category === "authorization" || capability.category === "secret_management").length * 4;

    return this.clamp(exposureWeight + securityWeight + serviceWeight + dataStoreWeight + authCapabilityWeight, 0, 100);
  }

  private averageFactors(findings: SecurityFinding[]): RiskFactors {
    if (findings.length === 0) {
      return {
        severity: 0,
        reachability: 0,
        exposure: 0,
        exploitability: 0,
        criticality: 0,
        businessImpact: 0,
        confidence: 0,
      };
    }

    return {
      severity: this.average(findings.map(finding => SEVERITY_WEIGHTS[finding.severity])),
      reachability: this.average(findings.map(finding => finding.reachability)),
      exposure: this.average(findings.map(finding => finding.exposure)),
      exploitability: this.average(findings.map(finding => finding.exploitability)),
      criticality: this.average(findings.map(finding => finding.criticality)),
      businessImpact: this.average(findings.map(finding => finding.businessImpact)),
      confidence: this.average(findings.map(finding => finding.confidence)),
    };
  }

  private isExposedPath(filePath: string | undefined, context: RepositoryContext): { exposureScore: number; reachabilityScore: number; exploitabilityScore: number; authFactor: number } {
    if (!filePath) {
      return { exposureScore: 0, reachabilityScore: 0, exploitabilityScore: 0, authFactor: 0 };
    }

    const exposure = context.exposures.find(entry => entry.files.includes(filePath));
    if (!exposure) {
      return { exposureScore: 0, reachabilityScore: 0, exploitabilityScore: 0, authFactor: 0 };
    }

    const authFactor = exposure.authentication === "required" ? -10 : 20;
    const exposureScore = exposure.kind === "api" ? 35 : 20;
    const reachabilityScore = exposure.kind === "api" ? 30 : 15;
    const exploitabilityScore = exposure.authentication === "required" ? 10 : 25;

    return {
      exposureScore,
      reachabilityScore,
      exploitabilityScore,
      authFactor,
    };
  }

  private dependencyRiskScore(finding: SecurityFinding, context: RepositoryContext): number {
    if (finding.category === "missing_dependency") {
      return 20;
    }

    if (finding.category === "unused_dependency") {
      return 5;
    }

    const riskyDependencies = context.thirdPartyDependencies.filter(dependency => {
      const name = dependency.name.toLowerCase();
      return name.includes("auth") || name.includes("jwt") || name.includes("crypto") || name.includes("secret") || name.includes("passport") || name.includes("oauth");
    });

    return Math.min(15, riskyDependencies.length * 3);
  }

  private secretFactor(finding: SecurityFinding, context: RepositoryContext): number {
    if (finding.category.includes("secret")) {
      return 20;
    }

    return context.capabilities.some(capability => capability.category === "secret_management") ? 5 : 0;
  }

  private criticalAssetScore(context: RepositoryContext): number {
    return Math.min(20, context.dataStores.length * 4 + context.securityModules.length * 2);
  }

  private businessImpactScore(context: RepositoryContext, finding: SecurityFinding): number {
    if (finding.category === "unauthenticated_exposure") {
      return 20;
    }

    if (context.thirdPartyServices.some(service => service.category === "payment" || service.category === "identity" || service.category === "ai")) {
      return 10;
    }

    return 0;
  }

  private serviceWeight(category: RepositoryContext["thirdPartyServices"][number]["category"]): number {
    switch (category) {
      case "payment":
      case "identity":
      case "ai":
        return 8;
      case "storage":
      case "messaging":
        return 5;
      default:
        return 3;
    }
  }

  private dataStoreWeight(kind: RepositoryContext["dataStores"][number]["kind"]): number {
    switch (kind) {
      case "sql":
      case "nosql":
        return 6;
      case "queue":
      case "cache":
        return 4;
      default:
        return 3;
    }
  }

  private average(values: number[]): number {
    if (values.length === 0) {
      return 0;
    }

    return values.reduce((sum, value) => sum + value, 0) / values.length;
  }

  private levelFromScore(score: number): RiskAssessment["level"] {
    if (score >= 85) {
      return "CRITICAL";
    }

    if (score >= 65) {
      return "HIGH";
    }

    if (score >= 35) {
      return "MEDIUM";
    }

    return "LOW";
  }

  private clamp(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, value));
  }
}
