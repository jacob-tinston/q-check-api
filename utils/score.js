const { TLS_VERSIONS } = require('./tls');

const grades = {
  CRITICAL: "🔴 Critically Vulnerable",
  WEAK: "🟠 Weak Legacy",
  MODERN: "🟡 Modern, But Insecure Tomorrow",
  TRANSITION: "🟢 Transition-Ready",
  EXPERIMENTAL: "🟣 Quantum Experimental",
}

const scoreTLSVersionHygiene = (minTLSVersion, maxTLSVersion) => {
  let score = 0;
  let recommendations = [];
  let notes = [
    "Our probe cannot detect TLS versions below 1.2 for security reasons, so this result may not reflect actual server capabilities.",
  ];

  if (minTLSVersion === TLS_VERSIONS.TLS1_3 && maxTLSVersion === TLS_VERSIONS.TLS1_3) {
    score = 20;
    notes.push("Excellent: Using only TLS 1.3");
  } else if (minTLSVersion === TLS_VERSIONS.TLS1_2 && maxTLSVersion === TLS_VERSIONS.TLS1_3) {
    score = 15;
    notes.push("Good: Supporting TLS 1.2 and 1.3, consider requiring TLS 1.3 only");
  } else if (minTLSVersion === TLS_VERSIONS.TLS1_2 && maxTLSVersion === TLS_VERSIONS.TLS1_2) {
    score = 10;
    notes.push("Acceptable: Using TLS 1.2, but consider upgrading to support TLS 1.3");
  }

  return { score, recommendations, notes };
}

const getScore = (breakdown) => Object.values(breakdown).reduce((sum, value) => sum + value, 0);

const getGrade = (score) => {
  if (score >= 96 && score <= 99) return grades.EXPERIMENTAL;
  if (score >= 80 && score <= 95) return grades.TRANSITION;
  if (score >= 60 && score <= 79) return grades.MODERN;
  if (score >= 30 && score <= 59) return grades.WEAK;
  return grades.CRITICAL;
}

const scoreQuantumResistance = (data) => {
  const tlsEvaluation = scoreTLSVersionHygiene(data.tls.minVersion, data.tls.negotiatedVersion);

  const breakdown = {
    tlsVersionHygiene: tlsEvaluation.score,
    forwardSecrecy: 0,
    hybridPQKeyExchange: 0,
    certificatePQReadiness: 0,
    hashAlgorithmHygiene: 0
  };

  const score = getScore(breakdown);
  const grade = getGrade(score);

  const recommendations = [
    ...tlsEvaluation.recommendations,
  ];

  const notes = [
    ...tlsEvaluation.notes,
  ];

  return {
    score,
    grade,
    breakdown,
    recommendations,
    notes
  };
}

module.exports = { scoreQuantumResistance };
