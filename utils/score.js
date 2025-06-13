const grades = {
  CRITICAL: "🔴 Critically Vulnerable",
  WEAK: "🟠 Weak Legacy",
  MODERN: "🟡 Modern, But Insecure Tomorrow",
  TRANSITION: "🟢 Transition-Ready",
  EXPERIMENTAL: "🟣 Quantum Experimental",
}

const getGrade = (score) => {
  if (score >= 96 && score <= 99) return grades.EXPERIMENTAL;
  if (score >= 80 && score <= 95) return grades.TRANSITION;
  if (score >= 60 && score <= 79) return grades.MODERN;
  if (score >= 30 && score <= 59) return grades.WEAK;
  return grades.CRITICAL;
}

const scoreQuantumResistance = (data) => {
  const breakdown = {
    tlsVersionHygiene: 0,
    forwardSecrecy: 0,
    hybridPQKeyExchange: 0,
    certificatePQReadiness: 0,
    hashAlgorithmHygiene: 0
  };

  const score = Object.values(breakdown).reduce((sum, value) => sum + value, 0);
  const grade = getGrade(score);

  const result = {
    score,
    grade,
    breakdown,
    recommendations: [],
    notes: []
  };

  return result;
}

module.exports = { scoreQuantumResistance };
