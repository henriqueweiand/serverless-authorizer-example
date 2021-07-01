const JwtService = require("../service/jwtService");
const { buildIAMPolicy } = require("../lib/util");

exports.handler = async (event) => {
  try {
    const jwtService = new JwtService([
      {
        alg: "RS256",
        e: "AQAB",
        kid: "N5U3GnUsaI53NXgEG/v6SvcKSbvagJZP7kLdagC/yhs=",
        kty: "RSA",
        n: "xeGYM2NHoAwv5kC487jnRrRdrQmcuKjPv0y-4iLcA2e7iFlCYKdAOovU3htwnF_2wnxhkANSud5K9C0mjFhjDDqOG022BUZRK-MxPRgEsMzkAMvsUU3Ivw-wg4fXo_5mE6oWgVWWjtbg0EwnXh4A-qXx6ZMIpZUdx5EGdiATWFqDSMxLG1X4ho_Xp1zJnZAfVaGE9DFTq6HyxG9EWWjyFAa4XrjGTUhxC4cux5tsvvVsPtSiSGWsH_5dFOegsYGGaG6t8GUcxbMR5jQEbm02NNXk64LX1WuDhXUcv-6hgZnytwLi5gshmqiMPWfBnZled-iWvqZ0wac2mv88fdG32w",
        use: "sig",
      },
      {
        alg: "RS256",
        e: "AQAB",
        kid: "qExqTGzkqvRofNpuhhtl8z2tcPfat/rk5DLHGoaqm5s=",
        kty: "RSA",
        n: "oq6w6oeHxdSR2U7ruuRo1VJDMalA1VfyPxK5jqu7Xut7_p5ktcb-nSEvYC8h96bXvqDNRu1cvaqT8vm3REpXv4bEvGM26YjJ5xThiftLtaV0ztcicfQQH-HCjl-urpXp_2mT3OdvrTpotaWmzYacypsuTtGnuWmkpAeHiw291yx_yyUH73kfm-uhYgNhZeKp2f59-7jR4f3gdOt9cMHFd5D52LK9uAR7kLuEBfvC99BfYMlCUDW0oDtLLcmu5-j1z7zm3M58zEelLi0AG5hmxJJpGb4RxOp93n390pEnuv6gSf8HSQe1NzYkKk0EdfNiY0FYMCQy36_rraNiiTfmnQ",
        use: "sig",
      },
    ]);

    const token = jwtService.extractToken(event.authorizationToken);
    jwtService.validate(token);
    const payload = jwtService.decode(token);
    const isAllowed = true;

    const context = {
      sub: payload.sub,
      rules: JSON.stringify(["sites:create", "sites:list", "sites:update"]),
    }; // busca na base se subs tem roles, caso n tem possua retornar JSON.stringify([])

    return buildIAMPolicy(
      payload.username,
      isAllowed ? "Allow" : "Deny",
      event.methodArn,
      context
    );
  } catch (e) {
    console.error("############ authorizer", e);
  }
};
