const { buildIAMPolicy } = require("../lib/util");

const jsonwebtoken = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");
const jws = require("jws");

class JwtService {
  jwks;

  constructor(_jwks) {
    this.jwks = _jwks;
  }

  extractToken(token) {
    const match = token.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) {
      throw new Error(
        `Invalid Authorization token - ${token} does not match "Bearer .*"`
      );
    }
    return match[1];
  }

  decode(token) {
    const decoded = jws.decode(token, {});

    if (!decoded) {
      return null;
    }
    var payload = decoded.payload;

    if (typeof payload === "string") {
      try {
        var obj = JSON.parse(payload);
        if (obj !== null && typeof obj === "object") {
          payload = obj;
        }
      } catch (e) {
        throw new Error("decode", e);
      }
    }

    return payload;
  }

  decodeHeader(token) {
    const [headerEncoded] = token.split(".");
    const buff = new Buffer(headerEncoded, "base64");
    const text = buff.toString("ascii");

    return JSON.parse(text);
  }

  getJsonWebKeyWithKID(kid) {
    for (let jwk of this.jwks) {
      if (jwk.kid === kid) {
        return jwk;
      }
    }
    return null;
  }

  validate(token) {
    try {
      const header = this.decodeHeader(token);
      const jsonWebKey = this.getJsonWebKeyWithKID(header.kid);
      const pem = jwkToPem(jsonWebKey);

      jsonwebtoken.verify(token, pem, { algorithms: ["RS256"] });
      return true;
    } catch (e) {
      throw new Error(e.stack);
    }
  }
}

module.exports = JwtService;
