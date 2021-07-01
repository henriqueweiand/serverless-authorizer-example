const JwtService = require("../service/jwtService");
const { buildIAMPolicy } = require("../lib/util");

exports.handler = async (event) => {
  try {
    const jwtService = new JwtService();
    // put keys here

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
