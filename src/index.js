import axios from "axios";
import dayjs from "dayjs";
import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";
import config from "./config";

const authorize = (options) => async (req, res, next) => {
  const {
    headers: { authorizationinfo: token },
  } = req;

  const jwkResponse = await axios.get(`${options.issuer}${config.jwkPath}`);

  const {
    data: {
      keys: [jwk],
    },
  } = jwkResponse;

  const pem = jwkToPem(jwk);

  let verified;

  try {
    jwt.verify(token, pem);
    verified = true;
  } catch (ex) {
    res.send(401);
  }

  if (verified) {
    const claims = jwt.decode(token);

    if (dayjs().isAfter(dayjs(claims.exp * 1000))) {
      console.log("Token expired");
      res.send(401);
    } else if (claims.iss !== options.issuer) {
      console.log("Token has invalid issuer");
      res.send(401);
    } else if (claims.aud !== options.audience) {
      console.log("Token has invalid audience");
      res.send(401);
    } else {
      req.user = claims;
      next();
    }
  }
};

export default authorize;
