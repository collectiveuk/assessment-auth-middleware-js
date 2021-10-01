import nock from "nock";
import { createRequest, createResponse } from "node-mocks-http";
import config from "./config";
import authorise from "./index";
import TokenGenerator from "./__tests__/TokenGenerator";

const tokenGenerator = new TokenGenerator();
const options = {
  issuer: "http://issuer.com",
  audience: "audience",
  algorithms: "RS256",
};
const currentTime = Math.round(Date.now() / 1000);
const claims = {
  sub: "foo",
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10,
};

beforeAll(async () => {
  await tokenGenerator.init();

  nock(options.issuer)
    .persist()
    .get(config.jwkPath)
    .reply(200, { keys: [tokenGenerator.jwk] });
});

describe("A request with a valid access token", () => {
  let res;
  let next;
  beforeEach(async () => {
    res = createResponse();
    next = jest.fn();
  });

  async function createAuthRequest(
    authClaims = claims,
    authTokenGenerator = tokenGenerator
  ) {
    const token = await authTokenGenerator.createSignedJWT(authClaims);
    return createRequest({
      headers: {
        authorizationinfo: token,
      },
    });
  }

  test("should add a user object containing the token claims to the request", async () => {
    const req = await createAuthRequest();
    await authorise(options)(req, res, next);
    expect(req).toHaveProperty("user", claims);
    expect(res.statusCode).toEqual(200);
  });
  test("should return 401 when token is invalid", async () => {
    const fakeTokenGenerator = new TokenGenerator();
    await fakeTokenGenerator.init();

    nock(options.issuer)
      .persist()
      .get("/.fake/jwks.json")
      .reply(200, { keys: [fakeTokenGenerator.jwk] });

    const req = await createAuthRequest(claims, fakeTokenGenerator);

    await authorise(options)(req, res, next);
    expect(res.statusCode).toEqual(401);
    expect(req).not.toHaveProperty("user");
  });
  test("should return 401 when token has expired", async () => {
    const alteredClaims = {
      ...claims,
      exp: currentTime - 100000,
    };
    const req = await createAuthRequest(alteredClaims);

    await authorise(options)(req, res, next);
    expect(res.statusCode).toEqual(401);
    expect(req).not.toHaveProperty("user");
  });
  test("should return 401 when issuer is not valid", async () => {
    const alteredClaims = {
      ...claims,
      iss: "fake.com",
    };
    const req = await createAuthRequest(alteredClaims);

    await authorise(options)(req, res, next);
    expect(res.statusCode).toEqual(401);
    expect(req).not.toHaveProperty("user");
  });
  test("should return 401 when audience is not valid", async () => {
    const alteredClaims = {
      ...claims,
      aud: "invalid",
    };
    const req = await createAuthRequest(alteredClaims);

    await authorise(options)(req, res, next);
    expect(res.statusCode).toEqual(401);
    expect(req).not.toHaveProperty("user");
  });
});
