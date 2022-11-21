const express = require("express");
const { auth, resolver, loaders } = require("@iden3/js-iden3-auth");
const getRawBody = require("raw-body");
const crypto = require("crypto");

require("dotenv").config();

const app = express();
const port = process.env.PORT || 8080;

app.use(express.static("static"));

app.get("/api/sign-in", (req, res) => {
  console.log("get Auth Request");
  GetAuthRequest(req, res);
});

app.post("/api/callback", (req, res) => {
  console.log("callback");
  Callback(req, res);
});

app.listen(port, () => {
  console.log("server running on port", port);
});

// Create a map to store the auth requests and their session IDs
const requestMap = new Map();

// GetQR returns auth request
async function GetAuthRequest(req, res) {
  // Audience is verifier id
  const hostUrl = process.env.HOST_URL;
  const sessionId = crypto.randomBytes(24).toString("hex");
  const callbackURL = "/api/callback";
  const audience = "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ";

  const uri = `${hostUrl}${callbackURL}?sessionId=${sessionId}`;

  // Generate request for basic authentication
  const request = auth.createAuthorizationRequestWithMessage(
    "test flow",
    "message to sign",
    audience,
    uri
  );

  const requestId = crypto.randomBytes(24).toString("hex");
  request.id = requestId;
  request.thid = requestId;

  // Add request for a specific proof
  const proofRequest = {
    id: 1,
    circuit_id: "credentialAtomicQuerySig",
    rules: {
      query: {
        allowedIssuers: ["11B13yv5snrdu63ejbWoTGREJ3HHntTwxGspuFx1Gw"],
        schema: {
          type: "Alunos",
          url: "https://s3.eu-west-1.amazonaws.com/polygonid-schemas/5f771f7c-b3e8-4918-8965-89635faa6a43.json-ld",
        },
        req: {
          Frequencia: {
            $gt: 70,
          },
        },
      },
    },
  };

  const scope = request.body.scope ?? [];
  request.body.scope = [...scope, proofRequest];

  // Store auth request in map associated with session ID
  requestMap.set(`${sessionId}`, request);

  return res.status(200).set("Content-Type", "application/json").send(request);
}

// Callback verifies the proof after sign-in callbacks
async function Callback(req, res) {
  // Get session ID from request

  const sessionId = req.query.sessionId;

  // get JWZ token params from the post request
  const raw = await getRawBody(req);
  const tokenStr = raw.toString().trim();

  // fetch authRequest from sessionID
  const authRequest = requestMap.get(`${sessionId}`);

  // Locate the directory that contains circuit's verification keys
  const verificationKeyloader = new loaders.FSKeyLoader("./keys");
  const sLoader = new loaders.UniversalSchemaLoader("ipfs.io");

  // Add Polygon Mumbai RPC node endpoint - needed to read on-chain state and identity state contract address
  const ethStateResolver = new resolver.EthStateResolver(
    process.env.POLYGON_MUMBAI_RPC_NODE,
    "0x46Fd04eEa588a3EA7e9F055dd691C688c4148ab3"
  );

  // EXECUTE VERIFICATION
  const verifier = new auth.Verifier(
    verificationKeyloader,
    sLoader,
    ethStateResolver
  );

  try {
    authResponse = await verifier.fullVerify(tokenStr, authRequest);
  } catch (error) {
    console.error(error);
    return res.status(500).send(error);
  }

  return res
    .status(200)
    .set("Content-Type", "application/json")
    .send("user with ID: " + authResponse.from + " Succesfully authenticated");
}
