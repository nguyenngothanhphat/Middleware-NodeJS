const jwt = require("jsonwebtoken");
const express = require("express");
const app = express();

let userData = [
  {
    id: 1,
    email: "user1@example.com",
    pass: "user1",
  },
  {
    id: 2,
    email: "user2@example.com",
    pass: "user2",
  },
  {
    id: 3,
    email: "user3@example.com",
    pass: "user3",
  },
];

const isEmpty = (obj) => {
  if (Object.keys(obj).length === 0) return true;
  return false;
};

const verifyToken = (req, res, next) => {
  const bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader !== "undefined") {
    const bearerToken = bearerHeader.split(" ")[1];
    req.token = bearerToken;
    next();
  } else {
    return res.status(401).json({ message: "Access Denied" });
  }
};

const auth = (req, res, next) => {
  const { headers } = req;
  if (isEmpty(headers)) {
    return res.status(400).json({ message: "Missing headers" });
  }
  const { authorization: token } = headers;
  if (!!token === false) {
    return res.status(400).json({ message: "Missing token" });
  }
  if (token) {
    const parts = token.split(" ");
    if (parts[0] !== "Bearer") {
      return res.status(400).json({ message: "Invalid token" });
    }
  }
  const nativeToken = token.split(" ")[1];
  const decoded = jwt.verify(nativeToken, "MySuperSecretPassPhrase", (err, decoded) => {
    if(err) {
      return res.status(403);
    } else {
      return decoded;
    }
  });
  if(decoded && decoded.exp, decoded.data, decoded.iat)
  {
    return next();
  } else {
    return res.status(400).json({ message: "Invalid token exp" });
  }
};

app.get("/authorization", verifyToken, auth, (req, res) => {
  jwt.verify(req.token, "MySuperSecretPassPhrase", (err, data) => {
    if (err) {
      return res.status(403);
    } else {
      return res.json({
        message: "Successfully",
        data: data
      });
    }
  });
});

app.post("/login", (req, res) => {
  const user = ({ email, pass } = req.query);

  const userFound = userData.find((u) => {
    return u.email === user.email && u.pass === user.pass;
  });

  if (userFound) {
    let token = jwt.sign(
      {
        body: userFound,
        algorithm: "HS256",
        exp: Math.floor(Date.now() / 1000) + 60 * 60,
      },
      "MySuperSecretPassPhrase"
    );
    return res.status(200).json({
      message: "Auth successful",
      token: token,
    });
  }
  return res.status(500).json({
    message: "Auth Failed && Email or password is incorrect",
    token: null,
  });
});

app.listen(3000, () => {
  console.log("Server listening on port 3000");
});
