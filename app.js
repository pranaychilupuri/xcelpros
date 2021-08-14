const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());
const dbPath = path.join(__dirname, "xcelpro.db");

let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(4000, () => {
      console.log("Server Running at http://localhost:4000/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

const validatePassword = (password) => {
  var passwordValidate = /^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,15}$/;
    if(password.match(passwordValidate)) { 
      return true;
    }
    else { 
      return false;
    }  
};

const validateEmailId = (email) => {
  var emailValidate = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
  if (email.match(emailValidate)) {
    return true;
  } else {
    return false;
  }
}

const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        request.username = payload.username;
        next();
      }
    });
  }
};

//Create User API

app.post("/userdetails", async (request, response) => {
  const { id, username, email, password, age, gender, company, designation, about } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const selectUserQuery = `SELECT * FROM userdetails WHERE username = '${username}';`;
  const dbUser = await db.get(selectUserQuery);

  if (validateEmailId(email)) {
    if (dbUser === undefined) {
      const createUserQuery = `
      INSERT INTO
        userdetails (id, username, email, password, age, gender, company, designation, about)
      VALUES
        (
        '${id}',
        '${username}',
        '${email}',
        '${hashedPassword}',
        '${age}',
        '${gender}',
        '${company}',
        '${designation}',
        '${about}'
        );`;

    
      if (validatePassword(password)) {
        const dbResponse = await db.run(createUserQuery);
        const user_id = dbResponse.lastID;
        response.send("User created successfully");
      } else {
        response.status(400);
        response.send("Password does not meet the given requirement");
      }
      } else {
        response.status(400);
        response.send("User already exists");
      }
    } else {
      response.send("Invalid Email Id");
    }  
});

//USER Login API

app.post("/login/", async (request, response) => {
    const { username, password } = request.body;
    const selectUserQuery = `SELECT * FROM userdetails WHERE username = '${username}'`;
    const dbUser = await db.get(selectUserQuery);
    if (dbUser === undefined) {
      response.status(400);
      response.send("Invalid user");
    } else {
      const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
      if (isPasswordMatched === true) {
      const payload = {
        username: username,
      };
      const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
      response.send({ jwtToken });
      } else {
        response.status(400);
        response.send("Invalid password");
      }
    }
  });

  //GET User API
  
app.get("/userdetails", authenticateToken, async (request, response) => {
    const getUserQuery = `
      SELECT *
      FROM userdetails;`;
    const userArray = await db.all(getUserQuery);
    response.send(userArray);
  });

//UPDATE User API

app.put("/userdetails/:id/", authenticateToken, async (request, response) => {
  const { username, email, password, age, gender, company, designation, about } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const {id} = request.params;
  const updateUserQuery = `
  UPDATE
    userdetails
  SET
    username = '${username}',
    email = '${email}',
    password = '${hashedPassword}',
    age = '${age}',
    gender = '${gender}',
    company = '${company}',
    designation = '${designation}',
    about = '${about}'
  WHERE
    id = ${id};`;

  await db.run(updateUserQuery);
  response.send("User Details Updated");
});

//GET BY UserId API

app.get("/userdetails/:id/", authenticateToken, async (request, response) => {
    const { id } = request.params;
    const getUserQuery = `
      SELECT * FROM userdetails WHERE id = ${id};`;
    const userItem = await db.get(getUserQuery);
    response.send(userItem);
});

//DELETE User API 

app.delete("/userdetails/:id/", authenticateToken, async (request, response) => {
    const { id } = request.params;
    const getUserQuery = `
      DELETE FROM userdetails WHERE id = ${id};`;
    const dbResponse = await db.run(getUserQuery);
  
    if (dbResponse.changes === 0) {
      response.status(401);
      response.send("Invalid Request");
    } else {
      response.send("User Deleted");
    }
  });

module.exports = app;