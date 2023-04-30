
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const image = [
    "cat1.gif",
    "cat2.gif",
    "cat3.jpeg"
  ];


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get("/", (req, res) => {
    var html;
    if (!req.session.authenticated) {
        html = `
          <button onclick="window.location.href='/signup'">Sign up</button>
          <br>
          <button onclick="window.location.href='/login'">Log in</button>
        `;
    } else {
        html = `
          <h1>hello${req.session.name}</h1>
          <button onclick="window.location.href='/members'">Go to Members Area</button>
          <button onclick="window.location.href='/logout'">Log out</button>
        `;
    }
    res.send(html);
  });

  app.get("/nosql-injection", async (req, res) => {
    var name = req.query.user;
  
    if (!name) {
      res.send(
        `<h3>No user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
      );
      return;
    }
    console.log("user: " + name);
  
    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(name);
  
    // If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.send(
        "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
      );
      return;
    }
  
    const result = await userCollection
      .find({ name: name })
      .project({ name: 1, password: 1, _id: 1 })
      .toArray();
  
    console.log(result);
  
    res.send(`<h1>Hello, ${name}!</h1>`);
  });
  
  //Sign up function
  app.get("/signup", (req, res) => {
    var html = `
        <h1>Create User</h1>
        <form action='/submitUser' method='post'>
        <input name='email' type='email' placeholder='Email'>
        <br><br>
        <input name='name' type='text' placeholder='Name'>
        <br><br>
        <input name='password' type='password' placeholder='Password'>
        <br><br>
        <button>Submit</button>
        </form>
        `;
    res.send(html);
  });
  
  app.post("/submitUser", async (req, res) => {
    var email = req.body.email;
    var name = req.body.name;
    var password = req.body.password;
  
    const schema = Joi.object({
      email: Joi.string().email().required(),
      name: Joi.string().alphanum().max(20).required(),
      password: Joi.string().max(20).required(),
    });
  
    const validationResult = schema.validate({ email, name, password });
    if (validationResult.error != null) {
      console.log(validationResult.error);
      var errorMessage = validationResult.error.details[0].message;
      res.send(
        `${errorMessage}. Please <a href="/signup">try again!</a>.`
      );
      return;
    }
  
    var hashedPassword = await bcrypt.hash(password, saltRounds);
  
    await userCollection.insertOne({
      name: name,
      password: hashedPassword,
      email: email,
    });
  
    req.session.authenticated = true;
    req.session.name = name;
  
    res.redirect("/");
  });
  
  app.get("/login", (req, res) => {
    var html = `
        <h1>Log in</h1><br>
        <form action='/loggingin' method='post'>
        <input name='email' type='text' placeholder='Email'><br>
        <input name='password' type='password' placeholder='Password'><br>
        <button>Submit</button>
        </form>
        `;
    res.send(html);
  });
  
  app.post("/loggingin", async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
  
    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/login");
      return;
    }
  
    const result = await userCollection
      .find({ email: email })
      .project({ name: 1, email: 1, password: 1, _id: 1 })
      .toArray();
  
   
    if (await bcrypt.compare(password, result[0].password)) {
      req.session.authenticated = true;
      req.session.email = email;
      req.session.name = result[0].name;
      req.session.cookie.maxAge = expireTime;
  
      res.redirect("/loggedin");
      return;
    } 
    console.log(result);
    if (result.length != 1) {
      res.send(`User not found. <a href="/login">try again</a>.`);
      return;
    }
    else {
      res.send(`password not matches.<a href="/login">try again</a>.`);
      return;
    }
  });
  
  app.get("/loggedin", (req, res) => {
      if (!req.session.authenticated) {
        res.redirect("/login");
      } else {
        res.redirect("/");
      }
    });
    
    app.get('/logout', (req,res) => {
        req.session.destroy();
        res.redirect("/");
    });
  
  
    app.get("/members", (req, res) => {
      if (!req.session.name) {
        res.redirect("/");
        return;
      }
    
      const name = req.session.name;
      const imagelink = image[Math.floor(Math.random() * image.length)];
    
      const html = `
        <h1>wassup, ${name}!</h1>
        <img src="/${imagelink}" alt="image">
        <br><br>
        <button onclick="window.location.href='/logout'">Log out</button>
      `;
      res.send(html);
    });
  
  
  
  app.use(express.static(__dirname + "/public"));
  
  app.get("*", (req, res) => {
    res.status(404);
    res.send(img + "<h1>Page not found - 404<h1>");
  });
  
  app.listen(port, () => {
    console.log("listening on port " + port);
  });