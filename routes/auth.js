const router = require("express").Router();
const { User } = require("../models/user");
const Token = require("../models/token");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
require("dotenv").config();

router.post("/", async (req, res) => {
  try {
    const { error } = validate(req.body);
    if (error)
      return res.status(400).send({ message: error.details[0].message });

    const user = await User.findOne({ email: req.body.email });
    if (!user)
      return res.status(401).send({ message: "Invalid Email or Password" });

    const validPassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!validPassword)
      return res.status(401).send({ message: "Invalid Email or Password" });

    if (!user.verified) {
      let token = await Token.findOne({ userId: user._id });
      if (!token) {
        token = new Token({
          userId: user._id,
          token: crypto.randomBytes(32).toString("hex"),
        });
        await token.save();

        const url = `${process.env.BASE_URL}users/${user.id}/verify/${token.token}`;
        await sendEmail(user.email, "Verify Email", url);
      }
      return res
        .status(400)
        .send({
          message:
            "An email has been sent to the admin. Please wait for approval.",
        });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWTPRIVATEKEY, {
      expiresIn: "1h",
    });

    res.status(200).send({ token, message: "Logged in successfully" });
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
  }
});


router.get("/getUser", async (req, res) => {
  try {
    const token = req.header("Authorization");
    if (!token) {
      return res.status(401).send({ message: "Access Denied. No token provided." });
    }

    const decoded = jwt.verify(token, process.env.JWTPRIVATEKEY);
    console.log(decoded); // Log the decoded token for debugging

    if (!decoded || !decoded.id) {
      return res.status(400).send({ message: "Invalid token." });
    }

    const user = await User.findById(decoded.id).select("firstName lastName email");

    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    res.status(200).send(user);
  } catch (error) {
    console.error(error);  // Log the error to server console for debugging
    res.status(500).send({ message: "Something went wrong", error: error.message });
  }
});



const validate = (data) => {
  const schema = Joi.object({
    email: Joi.string().email().required().label("Email"),
    password: Joi.string().required().label("Password"),
  });
  return schema.validate(data);
};

module.exports = router;
