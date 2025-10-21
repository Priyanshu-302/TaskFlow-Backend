const mongoose = require("mongoose");
const dotenv = require("dotenv");

dotenv.config();

const userSchema = mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password : {
    type : String,
    required : true,
    minlength : 8
  },
  username : {
    type : String,
    default : "user",
    required : true
  },
  createdAt : {
    type : Date,
    default : Date.now
  }
});

module.exports = mongoose.model("user", userSchema);