const mongoose = require("mongoose");

const taskSchema = mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "user",
    required: true,
  },
  title : {
    type : String,
    required : true,
    trim : true
  },
  completed : {
    type : Boolean,
    default : false
  },
  priority : {
    type : String,
    enum : ["Low", "Medium", "High"],
    default : "Medium"
  },
  createdAt : {
    type : Date,
    default : Date.now
  }
});

module.exports = mongoose.model("task", taskSchema);