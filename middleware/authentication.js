const mongoose = require('mongoose');
const User = require('../models/user');

module.exports = {
    isLoggedIn: (req, res, next) => {
      console.log("tryna auth");
      console.log(req.user);
  
      if (req.isAuthenticated()) {
        console.log("yes, is authenticated.");
        return next();
      }
      console.log("auth failed");
  
      res.redirect("/");
    }
  };