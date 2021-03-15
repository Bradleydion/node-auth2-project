const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets"); // use this secret!
const model = require("../users/users-model")
const bcrypt = require("bcryptjs")
const {default: jwtDecode} = require('jwt-decode');


router.post("/register", validateRoleName, async  (req, res, next) => {
  try{
    const {username, password, role_name} = req.body
    const hashPW = await bcrypt.hash(password,4)
    const newUser = await model.add({
      username,
      password: hashPW,
      role_name,
    })
    res.status(201).json({
      user_id: newUser.user_id,
      username: newUser.username,
      role_name: newUser.role_name,
    })

  }catch(err){
    next(err)
  }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
try {
  const {username, password} = req.body
  const user = await model.findBy({username})
  const passwordValid= await bcrypt.compare(password, user[0].password)
    if(!passwordValid){
      return res.status(401).json({
        message:"Invalid Credentials"
      })
    }
    const token = jwt.sign({
      subject: user[0].user_id,
      username:user[0].username,
      role_name: user[0].role_name
    }, JWT_SECRET, {expiresIn: "1d"})
    res.cookie("token", token)
    res.status(200).json({
      message:`${user[0].username} is back!`,
      token: token,
    })

}catch(err){
  next(err)
}
});

module.exports = router;
