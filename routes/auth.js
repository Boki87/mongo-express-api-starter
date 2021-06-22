const express = require("express");
const {protect} = require("../middleware/auth");
const {
  register,
  login,
  confirmEmail,
  forgotPassword,
  resetPassword,
  getMe,
  updateDetails,
  updatePassword
} = require("../controllers/auth");

const router = express.Router();

router.route("/register").post(register);
router.route("/login").post(login);
router.route("/confirmemail").get(confirmEmail);
router.route("/me").get(protect, getMe);
router.route("/updatedetails").put(protect, updateDetails);
router.route("/forgotpassword").post(forgotPassword);
router.route("/resetpassword/:resettoken").put(resetPassword);
router.route("/updatepassword").put(protect, updatePassword);

module.exports = router;
