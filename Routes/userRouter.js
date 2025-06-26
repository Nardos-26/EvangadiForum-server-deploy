import express from "express";
import authMiddleware from "../middleware/auth.js";
import { register, login, checkUser } from "../controller/userController.js";

const router = express.Router();

//register route
router.post("/register", register);  //http://localhost:3000/api/auth/register

//login user
router.post("/login", login);

//check user
router.get("/checkUser", authMiddleware, checkUser);  //changed to checkUser for testing

export default router;
