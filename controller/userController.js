import pool from "../config/databaseConfig.js";
import bcrypt from "bcrypt";
import { StatusCodes } from "http-status-codes";
import jwt from "jsonwebtoken";

//Register

export async function register(req, res) {
  const { username, first_name, last_name, email, password } = req.body;

  if (!email || !password || !first_name || !last_name || !username) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      success: false,
      error: "All fields are required.",
    });
  }

  if (password.trim().length < 8) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      success: false,
      error: "Password must be at least 8 characters long.",
    });
  }

  try {
    const [existingUsers] = await pool.query(
      "SELECT username, email FROM users WHERE username = ? OR email = ?",
      [username, email]
    );

    if (existingUsers.length > 0) {
      if (existingUsers[0].email === email) {
        return res.status(StatusCodes.CONFLICT).json({
          success: false,
          error: "An account with this email already exists.",
        });
      }
      if (existingUsers[0].username === username) {
        return res.status(StatusCodes.CONFLICT).json({
          success: false,
          error: "This username is already taken.",
        });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.execute(
      "INSERT INTO users (username, first_name, last_name, email, password) VALUES (?, ?, ?, ?, ?)",
      [username, first_name, last_name, email, hashedPassword]
    );

    return res.status(StatusCodes.CREATED).json({
      success: true,
      message: "User registered successfully.",
    });
  } catch (error) {
    console.error("Registration error:", error.message);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: "Registration failed. Please try again later.",
    });
  }
}
//Login

export async function login(req, res) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      success: false,
      error: "Email and password are required.",
    });
  }

  try {
    const [user] = await pool.execute(
      "SELECT user_id, username, password FROM users WHERE email = ?",
      [email]
    );

    if (user.length === 0) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Invalid email or password.",
      });
    }

    const isMatch = await bcrypt.compare(password, user[0].password);
    if (!isMatch) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Invalid email or password.",
      });
    }

    const token = jwt.sign(
      { user_id: user[0].user_id, username: user[0].username },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    return res.status(StatusCodes.OK).json({
      success: true,
      message: "Login successful.",
      token,
      user: {
        user_id: user[0].user_id,
        username: user[0].username,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: "Login failed. Please try again later.",
    });
  }
}

//CheckUser
export async function checkUser(req, res) {
  // req.user comes from JWT middleware(user info from verified token)
  const userId = req.user.user_id;

  try {
    const [users] = await pool.execute(
      "SELECT user_id, username, first_name, last_name, email FROM users WHERE user_id = ?",
      [userId]
    );
    console.log(users[0]);

    if (users.length === 0) {
      console.warn(`User with ID ${userId} not found in DB`);
      return res.status(StatusCodes.NOT_FOUND).json({
        error: "User not found",
      });
    }

    res.status(StatusCodes.OK).json({
      message: "User profile retrieved successfully",
      user: users[0],
    });
  } catch (error) {
    console.error("Get profile error:", error.message);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      error: "Failed to get user profile",
    });
  }
}
