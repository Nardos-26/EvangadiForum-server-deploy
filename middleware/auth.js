import { StatusCodes } from "http-status-codes";
import jwt from "jsonwebtoken";

async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;     //EXPECTED 'Bearer Token'

if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(StatusCodes.UNAUTHORIZED)
      .json({

         msg: "Authentication invalid",
         error: 'Access Denied. No Token Provided'
         });
  }
  const token = authHeader.split(" ")[1];

try {
    const { username, user_id } = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { username, user_id }; 
    next();
  } catch (error) {

    console.error('Token Verification error:', error.message);
    return res
      .status(StatusCodes.UNAUTHORIZED)
      .json({
        status: false,
        msg: "Authentication invalid",
        error: "Invalid Token"
    
    });
  }
}

export default authMiddleware;