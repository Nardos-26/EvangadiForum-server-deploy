  import express from 'express';
import authMiddleware from '../middleware/auth.js';
import { getAnswer, postAnswer } from '../controller/answerController.js';


const router = express.Router();



//protected route to post an answer(using JWT Token)
router.post('/', authMiddleware, postAnswer);

//protected route to get answer
router.get('/:id', authMiddleware, getAnswer)

export default router;