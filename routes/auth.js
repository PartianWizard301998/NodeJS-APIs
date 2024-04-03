import express from 'express';
import { registerUser, login, registerAdmin, sendEmail } from '../controllers/auth.controller.js';

const router = express.Router();

//Registration
router.post('/register', registerUser);

//Registartion As Admin
router.post('/register-admin',registerAdmin);

//Login
router.post('/login', login);

//send reset pass email
router.post('/send-email', sendEmail);

export default router;

