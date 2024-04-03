import express from 'express';
import { getAllUser, getById } from '../controllers/user.controller.js';
import { verifyAdmin, verifyUser } from '../utils/verifyJwtToken.js';
const router = express.Router();

//Get All users
/*-------------------------------------------------------------------------------------------------------------------------------------- 
We are adding the verifyAdmin middlewere as only Admin can check list of all users.
--------------------------------------------------------------------------------------------------------------------------------------*/
router.get('/', verifyAdmin, getAllUser);

//Get particular user by Id
/*-------------------------------------------------------------------------------------------------------------------------------------- 
The user logged in with user access only, can access his own details. He cannot see someones others profiles.
--------------------------------------------------------------------------------------------------------------------------------------*/
router.get('/:id', verifyUser, getById);

export default router;