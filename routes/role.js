import express from 'express';
import { createRole, updateRole, getAllRoles, deleteRole } from '../controllers/role.controller.js';
import { verifyAdmin } from '../utils/verifyJwtToken.js';

const router = express.Router();

//Creating a new role in DB --> createRole controller will get called.
 router.post('/create',verifyAdmin, createRole);

 //Updating the role in DB--> updateRole controller will get called.
 router.put('/update/:id',verifyAdmin, updateRole);

 //Get All the roles from DB--> getAllRoles controller will get called.
 router.get('/getAll', getAllRoles);

 //Deletinging the role from DB--> deleteRole controller will get called.
 router.delete('/deleteRole/:id', deleteRole);


 export default router;