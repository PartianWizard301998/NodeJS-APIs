import Role from '../models/Role.js';
import { createError } from '../utils/error.js';
import { createSuccess } from '../utils/success.js';

//Controller for creating the role in DB
export const createRole = async(req, res, next)=>{
    try {
        if (req.body.role && req.body.role !== '') {
            const newRole = new Role(req.body);
            await newRole.save();
            //return next(createSuccess(200,"Role Created"));
            return res.send({"status" : true, "message" : "Role Created Successfully", "status-code" : 200});
        } else {
            //return next(createError(400,"Bad Request"));
            return res.send({"status" : false, "message" : "Bad Request", "status-code" : 400});
        }
    } catch (error) {
          //return next(createError(500, "Interanl Server Error"));  
          return res.send({"status" : false, "message" : "Interanl Server Error", "status-code" : 500});
    }
 }

//Controller for updating the role in DB
export const updateRole = async(req,res,next) =>{
    try {
        const role = await Role.findById({_id : req.params.id});
        if (role) {
            const newData = await Role.findByIdAndUpdate(
                req.params.id,
                {$set : req.body},
                {new : true}
            );
            //return next(createSuccess(200, "Role updated."));
            return res.send({"status" : true, "message" : "Role Updated Successfully", "status-code" : 200});
        } else {
            //return next(createError(400, "Bad Request"));
            return res.send({"status" : false, "message" : "Bad Request", "status-code" : 400});
        }
    } catch (error) {
        //return  next(createError(500, "Interanl Server Error"));
        return res.send({"status" : false, "message" : "Interanl Server Error", "status-code" : 500});
    }
 }
//Controller for getting all the roles from DB
 export const getAllRoles = async(req,res,next) =>{
    try {
        const roles =  await Role.find({});
        //return next(createSuccess(200, "Roles Fetched", roles));
        return res.send({"status" : true, "message" : "Roles Fetched", "status-code" : 200, roles});
    } catch (error) {
        //return next (createError(500,"Interanl Server Error"));  
        return res.send({"status" : false, "message" : "Interanl Server Error", "status-code" : 500});
    }
 }

//Controller for deleting the role from DB
 export const deleteRole = async (req, res, next) =>{
    try {
        const roleId = req.params.id;
        const role = await Role.findById({_id: roleId});
        if (role) {
            await Role.findByIdAndDelete(roleId);
            //return next(createSuccess(200, "Role Deleted"));
            return res.send({"status" : true, "message" : "Role Deleted Successfully", "status-code" : 200});
        } else {
            //return next(createError(400, "Role not Found."));
            return res.send({"status" : false, "message" : "Role not Found.", "status-code" : 400});
        }
    } catch (error) {
        //return next(createError(500,"Interanl Server Error"));  
        return res.send({"status" : false, "message" : "Interanl Server Error", "status-code" : 500});
    }
 }