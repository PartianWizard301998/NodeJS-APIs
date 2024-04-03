/*---------------------------------------------------------------------------------------------------------------------------------------
This routes for getAll user and Get user by ID we will protect this 2 routes by using JWT token we genrated.
So we can handel the User Session
---------------------------------------------------------------------------------------------------------------------------------------*/
import { createError } from "../utils/error.js"
import { createSuccess } from "../utils/success.js";
import User from '../models/User.js';

export const getAllUser = async(req, res, next) =>{
try {
    const users = await User.find();
    //return next(createSuccess(200, "All users", users))
    return res.send({"status" : true, "message" : "Roles fetched Successfully", "status-code" : 200, users});
} catch (error) {
    //return next(createError(500, "Internal Server Error"));
    return res.send({"status" : false, "message" : "Internal Server Error", "status-code" : 500});
}
}

export const getById = async(req, res, next) =>{
try {

    const user = await User.findById(req.params.id);
    if(!user){
        //return next(createError(404, "User not found."));
        return res.send({"status" : false, "message" : "User not found.", "status-code" : 404});
    }    
   // return next(createSuccess(200, "Single User", user));
    return res.send({"status" : true, "message" : "Single User", "status-code" : 200, user});
} catch (error) {
   // return next(createError(500, "Internal Server Error"));
    return res.send({"status" : false, "message" : "Internal Server Error", "status-code" : 500});

}
}

