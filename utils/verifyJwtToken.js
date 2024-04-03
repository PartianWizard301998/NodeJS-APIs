/*---------------------------------------------------------------------------------------------------------------------------------------
This middleware will help to verify the jwt Token or Access token generated. If verified will all user to pass payload else will
send back the 401 errer "You are not authenticated".
---------------------------------------------------------------------------------------------------------------------------------------*/

import jwt from 'jsonwebtoken';
import { createError } from './error.js';
import router from '../routes/role.js';

export const verifyToken = (req, res, next) =>{
    const jwt_token = req.cookies.access_token;

    //If JWT token is NULL below if block will execute
    if(!jwt_token){
        return next(createError(401, "You are not Authenticated"));
    }
    //If the JWT token is not null it will come for verification stage.
    jwt.verify(jwt_token, process.env.JWT_SECRET_KEY, (error, user) =>{
        if(error){
            return next(createError(403, "Token is not Vaild."));
        }else{
            req.user = user;
        }
        next();   
    })

}


//using verifyToken() function we can now validate User and Admin while login.

export const verifyUser = (req, res, next) => {
    verifyToken(req, res, () =>{
        if(req.user.id === req.params.id || req.user.isAdmin){
            next();
        }else{
            return next(createError(403, "You are not Authorised."));
        }
    })
}

export const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, () =>{
        if(req.user.isAdmin){
            next();
        }else{
            return next(createError(403, "You are not Authorised."));
        }
    })
}

