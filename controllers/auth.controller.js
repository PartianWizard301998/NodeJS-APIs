import Role from '../models/Role.js';
import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import {createSuccess} from '../utils/success.js';
import {createError} from '../utils/error.js';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import userToken from '../models/userToken.js';

//Registration Controller
export const registerUser = async (req, res, next) =>{

    try {
        const user = await User.findOne({email : req.body.email});
        if(user){
            //return next(createError(409, "Email Already Exist"));
            return res.send({"status" : false, "message" : "Email Already Exist", "status-code" : 409});
        }else{
            const user = await User.findOne({userName : req.body.userName});
            if(user){
                //return next(createError(409, "UserName Already Exist"));
                return res.send({"status" : false, "message" : "UserName Already Exist", "status-code" : 409});
            }else{
                //by default while registering the role must be USER if he or she needs admin access will they needs to send the email.
                //Hence we are first we are checking for the 'User' role in DB and assigning it to the role constant.
                const role = await Role.find({role : 'User'});
                /*The below line will create a salt(key) for our password then we will hash our password as we cant store the hard codes
                password in Databases.*/
                const salt = await bcrypt.genSalt(10);
                const hashPassword = await bcrypt.hash(req.body.password, salt);

                const newUser = new User({
                    firstName : req.body.firstName,
                    lastName : req.body.lastName,
                    userName : req.body.userName,
                    email : req.body.email,
                    password: hashPassword,
                    roles:role,
                });
                await newUser.save();
                //return next(createSuccess(200, "User Registered Successfully.", data));
               // return res.status(200).send("User Created Successfully");
                return res.send({"status" : true, "message" : "User Created Successfully", "status-code" : 200});
                
         }
        }
    } catch (error) {
        //return next(createError(500, "Something went Wrong"));
        return res.send({"status" : false, "message" : "Something went Wrong", "status-code" : 500});
    }
}

//Admin Registration Controller
export const registerAdmin = async (req, res, next) =>{

    try {
        const user = await User.findOne({email : req.body.email});
        if(user){
            //return next(createError(409, "Email Already Exist"));
            return res.send({"status" : false, "message" : "Email Already Exist", "status-code" : 409});
        }else{
            const user = await User.findOne({userName : req.body.userName});
            if(user){
                //return next(createError(409, "UserName Already Exist"));
                return res.send({"status" : false, "message" : "UserName Already Exist", "status-code" : 409});
            }else{
                //by default while registering the role must be USER if he or she needs admin access will they needs to send the email.
                //Hence we are first we are checking for the 'User' role in DB and assigning it to the role constant.
                const role = await Role.find({});
                /*The below line will create a salt(key) for our password then we will hash our password as we cant store the hard codes
                password in Databases.*/
                const salt = await bcrypt.genSalt(10);
                const hashPassword = await bcrypt.hash(req.body.password, salt);

                const newUser = new User({
                    firstName : req.body.firstName,
                    lastName : req.body.lastName,
                    userName : req.body.userName,
                    email : req.body.email,
                    password: hashPassword,
                    isAdmin : true,
                    roles:role,
                });
                await newUser.save();
                //return next(createSuccess(200, "Admin Registered Successfully.", error));
                return res.send({"status" : true, "message" : "Admin Registered Successfully.", "status-code" : 200});
         }
        }
    } catch (error) {
        //return next(createError(500, "Something went Wrong"));
        return res.send({"status" : false, "message" : "Something went Wrong", "status-code" : 500});
    }
}

export const login = async (req, res, next) => {
    try {

        /*-------------------------------------------------------------------------------------------------------------------------
            1-> Below line will check the email that user entered is available in DB or not
            2-> The Populate method will add the roles from Role schema into the User model which we have provided the reference in
                user model.
        -------------------------------------------------------------------------------------------------------------------------*/
        
        const user = await User.findOne({email : req.body.email})
        .populate("roles", "role");

        const { roles } = user;
        /*If the above email/user is not availble inf DB below if condition will execute else the control will go to next line*/
        if(!user){
           
           // return next(createError(404, "User Not Found"));
            return res.send({"status" : false, "message" : "User Not Found", "status-code" : 404});
            
        }
        /*If the user entered email is present in DB, the below code will chceck the user entered password and the password 
        associated email in DB. Id the User entered password and Password in DB does not match the if loop will get executed.*/
        const isPasswordCorrect = await bcrypt.compare(req.body.password, user.password);
        if(!isPasswordCorrect){
           // return next(createError(400, "Password Incorrect"));
            return res.send({"status" : false, "message" : "Password Incorrect", "status-code" : 400});
        }

        /*---------------------------------------------------------------------------------------------------------------------------
        If the user is validated and its available, we will crate the JWT token before sneding the response back to user.
        -----------------------------------------------------------------------------------------------------------------------------*/

        const jwt_token = jwt.sign(
            {id: user._id, isAdmin: user.isAdmin, role:roles},
            process.env.JWT_SECRET_KEY
        )
        res.cookie("access_token", jwt_token, {httpOnly: true})
        .status(200)
        .json({
            status : 200,
            message : "Login Successful",
            data : user
        })
        /*If the email and password entered matched with DB records below responce will be sent back to the user.*/
        // return next(createSuccess(200, "Login Successfull"));
        
    } catch (error) {
        //return next(createError(500, "Something went Wrong"));
        return res.send({"status" : false, "message" : "Something went Wrong", "status-code" : 200});
        
    }
}

export const sendEmail = async (req, res, next) => {
    const email = req.body.email;
    const user = await User.findOne({email: {$regex: '^'+email+'$', $options:'i'}});

    if(!user){
        //return res.send({"status" : false, "message" : "User Not Found to reset the email", "status-code" : 404});
        return res.send({"status" : false, "message" : "User Not Found to reset the email", "status-code" : 404});
    }

    const payload = {
        email : user.email
    }

    const expiryTime = 300;
    const token = jwt.sign(payload, process.env.JWT_SECRET_KEY, {expiresIn:expiryTime});

    const newToken = new userToken({
        userId : user._id,
        tolen : token
    });


    const mailTransporter = nodemailer.createTransport({
        service : "gmail",
        auth : {
            user : "vaibhavbhute001@gmail.com",
            pass : "dsmyzxcovbgequrf"
        }
    });
    let mailDetails ={
        from : "vaibhavbhute001@gmail.com",
        to : email,
        subject : "Reset Password!!",
        html : `
        
        <html>
  <head>
    <title>Password Reset Request!!</title>
  </head>
  <body>
    <h1>Password Reset Request</h1>
    <p>Dear ${user.userName},</p>
    <p>We have recieved a request to reset you Password for you account with BookMyBook.
    to complete the Password reset process, please click on the button below :</p>
    <a href=${process.env.LIVE_URL}/reset/${token}><button style="background-color:#4CAF50; color: white; padding:14px 20px; border:none;
      cursor:pointer; border-radius:4px;">Reset Password</button></a>
      <p>Please note that this link is only valid for 5 mins. If you did not request a password reset, please disregard thos message</p>
      <p>Thank You,</p>
      <p>Lets Program Team</p>
  </body>
</html>
        `,

    };
    mailTransporter.sendMail(mailDetails, async(error, data) =>{

        if(error){
            console.log(error);
            return res.send({"status" : false, "message" : "Something went wrong while sendng email.", "status-code" : 500});
        }else{
            await newToken.save();
            return res.send({"status" : true, "message" : "Email sent Successfully.", "status-code" : 200});
        }
    })
}