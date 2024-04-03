import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import roleRouter from './routes/role.js';
import authRouter from './routes/auth.js';
import userRouter from './routes/user.js';
import blogRouter from './routes/blog.js';
import cookieParser from 'cookie-parser';



const app = express();
dotenv.config();

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin:'http://localhost:4200/',
    credentials : true
}))
app.use("/api/role", roleRouter);
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
//app.use('/api/blog', blogRouter);

 ;

//Response Handler Middleware
// app.use((obj, req, res, next) =>{
//     const statusCode = obj.status || 500;
//     const message = obj.message || "Something Went Wrong!";
//     return res.status(statusCode).json({
//         success : [200,201,204].some(a => a === obj.status) ? true : false,
//         status : statusCode,
//         message : message,
//         data : obj.data
//     });
// });


//Server Connection
app.listen(8080, () =>{
    connectMongoDB();
    console.log("----********Connected with Backend Server********----");
})

//Mongo DB Connection
const connectMongoDB = async () =>{
    try {
        
        await mongoose.connect(process.env.MONGO_CONNECTION_URL);
        console.log("----********Connected with Mongo Database********----")

    } catch (error) {
        throw error;
    }
}

