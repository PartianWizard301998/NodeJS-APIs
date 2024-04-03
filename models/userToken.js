import mongoose, {Schema} from "mongoose";

const TokenSchema = mongoose.Schema({

    userId : {
        type : Schema.Types.ObjectId,
        require: true,
        ref : "User"
    },
    token : {
        type : String,
        require : true
    },
    createdAt : {
        type : Date,
        default : Date.now(),
        //seconds(5 min)
        expires : 300 
    }

});

export default mongoose.model("Token", TokenSchema);



