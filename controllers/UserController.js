import UserModel from "../models/UserModel";
import bcrypt from 'bcrypt'
import { createToken } from "../helper/createToken.js";

export const registerUser = async(req, res) => {
    try{
        const {
            fullName, 
            email,
            password,
            contact,
            address,
            dateOfBirth,
            gender,
            education,
            role,
            resume,
            employmentStatus,
            skills,
            experience
        } = req.body();

        if(!fullName || !email || !password || !contact || !address || !dateOfBirth   || !gender){
            return res.status(400).json({
                message: "Please fill all the required fields"
            });
        }

        const saltRounds = 10;
        const salt = await bcrypt.genSalt(saltRounds);
        const hashedPassword = await bcrypt.hash(password,salt)
        
        const isUser = UserModel.find(email);

        const user = new UserModel({
            fullName,
            email,
            password : hashedPassword,
            contact,
            address,
            dateOfBirth,
            gender,
            education,
            role,
            resume,
            employmentStatus,
            skills,
            experience
        });

        if(isUser){
            return res.status(400).json({
                message: "User already exists"
            });
        }
        await user.save();
        
        res.status(201).json({
            message: "User Registered Successfully"
        });
        
        console.log("User Registered Successfully");

    }catch(error){
        console.log("Error in registering User : ", error);
        res.status(500).json({
            message : "Internal Server Error"}, 
            error);
    }
}
export const loginUser = async (req, res) =>{
    try{
        const {
            email, 
            password
        } = req.body
        
        const isUser = await UserModel.findOne({email});
        const name = isUser.fullName;
        
        if(!isUser){
            res.status(404).json({
                message: 'User not found'
            })
        }
        else{
            const isPassword = await bcrypt.compare(password, isUser.password);
            if(isPassword){  
                const token = createToken(isUser._id, isUser.fullName);
                console.log("Generated token" , token);
                  
                res.cookie('token', token, {
                    httpOnly: false,
                    maxAge: 24*60*60*1000,
                    secure : process.env.NODE_ENV === 'production',
                    sameSite: 'Strict'
                    
                });
                console.log("Token set in Cokkie");
                res.status(200).json({
                    message: 'Login successful',
                    token,
                    name
                });

            }
            else{
                res.status(400).json({
                    message: 'Invalid credentials'
                })
            }
        }
    }catch(error){
        res.status(500).json({
            message: ' Internal Server Error' , error
        })
        console.log(error);
    }
}

