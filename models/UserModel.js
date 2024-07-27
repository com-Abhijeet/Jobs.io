import mongoose, { mongo } from "mongoose";

const UserSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    contact:{
        type: String,
        required: true
    },
    address:{
        type: String,
        required: true
    },
    dateOfBirth:{
        type: Date,
        required: true
    },
    gender:{
        type: String,
        required : true
    },
    education: [{
        institutionName: String,
        startDate: Date,
        endDate: Date,
        major: String,
        cgpa: Number,
    }],
    role: {
        type: String,
        required: true,
        default: "Applicant"
    },
    profilePicture : {
        type: String,
        required: false
    },
    resume: {
        type: String,
        required : false
    },
    employmentStatus : {
        type: String,
        required: true,
        default: "Unemployed"
    },
    skills: [{
        skillName: String,
        skillLevel: String
    }],
    experience: [{
        companyName: String,
        jobTitle: String,
        startDate: Date,
        endDate: Date,
        jobDescription: String
    }],
    jobApplications: [{
        jobID: String,
        status: String
    }],
    jobOffers: [{
        jobID: String,
        status: String
    }],
    jobPosts: [{
        jobID: String
    }],
    jobPostsSaved: [{
        jobID: String
    }],


});

const UserModel = mongoose.model("User", UserSchema);
export default UserModel;