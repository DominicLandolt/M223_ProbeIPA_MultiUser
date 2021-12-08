import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import mongodb from "mongodb";
import bcrypt from 'bcryptjs';
import express from 'express';
import { Role } from './Role.js';
import { User } from './User.js';

dotenv.config();

const DB_URL = `mongodb://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}?authMechanism=${process.env.DB_AUTHMECHANISM}&authSource=${process.env.DB_DATABASE}`;
const DB_CLIENT = new mongodb.MongoClient(DB_URL)
const DB_CONNECTION = DB_CLIENT.connect()

var app = express();
let port: number = parseInt(process.env.PORT);

app.get("/signup", (req, res, next) => {
    let userName = <string>req?.query?.UserName;
    let userEmail = <string>req?.query?.Email;
    let userPassword = <string>req?.query?.Password;
    let userRepeatPassword = <string>req?.query?.RepeatPassword;

    if(userName == null || userName == ""){
        res.status(422).json({ message: "Error: Field \"UserName\" is required." });
    }
    else if(userEmail == null || userEmail == "" || !validateEmail(userEmail)){
        res.status(422).json({ message: "Error: Field \"Email\" is required and must be valid." });
    }
    else if(userPassword == null || userPassword.length < 6){
        res.status(422).json({ message: "Error: Field \"Password\" must be at least 6 characters long." });
    }
    else if(userPassword != userRepeatPassword){
        res.status(422).json({ message: "Error: Field \"RepeatPassword\" must match Field \"Password\"." });
    }else{
        DB_CONNECTION.then(() => {
            const authDB = DB_CLIENT.db("auth");
            const usersColl = authDB.collection('users')

            usersColl.count( { name: escape(userName) }, (error: any, count: number) => {
                if(error){
                    res.status(500).json({ message: "Error: Could not create new user. Please try again later." });
                }
                else if(count != 0){
                    res.status(422).json({ message: "Error: A user with this name already exists. Please choose a different name." });
                }
                else{
                    usersColl.count( { email: escape(userEmail) }, (error: any, count: number) => {
                        if(error){
                            res.status(500).json({ message: "Error: Could not create new user. Please try again later." });
                        }
                        else if(count != 0){
                            res.status(422).json({ message: "Error: A user with this Email already exists. Please use a different email." });
                        }
                        else{
                            bcrypt.hash(userPassword, parseInt(process.env.SALT), (err: any, hash: any) => {
                                if(err){
                                    res.status(500).json({ message: "Error: Could not create new user. Please try again later." });
                                }
                                else{
                                    DB_CONNECTION.then(() => {
                                        const authDB = DB_CLIENT.db("auth");
                                        const rolesColl = authDB.collection('roles')
                                        rolesColl.findOne({name: "Default"}, (err: any, result: any) => {
                                            if(err){
                                                res.status(500).json({ message: "Error: Could not create new user. Please try again later." });
                                            }
                                            else if(result == undefined || result == null){
                                                res.status(500).json({ message: "Error: Could not create new user. Please try again later." });
                                            }
                                            else{
                                                var role = new Role(result);
                                                if(role.id == null || role.name == null || role.permissions == null){
                                                    res.status(500).json({ message: "Error: Could not create new user. Please try again later." });
                                                }
                                                else{
                                                    var user = new User(escape(userName), escape(userEmail), hash, role.permissions)
                                                    DB_CONNECTION.then(() => {
                                                        const valueToInsert = { name: user.name, email: user.email, hash: user.hash, permissions: user.permissions }
                                                        const authDB = DB_CLIENT.db("auth");
                                                        const usersColl = authDB.collection('users')
                                                        usersColl.insertOne(valueToInsert, (err: any, result: any) => {
                                                            if(err){
                                                                res.status(500).json({ message: "Error: Could not create new user. Please try again later." });
                                                            }
                                                            else{
                                                                let token = jwt.sign({ user }, process.env.JWTSECRET, { algorithm: 'HS256', expiresIn: '1h' });
                                                                res.status(200).json({ message: "Successfully created account and logged in.", token });
                                                            }
                                                        })
                                                    });
                                                }
                                            }
                                        });
                                    });
                                }
                            });
                        }
                    });
                }
            });
        });
    }
});

function escape(message: string){
    if(message == null && message == undefined){
        return "";
    }
    message = message.toString().replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&#34;").replace(/'/g, "&#39;").replace(/`/g, "&#96;").replace(/\(/g, "&#40;").replace(/\)/g, "&#41;").replace(/\//g, "&#47;").replace(/\\/g, "&#92;").replace(/\[/g, "&#91;").replace(/\]/g, "&#93;").replace(/\{/g, "&#123;").replace(/\}/g, "&#125;").replace(/\|/g, "&#124;").replace(/\~/g, "&#126;");
    return message.trim();
}

function isTokenValid(token: string){
    let message;
    if(token){
        jwt.verify(token, process.env.JWTSECRET, (err: any, payload: any) => {
            if(err){
                message = { success: false };
            }else{
                message = { success: true, user: payload.user };
            }
        });
    }
    else{
        message = { success: false };
    }
    return message;
}

function validateEmail(email: string)
{
    return /^(\w+([\.-]?\w+)*)@(\w+([\.-]?\w+)*(\.\w{2,4})+)$/.test(email);
}

app.listen(port, function(){
    console.log(`Server listening at *:${port}`);
});

process.on('SIGINT', signal => {
    console.log(`Process has been manually interrupted`);
    process.exit(0);
});

process.on('exit', exitCode => {
    console.log(`Process exited with code ${exitCode}`);
});
