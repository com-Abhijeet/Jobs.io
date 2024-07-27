import jwt from 'jsonwebtoken';

export const createToken = (id ,name) =>{
    const JWT_SECRET = 'KingOfHill';
    return jwt.sign({id, name}, JWT_SECRET, {
        expiresIn: '1d'
    })
}