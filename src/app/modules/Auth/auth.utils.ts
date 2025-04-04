import jwt, { JwtPayload, SignOptions } from 'jsonwebtoken';
import { TJWTPayload } from './auth.interface';


export const createToken = (
    jwtPayload: TJWTPayload,
    secret: string,
    expiresIn: string,
) => {
    return jwt.sign(jwtPayload, secret, {
        expiresIn,
    } as jwt.SignOptions);
};

export const verifyToken = (token: string, secret: string) => {
    return jwt.verify(token, secret) as JwtPayload;
};
