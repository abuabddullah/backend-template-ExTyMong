import bcrypt from 'bcryptjs';
import httpStatus from 'http-status';
import jwt, { JwtPayload } from 'jsonwebtoken';
import config from '../../config';
import AppError from '../../errors/AppError';
import { sendEmail } from '../../utils/sendEmail';
import { User } from '../User/user.model';
import { TLoginUser, TJWTPayload } from './auth.interface';
import { createToken, verifyToken } from './auth.utils';
import { TUser } from '../User/user.interface';
import mongoose from 'mongoose';
import { findUserByIdOrEmail, generateUserId } from '../User/user.utils';

const createUserIntoDB = async (
    password: string,
    payload: Partial<TUser>,
) => {
    // create a user object
    const userData: Partial<TUser> = {};

    //if password is not given , use default password
    userData.password = password || (config.default_password as string);

    //set student role
    userData.role = 'user';
    // set student email
    userData.email = payload.email;
    const session = await mongoose.startSession();

    try {
        session.startTransaction();
        //set  generated id
        userData.id = await generateUserId(userData.role);


        // create a user (transaction-1)
        const newUser = await User.create([userData], { session }); // array

        //create a student
        if (!newUser.length) {
            throw new AppError(httpStatus.BAD_REQUEST, 'Failed to create user');
        }

        await session.commitTransaction();
        await session.endSession();

        return newUser;
    } catch (err: any) {
        await session.abortTransaction();
        await session.endSession();
        throw new Error(err);
    }
};

const loginUser = async (payload: TLoginUser) => {
    // checking if the user is exist

    const user = await findUserByIdOrEmail(payload);

    if (!user) {
        throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !');
    }
    // checking if the user is already deleted

    const isDeleted = user?.isDeleted;

    if (isDeleted) {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !');
    }

    // checking if the user is blocked

    const userStatus = user?.status;

    if (userStatus === 'blocked') {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !');
    }

    //checking if the password is correct

    if (!(await User.isPasswordMatched(payload?.password, user?.password)))
        throw new AppError(httpStatus.FORBIDDEN, 'Password do not matched');

    //create token and sent to the  client

    const jwtPayload = {
        _id: user._id,
        email: user.email,
        userId: user.id,
        role: user.role,
    };

    const accessToken = createToken(
        jwtPayload as TJWTPayload,
        config.jwt_access_secret as string,
        config.jwt_access_expires_in as string,
    );

    const refreshToken = createToken(
        jwtPayload as TJWTPayload,
        config.jwt_refresh_secret as string,
        config.jwt_refresh_expires_in as string,
    );

    return {
        accessToken,
        refreshToken,
        needsPasswordChange: user?.needsPasswordChange,
    };
};

const changePassword = async (
    userData: JwtPayload,
    payload: { oldPassword: string; newPassword: string },
) => {
    // checking if the user is exist
    const user = await findUserByIdOrEmail({ email: userData.email });

    if (!user) {
        throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !');
    }
    // checking if the user is already deleted

    const isDeleted = user?.isDeleted;

    if (isDeleted) {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !');
    }

    // checking if the user is blocked

    const userStatus = user?.status;

    if (userStatus === 'blocked') {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !');
    }

    //checking if the password is correct

    if (!(await User.isPasswordMatched(payload.oldPassword, user?.password)))
        throw new AppError(httpStatus.FORBIDDEN, 'Password do not matched');

    //hash new password
    const newHashedPassword = await bcrypt.hash(
        payload.newPassword,
        Number(config.bcrypt_salt_rounds),
    );

    await User.findOneAndUpdate(
        {
            email: userData.email,
            role: userData.role,
        },
        {
            password: newHashedPassword,
            needsPasswordChange: false,
            passwordChangedAt: new Date(),
        },
    );

    return null;
};

const refreshToken = async (token: string) => {
    // checking if the given token is valid
    const decoded = verifyToken(token, config.jwt_refresh_secret as string);

    const { userId, iat } = decoded;

    // checking if the user is exist
    const user = await User.isUserExistsByCustomId(userId);

    if (!user) {
        throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !');
    }
    // checking if the user is already deleted
    const isDeleted = user?.isDeleted;

    if (isDeleted) {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !');
    }

    // checking if the user is blocked
    const userStatus = user?.status;

    if (userStatus === 'blocked') {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !');
    }

    if (
        user.passwordChangedAt &&
        User.isJWTIssuedBeforePasswordChanged(user.passwordChangedAt, iat as number)
    ) {
        throw new AppError(httpStatus.UNAUTHORIZED, 'You are not authorized !');
    }

    const jwtPayload = {
        userId: user.id,
        role: user.role,
    };

    const accessToken = createToken(
        jwtPayload as TJWTPayload,
        config.jwt_access_secret as string,
        config.jwt_access_expires_in as string,
    );

    return {
        accessToken,
    };
};

const forgetPassword = async (email: string) => {
    // checking if the user is exist
    const user = await findUserByIdOrEmail({ email: email });

    if (!user) {
        throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !');
    }
    // checking if the user is already deleted
    const isDeleted = user?.isDeleted;

    if (isDeleted) {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !');
    }

    // checking if the user is blocked
    const userStatus = user?.status;

    if (userStatus === 'blocked') {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !');
    }

    const jwtPayload = {
        email: user.email,
        role: user.role,
        userId: user.id,
        _id: user._id,
    };

    const resetToken = createToken(
        jwtPayload as TJWTPayload,
        config.jwt_access_secret as string,
        '10m',
    );

    const resetUILink = `${config.reset_pass_ui_link}?email=${user.email}&token=${resetToken} `;

    sendEmail(user.email, resetUILink);

    console.log(resetUILink);
};

const resetPassword = async (
    payload: { email: string; newPassword: string },
    token: string,
) => {
    // checking if the user is exist
    const user = await findUserByIdOrEmail({ email: payload.email });

    if (!user) {
        throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !');
    }
    // checking if the user is already deleted
    const isDeleted = user?.isDeleted;

    if (isDeleted) {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !');
    }

    // checking if the user is blocked
    const userStatus = user?.status;

    if (userStatus === 'blocked') {
        throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !');
    }

    const decoded = jwt.verify(
        token,
        config.jwt_access_secret as string,
    ) as JwtPayload;

    //localhost:3000?id=A-0001&token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJBLTAwMDEiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MDI4NTA2MTcsImV4cCI6MTcwMjg1MTIxN30.-T90nRaz8-KouKki1DkCSMAbsHyb9yDi0djZU3D6QO4

    if (payload.email !== decoded.userId) {
        console.log(payload.email, decoded.userId);
        throw new AppError(httpStatus.FORBIDDEN, 'You are forbidden!');
    }

    //hash new password
    const newHashedPassword = await bcrypt.hash(
        payload.newPassword,
        Number(config.bcrypt_salt_rounds),
    );

    await User.findOneAndUpdate(
        {
            email: decoded.email,
            role: decoded.role,
        },
        {
            password: newHashedPassword,
            needsPasswordChange: false,
            passwordChangedAt: new Date(),
        },
    );
};


const getMe = async (userId: string, role: string) => {
    let result = null;
    if (role) {
        result = await User.findOne({ id: userId }).populate('user');
    }

    return result;
};

export const AuthServices = {
    createUserIntoDB,
    loginUser,
    changePassword,
    refreshToken,
    forgetPassword,
    resetPassword,
    getMe
};
