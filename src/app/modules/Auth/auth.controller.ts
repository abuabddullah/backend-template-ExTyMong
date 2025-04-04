import httpStatus from 'http-status';
import AppError from '../../errors/AppError';
import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';
import { AuthServices } from './auth.service';
import config from '../../config';

const register = catchAsync(async (req, res) => {
    const { password, ...userData } = req.body;

    const result = await AuthServices.createUserIntoDB(
        password,
        userData,
    );

    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: 'Student is created succesfully',
        data: result,
    });
});


const loginUser = catchAsync(async (req, res) => {
    const result = await AuthServices.loginUser(req.body);
    const { refreshToken, accessToken, needsPasswordChange } = result;

    res.cookie('refreshToken', refreshToken, {
        secure: config.node_env === 'production',
        httpOnly: true,
        sameSite: 'none',
        maxAge: 1000 * 60 * 60 * 24 * 365,
    });

    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: 'User is logged in succesfully!',
        data: {
            accessToken,
            needsPasswordChange,
        },
    });
});

const changePassword = catchAsync(async (req, res) => {
    const { ...passwordData } = req.body;

    if (!req.user) {
        throw new AppError(httpStatus.UNAUTHORIZED, 'You are not authorized');
    }

    const result = await AuthServices.changePassword(req.user, passwordData);
    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: 'Password is updated succesfully!',
        data: result,
    });
});

const refreshToken = catchAsync(async (req, res) => {
    const { refreshToken } = req.cookies;
    const result = await AuthServices.refreshToken(refreshToken);

    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: 'Access token is retrieved succesfully!',
        data: result,
    });
});

const forgetPassword = catchAsync(async (req, res) => {
    const email = req.body.email;
    const result = await AuthServices.forgetPassword(email);
    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: 'Reset link is generated succesfully!',
        data: result,
    });
});

const resetPassword = catchAsync(async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const { email, newPassword } = req.body;
    if (!token) {
        throw new AppError(httpStatus.BAD_REQUEST, 'Something went wrong !');
    }

    const result = await AuthServices.resetPassword(req.body, token);
    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: 'Password reset succesfully!',
        data: result,
    });
});


const getMe = catchAsync(async (req, res) => {
    if (!req.user) {
        throw new AppError(httpStatus.UNAUTHORIZED, 'You are not authorized');
    }
    const { userId, role } = req.user;
    const result = await AuthServices.getMe(userId, role);

    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: 'User is retrieved succesfully',
        data: result,
    });
});

export const AuthControllers = {
    register,
    loginUser,
    changePassword,
    refreshToken,
    forgetPassword,
    resetPassword,
    getMe
};
