/* eslint-disable no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { TJWTPayload } from '../Auth/auth.interface';
import { User } from './user.model';
import { findUserByIdOrEmail } from './user.utils';
import { TUser } from './user.interface';
import AppError from '../../errors/AppError';
import httpStatus from 'http-status';
import { generateUserId } from './user.utils';

const getMe = async (payload: { id?: string; email?: string }) => {
    let result = await findUserByIdOrEmail(payload);

    return result;
};

const changeStatus = async (id: string, payload: { status: string }) => {
    const result = await User.findByIdAndUpdate(id, payload, {
        new: true,
    });
    return result;
};

const changeRole = async (
    currentUser: TUser,
    targetUserId: string,
    newRole: string
) => {
    // Check if target user exists
    const targetUser = await User.findById(targetUserId);
    if (!targetUser) {
        throw new AppError(httpStatus.NOT_FOUND, 'User not found');
    }

    // Prevent self role change
    if (currentUser._id.toString() === targetUserId) {
        throw new AppError(httpStatus.FORBIDDEN, 'You cannot change your own role');
    }

    // Permission checks
    if (currentUser.role === 'user') {
        throw new AppError(httpStatus.FORBIDDEN, 'You do not have permission to change roles');
    }

    if (currentUser.role === 'admin') {
        // Admin can only change between user and admin
        if (!['user', 'admin'].includes(newRole)) {
            throw new AppError(httpStatus.FORBIDDEN, 'Admin can only change roles between user and admin');
        }
        // Admin cannot change superAdmin's role
        if (targetUser.role === 'superAdmin') {
            throw new AppError(httpStatus.FORBIDDEN, 'Admin cannot change superAdmin role');
        }
    }

    // Generate new ID based on new role
    const newId = await generateUserId(newRole);

    // Update user with new role and ID
    const updatedUser = await User.findByIdAndUpdate(
        targetUserId,
        {
            role: newRole,
            id: newId
        },
        { new: true }
    );

    return updatedUser;
};

export const UserServices = {
    getMe,
    changeStatus,
    changeRole
};
