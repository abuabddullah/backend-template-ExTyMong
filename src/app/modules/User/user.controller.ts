import httpStatus from 'http-status';
import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';
import { UserServices } from './user.service';
import AppError from '../../errors/AppError';
import { User } from './user.model';


const getMe = catchAsync(async (req, res) => {
  const result = await UserServices.getMe(req.user?.email);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'User is retrieved succesfully',
    data: result,
  });
});

const changeStatus = catchAsync(async (req, res) => {
  const id = req.params.id;

  const result = await UserServices.changeStatus(id, req.body);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Status is updated succesfully',
    data: result,
  });
});

const changeRole = catchAsync(async (req, res) => {
  const { role } = req.body;
  const userId = req.params.id;
  
  if (!req.user) {
    throw new AppError(httpStatus.UNAUTHORIZED, 'You are not authorized');
  }

  // Get the full user document
  const currentUser = await User.findById(req.user._id);
  if (!currentUser) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }

  const result = await UserServices.changeRole(currentUser, userId, role);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Role changed successfully',
    data: result,
  });
});

export const UserControllers = {
  getMe,
  changeStatus,
  changeRole,
};
