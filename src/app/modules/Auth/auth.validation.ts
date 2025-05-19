import { z } from 'zod';
import { USER_ROLE, UserStatus } from '../../constants';

const registerValidationSchema = z.object({
  body: z.object({
    name: z.string({ required_error: 'Name is required' }),
    username: z.string({ required_error: 'Name is required' }).optional(),
    email: z.string({ required_error: 'Email is required' }),
    password: z.string({ required_error: 'Password is required' }),
  }),
});

const loginValidationSchema = z.object({
  body: z.object({
    // id: z.string({ required_error: 'Id is required.' }).optional(),
    username: z.string({ required_error: 'Id is required.' }).optional(),
    email: z.string({ required_error: 'Email is required' }).optional(),
    password: z.string({ required_error: 'Password is required' }),
  }),
});

const changePasswordValidationSchema = z.object({
  body: z.object({
    oldPassword: z.string({
      required_error: 'Old password is required',
    }),
    newPassword: z.string({ required_error: 'Password is required' }),
  }),
});

const refreshTokenValidationSchema = z.object({
  cookies: z.object({
    refreshToken: z.string({
      required_error: 'Refresh token is required!',
    }),
  }),
});

const forgetPasswordValidationSchema = z.object({
  body: z.object({
    email: z.string({
      required_error: 'Email is required!',
    }),
  }),
});

const resetPasswordValidationSchema = z.object({
  body: z.object({
    email: z.string({
      required_error: 'Email is required!',
    }),
    newPassword: z.string({
      required_error: 'User password is required!',
    }),
  }),
});


const changeStatusValidationSchema = z.object({
  body: z.object({
      status: z.enum([...UserStatus] as [string, ...string[]]),
  }),
});

const changeRoleValidationSchema = z.object({
  body: z.object({
      role: z.enum([...Object.values(USER_ROLE) as [string, ...string[]]]),
  }),
});

export const AuthValidation = {
  registerValidationSchema,
  loginValidationSchema,
  changePasswordValidationSchema,
  refreshTokenValidationSchema,
  forgetPasswordValidationSchema,
  resetPasswordValidationSchema,
  changeRoleValidationSchema,
  changeStatusValidationSchema
};
