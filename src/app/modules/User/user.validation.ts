
import { z } from 'zod';
import { USER_ROLE, UserStatus } from '../../constants';


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


export const UserValidation = {
    changeStatusValidationSchema,
    changeRoleValidationSchema
};