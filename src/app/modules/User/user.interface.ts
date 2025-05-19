/* eslint-disable no-unused-vars */
import { Model } from 'mongoose';

export interface TUser {
  _id: string;
  id?: string;
  name: string;
  username: string;
  avatar?: string;
  phone?: string;
  address?: string;
  email: string;
  password: string;
  passwordChangedAt?: Date;
  role: 'superAdmin' | 'admin' | 'user';
  status: 'in-progress' | 'blocked';
  isDeleted: boolean;
}

// requires for statics middlewares
export interface UserModel extends Model<TUser> {
  //instance methods for checking if the user exist
  isUserExistsByUsername(username: string): Promise<TUser>;
  //instance methods for checking if passwords are matched
  isPasswordMatched(
    plainTextPassword: string,
    hashedPassword: string,
  ): Promise<boolean>;
  isJWTIssuedBeforePasswordChanged(
    passwordChangedTimestamp: Date,
    jwtIssuedTimestamp: number,
  ): boolean;
}

