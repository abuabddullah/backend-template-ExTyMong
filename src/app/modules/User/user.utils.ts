import { User } from './user.model';
import { TUser } from './user.interface';

const findLastUserId = async (role: string) => {
  const lastUser = await User.findOne(
    {
      role: role,
    },
    {
      id: 1,
      _id: 0,
    },
  )
    .sort({
      createdAt: -1,
    })
    .lean();

  return lastUser?.id ? lastUser.id : undefined;
};

export const generateUserId = async (role: string) => {
  const rolePrefix = role.charAt(0).toUpperCase();
  const lastUserId = await findLastUserId(role);
  
  let currentId = (0).toString();
  
  if (lastUserId) {
    const lastIdNumber = parseInt(lastUserId.substring(1));
    currentId = (lastIdNumber + 1).toString();
  }

  const paddedId = currentId.padStart(6, '0');
  return `${rolePrefix}${paddedId}`;
};


export const findUserByUserNameOrEmail = async (payload: { username?: string; email?: string }): Promise<TUser | null> => {
  let user: TUser | null = null;
  
  if (payload.username) {
    user = await User.isUserExistsByUsername(payload.username);
  }

  if (!user && payload.email) {
    user = await User.findOne({ email: payload.email }).select('+password');
  }

  return user;
};

