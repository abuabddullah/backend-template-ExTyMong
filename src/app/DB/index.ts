import config from '../config';
import { USER_ROLE } from '../constants';
import { User } from '../modules/User/user.model';

const superUser = {
  username: 'admin',
  name: 'admin',
  email: 'admin@admin.admin',
  password: "000000",
  role: USER_ROLE.superAdmin,
  status: 'in-progress',
  isDeleted: false,
};

const seedSuperAdmin = async () => {
  //when database is connected, we will check is there any user who is super admin
  const isSuperAdminExits = await User.findOne({ role: USER_ROLE.superAdmin });

  if (!isSuperAdminExits) {
    await User.create(superUser);
    console.info("super admin created")
  }
};

export default seedSuperAdmin;
