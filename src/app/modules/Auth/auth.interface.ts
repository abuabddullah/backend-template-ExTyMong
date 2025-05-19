export type TLoginUser = {
    username?: string;
    email?: string;
    password: string;
  };
  
  
export type TJWTPayload = { _id: string; email: string; username: string; role: string }