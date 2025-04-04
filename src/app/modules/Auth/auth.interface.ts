export type TLoginUser = {
    id?: string;
    email?: string;
    password: string;
  };
  
  
export type TJWTPayload = { _id: string; email: string; userId: string; role: string }