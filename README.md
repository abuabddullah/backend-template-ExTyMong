# Server Starter Template

A robust Node.js/Express server template with authentication, role-based access control, and error handling.

## Complete Setup Guide
- - basic setup and folder structure [follow here][https://www.notion.so/Interview-QnA-1b5714dc6fc4807c82e1ca4c160a157e?pvs=4#1cb714dc6fc480069957d850ac4c3ddc]
- - error handling [open the repo and resolve globalErrorHandler and inside of it][https://github.com/abuabddullah/backend-template-ExTyMong]
- - route generating

### Part 1: Basic Setup and Project Structure

1. **Initialize Project**
```bash
npm init -y
```

2. **Install Dependencies**
```bash
npm install express mongoose dotenv cors jsonwebtoken bcrypt cookie-parser
npm install -D typescript @types/express @types/node @types/cors @types/jsonwebtoken @types/bcrypt @types/cookie-parser ts-node-dev
```

3. **TypeScript Configuration**
Create `tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "es6",
    "module": "commonjs",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "moduleResolution": "node"
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules"]
}
```

4. **Project Structure**
```
src/
├── app/
│   ├── config/           # Configuration files
│   ├── constants/        # Constant values
│   ├── DB/              # Database connection
│   ├── errors/          # Error handling
│   ├── interfaces/      # TypeScript interfaces
│   ├── middlewares/     # Custom middlewares
│   ├── modules/         # Feature modules
│   ├── routes/          # Route definitions
│   └── utils/           # Utility functions
├── types/               # TypeScript type definitions
├── app.ts               # Express app setup
└── server.ts            # Server entry point
```

5. **Basic Express Setup**
Create `src/app.ts`:
```typescript
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import globalErrorHandler from './app/middlewares/globalErrorHandler';

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Routes
// app.use('/api/v1', routes);

// Global error handler
app.use(globalErrorHandler);

export default app;
```

6. **Server Entry Point**
Create `src/server.ts`:
```typescript
import app from './app';
import config from './app/config';
import { connectDB } from './app/DB';

const startServer = async () => {
    try {
        await connectDB();
        app.listen(config.port, () => {
            console.log(`Server is running on port ${config.port}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
    }
};

startServer();
```

### Part 2: Error Handling Setup

1. **Custom Error Class**
Create `src/app/errors/AppError.ts`:
```typescript
class AppError extends Error {
    statusCode: number;
    status: string;
    isOperational: boolean;

    constructor(message: string, statusCode: number) {
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;

        Error.captureStackTrace(this, this.constructor);
    }
}

export default AppError;
```

2. **Global Error Handler**
Create `src/app/middlewares/globalErrorHandler.ts`:
```typescript
import { ErrorRequestHandler } from 'express';
import AppError from '../errors/AppError';

const globalErrorHandler: ErrorRequestHandler = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    if (process.env.NODE_ENV === 'development') {
        res.status(err.statusCode).json({
            success: false,
            message: err.message,
            errorSources: err.errorSources || [],
            stack: err.stack
        });
    } else {
        res.status(err.statusCode).json({
            success: false,
            message: err.message,
            errorSources: err.errorSources || []
        });
    }
};

export default globalErrorHandler;
```

3. **Error Types**
Create `src/app/errors/errorTypes.ts`:
```typescript
export const ERROR_TYPES = {
    VALIDATION_ERROR: 'ValidationError',
    CAST_ERROR: 'CastError',
    DUPLICATE_ERROR: 'DuplicateError',
    JWT_ERROR: 'JsonWebTokenError',
    JWT_EXPIRED: 'TokenExpiredError',
    UNAUTHORIZED: 'UnauthorizedError'
};
```

### Part 3: Route and Database Integration

1. **Database Connection**
Create `src/app/DB/index.ts`:
```typescript
import mongoose from 'mongoose';
import config from '../config';

const connectDB = async () => {
    try {
        await mongoose.connect(config.database_url as string);
        console.log('Database connected successfully');
    } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
    }
};

export { connectDB };
```

2. **User Model**
Create `src/app/modules/User/user.model.ts`:
```typescript
import { Schema, model } from 'mongoose';
import { UserModel, IUser } from './user.interface';

const userSchema = new Schema<IUser, UserModel>({
    email: {
        type: String,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'superAdmin'],
        default: 'user'
    },
    ....
}, {
    timestamps: true
});

export const User = model<IUser, UserModel>('User', userSchema);
```

3. **Route Setup**
Create `src/app/routes/index.ts`:
```typescript
import express from 'express';
import { AuthRoutes } from '../modules/Auth/auth.route';
import { UserRoutes } from '../modules/User/user.route';

const router = express.Router();

const moduleRoutes = [
    {
        path: '/auth',
        route: AuthRoutes
    },
    {
        path: '/users',
        route: UserRoutes
    }
];

moduleRoutes.forEach(route => router.use(route.path, route.route));

export default router;
```

4. **Authentication Middleware**
Create `src/app/middlewares/auth.ts`:
```typescript
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import config from '../config';
import AppError from '../errors/AppError';

const auth = (...requiredRoles: string[]) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            const token = req.headers.authorization?.split(' ')[1];

            if (!token) {
                throw new AppError('You are not authorized', 401);
            }

            const decoded = jwt.verify(token, config.jwt_access_secret as string) as any;

            if (requiredRoles.length && !requiredRoles.includes(decoded.role)) {
                throw new AppError('You are not authorized', 401);
            }

            req.user = decoded;
            next();
        } catch (error) {
            next(error);
        }
    };
};

export default auth;
```

5. **Environment Variables**
Create `.env`:
```
NODE_ENV = development
PORT = 5000
DATABASE_URL = mongodb+srv://asifaowadud:sof6vxfRNfUEvdCg@cluster0.gjcwx8p.mongodb.net/server-starter-template?retryWrites=true&w=majority&appName=Cluster0
CORS_ORIGIN = ["http://localhost:5173"]
SENDER_EMAIL = asifaowadud@gmail.com
SENDER_PASSWORD = xfqj dshz wdui ymtb
BCRYPT_SALT_ROUNDS =12
DEFAULT_PASS =000000
JWT_ACCESS_SECRET =3a7b5c9d2e1f8a6b4c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9
JWT_REFRESH_SECRET =8f7e6d5c4b3a2918273645546372819a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f
JWT_ACCESS_EXPIRES_IN =15m
JWT_REFRESH_EXPIRES_IN =7d
RESET_PASS_UI_LINK =http://localhost:3000
CLOUDINARY_CLOUD_NAME = dglsw3gml
CLOUDINARY_API_KEY = 393288281474652
CLOUDINARY_API_SECRET = PYDhbIQtyacVMPMkSLhFF8kVY7s
SUPER_ADMIN_PASSWORD =000000

```

6. **Package Scripts**
Update `package.json`:
```json
{
  "scripts": {
    "dev": "ts-node-dev --respawn --transpile-only src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js"
  }
}
```

## API Documentation

### Authentication Endpoints

#### 1. Register User
```http
POST /api/v1/auth/register
```
Request Body:
```json
{
    "password": "user123",
    "user": {
        "email": "user@example.com",
        "name": "John Doe"
    }
}
```
Response:
```json
{
    "success": true,
    "message": "Student is created successfully",
    "data": {
        "email": "user@example.com",
        "name": "John Doe",
        "role": "user"
    }
}
```

#### 2. Login
```http
POST /api/v1/auth/login
```
Request Body:
```json
{
    "email": "user@example.com",
    "password": "user123"
}
```
Response:
```json
{
    "success": true,
    "message": "User is logged in successfully!",
    "data": {
        "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
}
```
Note: Refresh token is set in HTTP-only cookie

#### 3. Change Password
```http
POST /api/v1/auth/change-password
```
Headers:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
Request Body:
```json
{
    "oldPassword": "user123",
    "newPassword": "newPassword123"
}
```
Response:
```json
{
    "success": true,
    "message": "Password is updated successfully!",
    "data": null
}
```

#### 4. Refresh Token
```http
POST /api/v1/auth/refresh-token
```
Headers:
```
Cookie: refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
Response:
```json
{
    "success": true,
    "message": "Access token is retrieved successfully!",
    "data": {
        "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
}
```

#### 5. Forget Password
```http
POST /api/v1/auth/forget-password
```
Request Body:
```json
{
    "email": "user@example.com"
}
```
Response:
```json
{
    "success": true,
    "message": "Reset link is generated successfully!",
    "data": {
        "resetLink": "http://localhost:5000/api/v1/auth/reset-password?token=..."
    }
}
```

#### 6. Reset Password
```http
POST /api/v1/auth/reset-password
```
Headers:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
Request Body:
```json
{
    "email": "user@example.com",
    "newPassword": "newPassword123"
}
```
Response:
```json
{
    "success": true,
    "message": "Password reset successfully!",
    "data": null
}
```

### User Endpoints

#### 1. Get User Profile
```http
GET /api/v1/users/me
```
Headers:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
Response:
```json
{
    "success": true,
    "message": "User is retrieved successfully",
    "data": {
        "email": "user@example.com",
        "name": "John Doe",
        "role": "user"
    }
}
```

#### 2. Change User Role
```http
POST /api/v1/users/change-role/:id
```
Headers:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
Request Body:
```json
{
    "role": "admin"
}
```
Response:
```json
{
    "success": true,
    "message": "Role changed successfully",
    "data": {
        "email": "user@example.com",
        "name": "John Doe",
        "role": "admin"
    }
}
```

## Installation

1. Clone the repository
2. Install dependencies:
```bash
npm install
```
3. Set up environment variables
4. Start the development server:
```bash
npm run dev
```

## Production

To start in production mode:
```bash
npm start
```